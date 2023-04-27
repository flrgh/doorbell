local test = require "spec.testing"
local join = test.fs.join

describe("state", function()
  local state_file
  local conf

  ---@type spec.testing.nginx
  local nginx

  local function get_state()
    local state = test.fs.read_json_file(state_file)
    assert.is_table(state)

    if type(state.rules) == "table" then
      table.sort(state.rules, function(a, b)
        return a.ua < b.ua
      end)
    end

    return state
  end

  before_each(function()
    conf = test.config()
    conf.notify = nil

    state_file = join(conf.runtime_path, "rules.json")

    nginx = test.nginx(conf)
    nginx:conf_test()
    nginx:start()
  end)

  after_each(function()
    if nginx then
      nginx:stop()
    end
  end)

  it("saves config-sourced rules on start", function()
    nginx:stop()

    conf.allow = {
      {
        ua = "start-1",
      }
    }

    conf.deny = {
      {
        ua = "start-2",
      }
    }

    nginx:update_config(conf)
    nginx:start()

    test.await.no_error(function()
      local state = get_state()

      assert.same(2, #state.rules)

      assert.same("start-1", state.rules[1].ua)
      assert.same("config", state.rules[1].source)

      assert.same("start-2", state.rules[2].ua)
      assert.same("config", state.rules[2].source)
    end)
  end)


  it("saves config-sourced rules on reload", function()
    conf.allow = {
      {
        ua = "reload-1",
      }
    }

    conf.deny = {
      {
        ua = "reload-2",
      }
    }

    nginx:update_config(conf)
    nginx:reload()

    test.await.no_error(function()
      local state = get_state()

      assert.same(2, #state.rules)

      assert.same("reload-1", state.rules[1].ua)
      assert.same("config", state.rules[1].source)

      assert.same("reload-2", state.rules[2].ua)
      assert.same("config", state.rules[2].source)
    end)
  end)


  it("replaces old config-sourced rules on reload", function()
    conf.allow = {
      {
        ua = "reload-old-1",
      }
    }

    conf.deny = {
      {
        ua = "reload-old-2",
      }
    }

    nginx:update_config(conf)
    nginx:reload()

    test.await.no_error(function()
      local state = get_state()
      assert.same(2, #state.rules)
    end)

    conf.allow = {
      {
        ua = "reload-new-1",
      }
    }

    conf.deny = {
      {
        ua = "reload-new-2",
      }
    }

    nginx:update_config(conf)
    nginx:reload()

    test.await.no_error(function()
      local state = get_state()

      assert.same(2, #state.rules)
      assert.same("reload-new-1", state.rules[1].ua)
      assert.same("config", state.rules[1].source)

      assert.same("reload-new-2", state.rules[2].ua)
      assert.same("config", state.rules[2].source)
    end)
  end)

  it("saves rules on API changes", function()
    local client = test.client()

    finally(function() client:close() end)

    local res = client:post("/rules", {
      json = {
        action = "allow",
        ua = "1",
      }
    })

    test.await.no_error(function()
      local state = get_state()
      assert.same(1, #state.rules)
      assert.same("1", state.rules[1].ua)
      assert.same("allow", state.rules[1].action)
      assert.same("api", state.rules[1].source)
    end)

    client:patch("/rules/" .. res.json.id, {
      json = { action = "deny" },
    })

    test.await.no_error(function()
      local state = get_state()
      assert.same(1, #state.rules)
      assert.same("1", state.rules[1].ua)
      assert.same("deny", state.rules[1].action)
      assert.same("api", state.rules[1].source)
    end)

    res = client:delete("/rules/" .. res.json.id, {
      json = { action = "deny" },
    })
    assert.same(204, res.status)

    test.await.no_error(function()
      local state = get_state()
      assert.same(0, #state.rules)
    end)
  end)

  it("restores rules on start", function()
    local client = test.client()

    local res = client:post("/rules", {
      json = {
        action = "allow",
        ua = "start",
      }
    })

    local id = assert(res.json.id)

    test.await.no_error(function()
      local state = get_state()
      assert.same(1, #state.rules)
      assert.same("start", state.rules[1].ua)
      assert.same("allow", state.rules[1].action)
      assert.same("api", state.rules[1].source)
    end, 5, 0.1, "expected state file to be updated after adding a new rule via API")

    client:close()
    nginx:stop()

    ngx.sleep(0.1)
    nginx:start()

    client = test.client()
    finally(client:close())

    test.await.no_error(function()
      res = client:get("/rules/" .. id)
      assert.same(200, res.status)
      assert.same("start", res.json.ua)
    end, 5, 0.1, "expected API rule to be restored from state on startup")
  end)
end)
