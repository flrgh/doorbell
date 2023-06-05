local test = require "spec.testing"
local signal = require "resty.signal"

describe("nginx api", function()
  local interval = 1

  ---@type spec.testing.client
  local client

  ---@type spec.testing.nginx
  local nginx

  lazy_setup(function()
    local conf = test.config()
    conf.trusted = { "0.0.0.0/0" }

    conf.metrics = {
      interval = interval,
    }

    conf.network_tags = {
      default = "other",
      ["127.0.0.1"] = "localhost",
      ["10.0.0.0/8"] = "lan",
    }

    nginx = test.nginx(conf)

    nginx:start()

    client = nginx:add_client(test.client())
    client.reopen = true
  end)

  before_each(function()
    client.assert_status.GET = nil
    client.raise_on_request_error = false
    client.raise_on_connect_error = false

    test.await.truthy(function()
      client:get("/nginx", { query = { block = 1 } })
      return client.err == nil
         and client.response
         and client.response.status == 200
    end, 5, 0.1)

    client:reset()

    client.assert_status.GET = { eq = 200 }
    client.raise_on_request_error = true
    client.raise_on_connect_error = true
  end)

  lazy_teardown(function()
    nginx:stop()
  end)

  it("returns info about nginx", function()
    client:get("/nginx")

    local info = assert.is_table(client.response.json)

    assert.table_shape({
      agent        = "table",
      group        = "number",
      started      = "number",
      uptime       = "number",
      worker_count = "number",
      workers      = "table",
    }, info)

    assert.is_table(info.workers[1])
    assert.table_shape({
      id            = "number",
      last_seen     = "number",
      pid           = "number",
      respawn_count = "number",
      started       = "number",
    }, info.workers[1])

    assert.table_shape({
      id            = "number",
      last_seen     = "number",
      pid           = "number",
      respawn_count = "number",
      started       = "number",
    }, info.agent)
  end)

  it("updates with each heartbeat", function()
    client:get("/nginx")

    local info = assert.is_table(client.response.json)

    test.await.truthy(function()
      client:get("/nginx")
      local new = assert.is_table(client.response.json)

      if new.agent.last_seen <= info.agent.last_seen then
        return false
      end

      if #new.workers ~= info.worker_count then
        return false
      end

      for i = 1, #info.workers do
        if new.workers[i].last_seen <= info.workers[i].last_seen then
          return false
        end
      end

      return true
    end, 3, 0.25)
  end)

  it("updates when workers are respawned", function()
    for _ = 1, 5 do
      client:get("/nginx")

      local info = assert.is_table(client.response.json)
      local old = info.workers[1]
      assert.same(0, old.id)
      assert(signal.kill(old.pid, 9))

      local new

      test.await.truthy(function()
        client:get("/nginx")
        new = client.response.json.workers[1]
        if not new then
          return false

        elseif new.id ~= old.id then
          return false

        elseif new.pid == old.pid then
          return false
        end

        return true
      end)

      assert.is_true(new.respawn_count > 0)
      assert.is_true(new.respawn_count > old.respawn_count)
      assert.is_true(new.started > old.started)
    end
  end)

  it("updates when nginx is reloaded", function()
    client:get("/nginx")

    local old = assert.is_table(client.response.json)

    nginx:reload()

    local new

    client.assert_status.GET = nil
    client.raise_on_request_error = false
    client.raise_on_connect_error = false

    test.await.truthy(function()
      client:get("/nginx")

      if client.err then
        return nil, client.err

      elseif client.response.status ~= 200 then
        return nil, client.response.status
      end

      new = client.response.json

      if new.group == old.group then
        return false

      elseif #new.workers ~= old.worker_count then
        return false
      end

      return true
    end, 5, 0.1)

    assert.is_true(new.group > old.group)

    assert.same(old.agent.id, new.agent.id)
    assert.not_same(old.agent.pid, new.agent.pid)
    assert.same(0, new.agent.respawn_count)

    for i = 1, old.worker_count do
      assert.same(old.workers[i].id, new.workers[i].id)
      assert.not_same(old.workers[i].pid, new.workers[i].pid)
      assert.same(0, new.workers[i].respawn_count)
    end
  end)
end)
