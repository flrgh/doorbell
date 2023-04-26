local test = require "spec.testing"
local join = require("spec.testing.fs").join

describe("rule stats", function()
  local prefix = os.getenv("DOORBELL_PREFIX") or join(test.ROOT_DIR, "test")

  ---@type spec.testing.client
  local client

  ---@type spec.testing.nginx
  local nginx

  local stats_file = join(prefix, "stats.json")


  local function get_rule_with_stats(rule)
    local id = rule

    if type(rule) == "table" then
      id = rule.id
    end

    assert(client:get("/rules/" .. id, {
      query = { stats = true }
    }))

    assert.is_nil(client.err, "unexpected /rules API error")
    assert.same(200, client.response.status)
    assert.is_table(client.response.json)

    return client.response.json
  end


  lazy_setup(function()
    local conf = test.config(prefix)

    nginx = test.nginx(prefix, conf)
    nginx:conf_test()
    nginx:start()
  end)

  lazy_teardown(function()
    if client then
      client:close()
    end

    nginx:stop()
  end)

  ---@type doorbell.rule
  local rule

  before_each(function()
    client = test.client()
    client.timeout = 5000
    client.request.path = "/ring"
    client.request.host = "127.0.0.1"

    do
      local ua = test.random_string()
      assert(client:post("/rules", {
        json = {
          action = "allow",
          ua = ua,
        }
      }))

      assert.same(201, client.response.status)

      rule = assert.is_table(client.response.json)
    end
  end)

  after_each(function()
    if client then
      client:close()
    end
  end)

  it("update with each rule match", function()
    local stats = get_rule_with_stats(rule)
    test.inspect(stats)

    assert.same(0, stats.last_matched)
    assert.same(0, stats.match_count)

    client:add_x_forwarded_headers("1.2.3.4", "GET", "https://test/")
    client.headers["user-agent"] = rule.ua
    client:get("/ring")
    assert.is_nil(client.err)
    assert.same(200, client.response.status)

    stats = get_rule_with_stats(rule)
    test.inspect(stats)

    assert.same(1, stats.match_count)
    assert.near(ngx.now(), stats.last_matched, 1)

    -- wait to ensure that the last_matched timestamp is updated
    ngx.sleep(1)

    client:get("/ring")
    assert.is_nil(client.err)
    assert.same(200, client.response.status)

    local last = stats
    stats = get_rule_with_stats(rule)
    test.inspect(stats)

    assert.same(2, stats.match_count)
    assert.is_true(stats.last_matched > last.last_matched)
  end)


  it("persists/reloads stats on startup", function()
    client:add_x_forwarded_headers("1.2.3.4", "GET", "https://test/")
    client.headers["user-agent"] = rule.ua

    local mtime = test.fs.mtime(stats_file)

    for _ = 1, 10 do
      client:get("/ring")
      assert.is_nil(client.err)
      assert.same(200, client.response.status)
    end

    local stats = get_rule_with_stats(rule)
    assert.same(10, stats.match_count)
    assert.near(ngx.now(), stats.last_matched, 1)

    test.await.truthy(function()
      return test.fs.mtime(stats_file) > mtime
    end, 10, nil, "wait for stats file to be saved/updated")

    assert.truthy(nginx:stop())
    ngx.sleep(1)
    nginx:start()

    local last = stats
    test.await.no_error(function()
      stats = get_rule_with_stats(rule)
      test.inspect(stats)
      assert.same(10, stats.match_count)
      assert.same(last.last_matched, stats.last_matched)
    end, 5, nil, "wait for stats to be reloaded")

    for _ = 1, 15 do
      client:get("/ring")
      assert.is_nil(client.err)
      assert.same(200, client.response.status)
    end

    stats = get_rule_with_stats(rule)
    assert.same(25, stats.match_count)
    assert.near(ngx.now(), stats.last_matched, 1)
  end)

end)
