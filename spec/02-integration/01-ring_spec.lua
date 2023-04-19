local test = require "spec.testing"
local join = require("spec.testing.fs").join

describe("doorbell", function()
  local prefix = os.getenv("DOORBELL_PREFIX") or join(test.ROOT_DIR, "test")

  local client
  local nginx

  lazy_setup(function()
    local conf = test.config(prefix)
    conf.allow = { { ua = "allow" } }
    conf.deny  = { { ua = "deny" } }
    conf.notify = nil

    nginx = test.nginx(prefix, conf)
    nginx:conf_test()
    nginx:start()

    client = test.client()
  end)

  lazy_teardown(function()
    if client then
      client:close()
    end
    nginx:stop()
  end)

  describe("/ring", function()
    local headers
    local res, err

    before_each(function()
      client:reset()
      client.timeout = 1000
      headers = client.headers
      client.request.path = "/ring"
      client.request.host = "127.0.0.1"
    end)

    lazy_teardown(function()
      if res and type(res.status) == "number" and res.status >= 500 then
        print(string.rep("-", 120))
        print(nginx:read_error_log())
        print(string.rep("-", 120))
      end
    end)

    it("returns a 400 if any x-forwarded-(for|method|proto|host|uri) header is missing", function()
      res, err = client:send()
      assert.is_nil(err)
      assert.equals(400, res.status)

      headers.x_forwarded_for = "1.2.3.4."
      res, err = client:send()
      assert.is_nil(err)
      assert.equals(400, res.status)

      headers.x_forwarded_method = "GET"
      res, err = client:send()
      assert.is_nil(err)
      assert.equals(400, res.status)

      headers.x_forwarded_proto = "http"
      res, err = client:send()
      assert.is_nil(err)
      assert.equals(400, res.status)

      headers.x_forwarded_host = "test"
      res, err = client:send()
      assert.is_nil(err)
      assert.equals(400, res.status)

      -- finally we get a 401 after adding the last necessary header
      headers.x_forwarded_uri = "/"
      res, err = client:send()
      assert.is_nil(err)
      assert.equals(401, res.status)
    end)

    it("returns 200 when allowed by a matched rule", function()
      client:add_x_forwarded_headers("1.2.3.4", "GET", "http://test/")
      headers["user-agent"] = "allow"
      res, err = client:send()
      assert.is_nil(err)
      assert.equals(200, res.status)
    end)

    it("returns 403 when denied by a matched rule", function()
      client:add_x_forwarded_headers("1.2.3.4", "GET", "http://test/")
      headers["user-agent"] = "deny"
      res, err = client:send()
      assert.is_nil(err)
      assert.equals(403, res.status)
    end)

    it("responds to API updates", function()
      local ua = "api-test"

      client:add_x_forwarded_headers("1.2.3.4", "GET", "http://api.test/")
      headers["user-agent"] = ua

      local api = test.client()
      finally(api:close())

      local rule = assert(api:post("/rules", {
        json = {
          action = "allow",
          host = "api.test",
          ua = ua,
        }
      })).json

      test.await.no_error(function()
        res, err = client:send()
        assert.is_nil(err)
        assert.same(200, res.status)
      end, 1, 0.1, "expected request to be allowed after adding allow rule")

      assert.same(200, api:patch("/rules/" .. rule.id, {
        json = {
          action = "deny",
          host = "api.test",
          ua = ua,
        }
      }).status)

      test.await.no_error(function()
        res, err = client:send()
        assert.is_nil(err)
        assert.same(403, res.status)
      end, 1, 0.1, "expected request to be denied after changing rule action to deny")

      rule = assert(api:post("/rules", {
        json = {
          action = "allow",
          host = "api.test",
          ua = ua,
          path = "~^/allow",
        }
      })).json

      client:add_x_forwarded_headers("1.2.3.4", "GET", "http://api.test/allow/me/please")

      test.await.no_error(function()
        res, err = client:send()
        assert.is_nil(err)
        assert.same(200, res.status)
      end, 1, 0.1, "expected request to be allowed after adding new allow rule")

      assert(api:delete("/rules/" .. rule.id))

      test.await.no_error(function()
        res, err = client:send()
        assert.is_nil(err)
        assert.same(403, res.status)
      end, 1, 0.1, "expected request to be denied after deleting allow rule")
    end)

    it("responds to rule expiry", function()
      local ua = "expires-test"

      client:add_x_forwarded_headers("1.2.3.4", "GET", "http://api.test/")
      headers["user-agent"] = ua

      local api = test.client()
      finally(api:close())

      -- add a blanket deny rule
      res = assert(api:post("/rules", {
        json = {
          action = "deny",
          ua = ua,
        }
      }))

      assert.same(201, res.status)

      -- await deny
      test.await.no_error(function()
        res, err = client:send()
        assert.is_nil(err)
        assert.same(403, res.status)
      end, 1, 0.1, "expected request to be denied after adding a deny rule")

      -- add temporary allow rule
      res = assert(api:post("/rules", {
        json = {
          action = "allow",
          host = "api.test",
          ua = ua,
          ttl = 2,
        }
      }))

      assert.same(201, res.status)

      -- await initial state update
      test.await.no_error(function()
        res, err = client:send()
        assert.is_nil(err)
        assert.same(200, res.status)
      end, 1, 0.05, "expected request to be allowed after adding temp allow rule")

      -- await expiry
      test.await.no_error(function()
        res, err = client:send()
        assert.is_nil(err)
        assert.same(403, res.status)
      end, 5, 0.1, "expected request to be denied after temp allow rule expired")
    end)
  end)
end)
