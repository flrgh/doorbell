local test = require "spec.testing"
local join = require("spec.testing.fs").join

local http = require "resty.http"

describe("doorbell", function()
  local prefix = os.getenv("DOORBELL_PREFIX") or join(test.ROOT_DIR, "test")

  local client
  local nginx

  lazy_setup(function()
    local conf = test.config(prefix)
    conf.allow = { { ua = "allow" } }
    conf.deny  = { { ua = "deny" } }

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
      headers = client.headers
      client.request.path = "/ring"
      client.request.host = "127.0.0.1"
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
  end)
end)
