local test = require "spec.testing"
local const = require "spec.testing.constants"
local join = require("spec.testing.fs").join

local http = require "resty.http"


describe("doorbell", function()
  local prefix = os.getenv("DOORBELL_PREFIX") or join(const.ROOT_DIR, "test")

  local client
  local nginx

  lazy_setup(function()
    nginx = test.nginx(prefix, {
      base_url = "http://127.0.0.1/",
      trusted = { "127.0.0.1/32" },
      asset_path = const.ASSET_DIR,
      state_path = join(prefix, "state"),
      log_path   = join(prefix, "logs"),
      metrics    = {
        disable  = true,
      },
      allow      = {
        { ua     = "allow" },
      },
      deny       = {
        { ua     = "deny" },
      },
    })
    nginx:conf_test()
    nginx:start()

    client = assert(http.new())
  end)

  lazy_teardown(function()
    if client then
      client:close()
    end
    nginx:stop()
  end)

  describe("/ring", function()
    local headers, path, method, host
    local res, err
    local need_connect = true

    local function request()
      if need_connect then
        assert(client:connect({
          host   = "127.0.0.1",
          scheme = "http",
          port   = 9876,
        }))
      end

      need_connect = false

      local params = {
        path    = path,
        headers = headers,
        method  = method,
        host    = host,
      }
      --print(require("inspect")(params))
      res, err = client:request(params)
      if res and res.has_body then
        res.body, res.body_err = res:read_body()
      end
      --print(require("inspect")({ res = res, err = err }))

      if not res or (res.headers.connection == "close") then
        client:close()
        need_connect = true
      end
    end

    local function add_x_forwarded_headers(addr, meth, req)
      headers.x_forwarded_for = addr
      headers.x_forwarded_method = meth
      local parsed = assert(client:parse_uri(req, true))
      headers.x_forwarded_proto = parsed[1]
      headers.x_forwarded_host  = parsed[2]
      headers.x_forwarded_uri   = parsed[4]
    end

    before_each(function()
      headers = test.headers()
      path = "/ring"
      method = "GET"
      host = "127.0.0.1"
    end)

    it("returns a 400 if any x-forwarded-(for|method|proto|host|uri) header is missing", function()
      request()
      assert.is_nil(err)
      assert.equals(400, res.status)

      headers.x_forwarded_for = "1.2.3.4."
      request()
      assert.is_nil(err)
      assert.equals(400, res.status)

      headers.x_forwarded_method = "GET"
      request()
      assert.is_nil(err)
      assert.equals(400, res.status)

      headers.x_forwarded_proto = "http"
      request()
      assert.is_nil(err)
      assert.equals(400, res.status)

      headers.x_forwarded_host = "test"
      request()
      assert.is_nil(err)
      assert.equals(400, res.status)

      -- finally we get a 401 after adding the last necessary header
      headers.x_forwarded_uri = "/"
      request()
      assert.is_nil(err)
      assert.equals(401, res.status)
    end)

    it("returns 200 when allowed by a matched rule", function()
      add_x_forwarded_headers("1.2.3.4", "GET", "http://test/")
      headers["user-agent"] = "allow"
      request()
      assert.is_nil(err)
      assert.equals(200, res.status)
    end)

    it("returns 403 when denied by a matched rule", function()
      add_x_forwarded_headers("1.2.3.4", "GET", "http://test/")
      headers["user-agent"] = "deny"
      request()
      assert.is_nil(err)
      assert.equals(403, res.status)
    end)
  end)
end)
