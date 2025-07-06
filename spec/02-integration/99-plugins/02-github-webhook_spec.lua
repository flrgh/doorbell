local test = require "spec.testing"
local ms = require "spec.testing.mock-upstream"
local mac = require "resty.openssl.mac"


describe("github-webhook", function()
  ---@type spec.testing.client
  local client

  ---@type spec.testing.nginx
  local nginx

  ---@type doorbell.config
  local conf

  ---@type string
  local secret

  local function sign_request()
    if not client.request.body then
      return
    end

    local hmac = assert(mac.new(secret, "hmac", nil, "sha256"))

    local sig = assert(hmac:final(client.request.body))
    client.headers["x-hub-signature-256"] = "sha256=" .. ngx.encode_base64(sig)
  end

  lazy_setup(function()
    secret = test.random_string(32)

    if not conf then
      conf = test.config()

      conf.allow = { { ua = "allow" } }
      conf.deny  = { { ua = "deny" } }
      conf.trusted = { "127.0.0.1/8" }
      conf.plugins = {
        ["github-webhook"] = {
          secret = secret,
        }
      }
    end

    nginx = test.nginx(conf)
    nginx:conf_test()
    nginx:start()

    client = nginx:add_client(test.client())
    client.timeout = 1000
  end)

  before_each(function()
    client:reset()
    client.request.path = "/ring"
    client.request.host = "127.0.0.1"
    client:add_x_forwarded_headers("1.2.3.4", "POST", "http://my-host/webhooks/foo")

    ms.mock.reset()
  end)

  lazy_teardown(function()
    nginx:stop()
  end)

  after_each(function()
    local res = client.response
    if res and type(res.status) == "number" and res.status >= 500 then
      print(string.rep("-", 120))
      print(nginx:read_error_log())
      print(string.rep("-", 120))
    end
  end)

  describe("webhook validation", function()
    it("allows requests with valid webhook signatures", function()
      client.request.body = "test!"
      sign_request()
      client:send()
      assert.is_nil(client.err)
      assert.equals(200, client.response.status)
    end)

    it("ignores non-POST requests", function()
      client.request.body = "test!"
      client:add_x_forwarded_headers("1.2.3.4", "PUT", "http://my-host/webhooks/foo")
      client:send()
      assert.is_nil(client.err)
      assert.equals(401, client.response.status)
    end)

    it("denies invalid signatures", function()
      client.request.body = "test!"
      sign_request()
      client.request.body = "altered"
      client:send()
      assert.is_nil(client.err)
      assert.equals(403, client.response.status)
    end)
  end)
end)
