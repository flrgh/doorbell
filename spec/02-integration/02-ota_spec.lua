local test = require "spec.testing"
local join = require("spec.testing.fs").join
local ms = require "spec.testing.mock-upstream"

describe("OTA updates", function()
  local prefix = os.getenv("DOORBELL_PREFIX") or join(test.ROOT_DIR, "test")

  local client
  local nginx

  lazy_setup(function()
    local conf = test.config(prefix)
    conf.ota = {
      url = ("http://127.0.0.1:%s/ota.json"):format(test.constants.MOCK_UPSTREAM_PORT),
      headers = {
        ["X-foo-header"] = "bar",
      },
      interval = 0.1,
    }

    conf.deny = { { ua = "~.*" } }

    nginx = test.nginx(prefix, conf)
    nginx:conf_test()
    nginx:start()

    ms.mock.prepare({
      path = "/ota.json",
      method = "GET",
      response = {
        status = 200,
        headers = { ["Content-Type"] = "application/json" },
        json = {
          { ua = "test", action = "allow", terminate = true },
        },
      },
    })

    client = test.client()
  end)

  lazy_teardown(function()
    if client then
      client:close()
    end
    nginx:stop()
  end)

  local headers

  before_each(function()
    client:reset()
    headers = client.headers
    client.request.path = "/ring"
    client.request.host = "127.0.0.1"

    headers.x_forwarded_for = "1.2.3.4."
    headers.x_forwarded_method = "GET"
    headers.x_forwarded_proto = "http"
    headers.x_forwarded_host = "test"
    headers.x_forwarded_uri = "/"
  end)


  describe("OTA rule updates", function()
    --local res, err

    it("loads new rules from a remote URL", function()
      headers.user_agent = "test"

      test.await.truthy(function()
        local res, err = client:send()
        assert.is_nil(err)
        return res.status == 200
      end, 5, 1, "expected 200 response")
    end)
  end)
end)
