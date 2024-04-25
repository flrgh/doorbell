local const = require "doorbell.constants"
local test = require "spec.testing"
local join = require("spec.testing.fs").join
local cjson = require "cjson"

describe("doorbell - email validation", function()
  ---@type spec.testing.client
  local ring_client

  ---@type spec.testing.client
  local client

  ---@type spec.testing.nginx
  local nginx

  local res, err

  lazy_setup(function()
    local conf = test.config()
    conf.unauthorized = const.unauthorized.validate_by_email
    conf.auth.users = {
      {
        name = "freddy",
        identifiers = {
          { email = "freddy@example.test" },
        },
      }
    }

    nginx = test.nginx(conf)
    nginx:conf_test()
    nginx:start()

    client = nginx:add_client(test.client())
  end)

  lazy_teardown(function()
    nginx:stop()
  end)

  before_each(function()
    ring_client = nginx:add_client(test.client())
    ring_client.timeout = 1000
    ring_client.request.path = "/ring"
    ring_client.headers.host = "127.0.0.1"
    ring_client:add_x_forwarded_headers(test.random_ipv4(), "GET", "http://answer.test/")

    client.request.path = const.endpoints.email_validate
    client.request.method = "GET"
  end)

  describe("/ring", function()
    it("redirects to the email validation endpoint", function()
      res, err = ring_client:send()
      assert.is_nil(err)
      assert.equal(302, res.status)

      local location = assert.is_string(res.headers.location)
      assert.matches(const.endpoints.email_validate, location, nil, true)
    end)
  end)

  describe(const.endpoints.email_validate, function()
    describe("GET", function()
      it("pre-validate, no token", function()
        local res, err = client:send()
        assert.is_nil(err)
        assert.equals(200, res.status)
        assert.equals("text/html", res.headers.content_type)
      end)
    end)

    describe("POST", function()
      describe("pre-validate, no token", function()
        client.request.method = "POST"
        client.request.post = {
          email = "freddy@example.test",
        }

        local res, err = client:send()
        assert.is_nil(err)
        assert.equals(200, res.status)
        assert.equals("text/html", res.headers.content_type)
      end)
    end)
  end)

  pending("/answer", function()
    describe("GET", function()
      it("accepts a valid token as a query param", function()
        local th = assert(ngx.thread.spawn(function()
          ring_client:send()
        end))

        finally(function()
          ngx.thread.kill(th)
        end)

        local token = await_answer_token()
        answer_client.request.query = { t = token }
        res, err = answer_client:send()
        assert.is_nil(err)
        assert.same(200, res.status)
        assert.same("text/html", res.headers["content-type"])
      end)

      it("rejects requests without a valid token", function()
        answer_client.request.query = {}
        res, err = answer_client:send()
        assert.is_nil(err)
        assert.same(400, res.status)
      end)

      it("responds with a 404 for unknown tokens", function()
        answer_client.request.query = { t = "12345" }
        res, err = answer_client:send()
        assert.is_nil(err)
        assert.same(404, res.status)
      end)
    end)

    describe("POST", function()
      it("can approve access", function()
        local ua = "answer/" .. test.random_string(16)
        ring_client.headers.user_agent = ua

        local th = assert(ngx.thread.spawn(function()
          ring_client:send()
        end))

        finally(function()
          ngx.thread.kill(th)
        end)

        local token = await_answer_token()
        answer_client.request.query = { t = token }
        answer_client.request.method = "POST"
        answer_client.request.post = {
          action  = "approve",
          subject = const.subjects.ua,
          scope   = const.scopes.host,
          period  = "hour",
        }

        res, err = answer_client:send()
        assert.is_nil(err)
        assert.same(201, res.status)
        assert.same("text/plain", res.headers["content-type"])
        assert.matches("Approved access for", res.body)
        assert.matches(ua, res.body, nil, true)

        assert(ngx.thread.wait(th))

        test.await.truthy(function()
          if ring_client.err then
            error("unexpected client error: " .. tostring(ring_client.err))

          elseif not ring_client.response then
            return

          elseif ring_client.response.status ~= 201 then
            error("unexpected client response status: " .. tostring(ring_client.response.status))

          end

          return true
        end, 5, nil, "waiting for client request to return 201")
      end)

    end)

  end)
end)
