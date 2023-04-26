local const = require "doorbell.constants"
local test = require "spec.testing"
local join = require("spec.testing.fs").join
local cjson = require "cjson"

describe("doorbell", function()
  local prefix = os.getenv("DOORBELL_PREFIX") or join(test.ROOT_DIR, "test")

  ---@type spec.testing.client
  local client

  ---@type spec.testing.client
  local answer_client

  ---@type spec.testing.nginx
  local nginx

  local notify_log = join(prefix, "notify.log")

  local res, err

  local function await_answer_token()
    local token
    test.await.no_error(function()
      local fh = assert(io.open(notify_log, "r"))

      local last
      for line in fh:lines() do
        last = line
      end

      fh:close()

      local data = cjson.decode(last)
      local url = assert(assert(data.params).url)
      token = assert(url:match("t=([^&]+)"))
    end, 5, nil, "waiting for answer token to be available from mock notifier")

    return token
  end

  lazy_setup(function()
    local conf = test.config(prefix)

    nginx = test.nginx(prefix, conf)
    nginx:conf_test()
    nginx:start()

    answer_client = test.client()
  end)

  lazy_teardown(function()
    if client then
      client:close()
    end

    if answer_client then
      answer_client:close()
    end

    nginx:stop()
  end)

  before_each(function()
    client = test.client()
    client.timeout = 5000
    client.request.path = "/ring"
    client.request.host = "127.0.0.1"
    client:add_x_forwarded_headers(test.random_ipv4(), "GET", "http://answer.test/")

    answer_client:reset()
    answer_client.request.path = "/answer"
    client.request.host = "127.0.0.1"

    test.fs.truncate(notify_log)
  end)

  after_each(function()
    if client then
      client:close()
    end
  end)

  describe("/answer", function()
    describe("GET", function()
      it("accepts a valid token as a query param", function()
        local th = assert(ngx.thread.spawn(function()
          client:send()
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
        client.headers.user_agent = ua

        local th = assert(ngx.thread.spawn(function()
          client:send()
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
          if client.err then
            error("unexpected client error: " .. tostring(client.err))

          elseif not client.response then
            return

          elseif client.response.status ~= 201 then
            error("unexpected client response status: " .. tostring(client.response.status))

          end

          return true
        end, 5, nil, "waiting for client request to return 201")
      end)

    end)

  end)
end)
