local test = require "spec.testing"
local const = require "doorbell.constants"
local http = require "doorbell.http"

describe("/ring", function()

  ---@type spec.testing.client
  local client

  ---@type spec.testing.nginx
  local nginx

  ---@type doorbell.config
  local conf

  local reset_config = false

  local function update_config(updates)
    conf = conf or test.config()

    for k, v in pairs(updates) do
      if v == ngx.null then
        v = nil
      end

      conf[k] = v
    end

    nginx:update_config(conf)
    nginx:restart()

    reset_config = true
  end

  before_each(function()
    if not conf then
      conf = test.config()

      conf.allow = { { ua = "allow" } }
      conf.deny  = { { ua = "deny" } }
      conf.trusted = { "127.0.0.1/8" }
    end

    nginx = test.nginx(conf)
    nginx:conf_test()
    nginx:start()

    client = test.client()
    client.timeout = 5000
    client.request.path = "/ring"
    client.request.host = "127.0.0.1"
    client.api_key = nil
    nginx:add_client(client)
  end)

  after_each(function()
    local res = client.response
    if res and type(res.status) == "number" and res.status >= 500 then
      print(string.rep("-", 120))
      print(nginx:read_error_log())
      print(string.rep("-", 120))
    end

    nginx:stop()
    if reset_config then
      conf = nil
    end
  end)

  it("returns a 400 if any x-forwarded-(for|method|proto|host|uri) header is missing", function()
    client:send()
    assert.is_nil(client.err)
    assert.equals(400, client.response.status)

    local headers = client.headers
    headers.x_forwarded_for = "1.2.3.4."
    assert.is_nil(client.err)
    assert.equals(400, client.response.status)

    headers.x_forwarded_method = "GET"
    client:send()
    assert.is_nil(client.err)
    assert.equals(400, client.response.status)

    headers.x_forwarded_proto = "http"
    client:send()
    assert.is_nil(client.err)
    assert.equals(400, client.response.status)

    headers.x_forwarded_host = "test"
    client:send()
    assert.is_nil(client.err)
    assert.equals(400, client.response.status)

    -- finally we get a 401 after adding the last necessary header
    headers.x_forwarded_uri = "/"
    client:send()
    assert.is_nil(client.err)
    assert.equals(401, client.response.status)
  end)

  it("returns 200 when allowed by a matched rule", function()
    client:add_x_forwarded_headers("1.2.3.4", "GET", "http://test/")
    client.headers["user-agent"] = "allow"
    client:send()
    assert.is_nil(client.err)
    assert.equals(200, client.response.status)
  end)

  it("returns 403 when denied by a matched rule", function()
    client:add_x_forwarded_headers("1.2.3.4", "GET", "http://test/")
    client.headers["user-agent"] = "deny"
    client:send()
    assert.is_nil(client.err)
    assert.equals(403, client.response.status)
  end)

  it("returns a request ID header with all responses", function()
    client:add_x_forwarded_headers("1.2.3.4", "GET", "http://test/")

    client.headers["user-agent"] = "allow"
    client:send()
    local id = assert.response(client.response)
                     .has.header(const.headers.request_id)

    client.headers["user-agent"] = "deny"
    client:send()
    assert.not_equals(id, assert.response(client.response)
                                .has.header(const.headers.request_id))
  end)

  it("denies requests from untrusted IPs", function()
    update_config({ trusted = { "1.2.3.4/32" }})

    client:add_x_forwarded_headers("1.2.3.4", "GET", "http://untrusted.test/")
    client:get("/ring")

    assert.same(403, client.response.status)
  end)


  it("responds to API updates", function()
    local ua = "api-test"

    client:add_x_forwarded_headers("1.2.3.4", "GET", "http://api.test/")
    client.headers["user-agent"] = ua

    local api = test.client()
    nginx:add_client(api)

    local rule = assert(api:post("/rules", {
      json = {
        action = "allow",
        host = "api.test",
        ua = ua,
      }
    })).json

    test.await.no_error(function()
      client:send()
      assert.is_nil(client.err)
      assert.same(200, client.response.status)
    end, 1, 0.1, "expected request to be allowed after adding allow rule")

    assert.same(200, api:patch("/rules/" .. rule.id, {
      json = {
        action = "deny",
        host = "api.test",
        ua = ua,
      }
    }).status)

    test.await.no_error(function()
      client:send()
      assert.is_nil(client.err)
      assert.same(403, client.response.status)
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
      client:send()
      assert.is_nil(client.err)
      assert.same(200, client.response.status)
    end, 1, 0.1, "expected request to be allowed after adding new allow rule")

    assert(api:delete("/rules/" .. rule.id))

    test.await.no_error(function()
      client:send()
      assert.is_nil(client.err)
      assert.same(403, client.response.status)
    end, 1, 0.1, "expected request to be denied after deleting allow rule")
  end)

  it("responds to rule expiry", function()
    local ua = "expires-test"

    client:add_x_forwarded_headers("1.2.3.4", "GET", "http://api.test/")
    client.headers["user-agent"] = ua

    local api = test.client()
    nginx:add_client(api)

    -- add a blanket deny rule
    assert(api:post("/rules", {
      json = {
        action = "deny",
        ua = ua,
      }
    }))

    assert.same(201, api.response.status)

    -- await deny
    test.await.no_error(function()
      client:send()
      assert.is_nil(client.err)
      assert.same(403, client.response.status)
    end, 1, 0.1, "expected request to be denied after adding a deny rule")

    -- add temporary allow rule
    assert(api:post("/rules", {
      json = {
        action = "allow",
        host = "api.test",
        ua = ua,
        ttl = 2,
      }
    }))

    assert.same(201, api.response.status)

    -- await initial state update
    test.await.no_error(function()
      client:send()
      assert.is_nil(client.err)
      assert.same(200, client.response.status)
    end, 1, 0.05, "expected request to be allowed after adding temp allow rule")

    -- await expiry
    test.await.no_error(function()
      client:send()
      assert.is_nil(client.err)
      assert.same(403, client.response.status)
    end, 5, 0.1, "expected request to be denied after temp allow rule expired")
  end)

  -- This approval path is pretty well-covered by the integration tests for the /answer
  -- endpoint, so we're not going to test that here.
  describe("policy: request-approval", function()
    before_each(function()
      update_config({ unauthorized = const.unauthorized.request_approval })
    end)


    it("blocks until access is approved", function()
      local timeout = 500
      client.timeout = timeout

      client:add_x_forwarded_headers("1.2.3.4", "GET", "http://test/")
      client.headers["user-agent"] = "unknown"

      local start = ngx.now()

      client:send()
      assert.same("timeout", client.err)
      assert.is_nil(client.response)

      local elapsed = (ngx.now() - start) * 1000
      assert.near(timeout, elapsed, 100)
    end)

    it("allows access to the answer endpoint", function()
      client.headers["user-agent"] = "nope"

      client:add_x_forwarded_headers("1.2.3.4", "GET", conf.base_url .. "answer")
      client:send()
      assert.is_nil(client.err)
      assert.equals(200, client.response.status)

      client:add_x_forwarded_headers("1.2.3.4", "POST", conf.base_url .. "answer")
      client:send()
      assert.is_nil(client.err)
      assert.equals(200, client.response.status)
    end)
  end)

  describe("policy: return-401", function()
    before_each(function()
      update_config({ unauthorized = const.unauthorized.return_401 })
    end)


    it("returns a 401 for unauthorized requests", function()
      client:add_x_forwarded_headers("1.2.3.4", "GET", "http://test/")
      client.headers["user-agent"] = "unknown"

      client:send()
      assert.is_nil(client.err)
      assert.same(401, client.response.status)
    end)
  end)

  describe("policy: redirect-for-approval", function()
    before_each(function()
      update_config({
        unauthorized = const.unauthorized.redirect_for_approval,
        redirect_uri = "http://lolololo.test/",
      })
    end)


    it("redirects the client to the request approval endpoint", function()
      local url = "http://test/?a=1&b=2"
      client:add_x_forwarded_headers(test.random_ipv4(), "GET", url)
      client.headers["user-agent"] = "unknown"

      client:send()
      assert.is_nil(client.err)
      assert.same(302, client.response.status)
      local location = assert.is_string(client.response.headers.location)
      assert.matches(conf.redirect_uri, location, nil, true)

      local parsed = assert(http.parse_url(location))
      local query = ngx.decode_args(parsed.query)
      local next_url = assert.is_string(query.next)
      assert.same(url, next_url)
    end)

    it("redirects the client even when an access request is pending", function()
      local url = "http://test/?a=1&b=2"
      local addr = test.random_ipv4()
      client:add_x_forwarded_headers(addr, "GET", url)
      client.headers["user-agent"] = "unknown"

      client:send()
      assert.is_nil(client.err)
      assert.same(302, client.response.status)

      client:add_x_forwarded_headers(addr, "GET", "http://other.test/")
      client:send()
      assert.is_nil(client.err)
      assert.same(302, client.response.status)
    end)


    it("allows access to the approval endpoint", function()
      client.headers["user-agent"] = "nope"
      for _, method in ipairs({ "GET", "POST" }) do
        client:add_x_forwarded_headers(test.random_ipv4(), method, conf.base_url .. "letmein")
        client:send()
        assert.is_nil(client.err)
        assert.equals(200, client.response.status)
      end
    end)
  end)

  describe("policy: validate-email", function()
    before_each(function()
      update_config({
        unauthorized = const.unauthorized.validate_email,
        smtp = {
          host = "my-host",
          username = "my-username",
          password = "my-password",
        },
      })
    end)

    it("redirects the client to the email validation endpoint", function()
      local url = "http://test/?a=1&b=2"
      client:add_x_forwarded_headers(test.random_ipv4(), "GET", url)
      client.headers["user-agent"] = "unknown"

      client:send()
      assert.is_nil(client.err)
      assert.same(302, client.response.status)

      local location = assert.is_string(client.response.headers.location)
      assert.matches(const.endpoints.email, location, nil, true)

      local parsed = assert(http.parse_url(location))
      local query = ngx.decode_args(parsed.query)
      assert.is_string(query.s)

      client.request.path = "/email-validate"
      client.request.query = query
      client:send()
      assert.same(200, client.response.status)
      assert.same("text/html", client.response.headers["content-type"])
    end)

    it("redirects the client even when an access request is pending", function()
      local url = "http://test/?a=1&b=2"
      local addr = test.random_ipv4()
      client:add_x_forwarded_headers(addr, "GET", url)
      client.headers["user-agent"] = "unknown"

      client:send()
      assert.is_nil(client.err)
      assert.same(302, client.response.status)

      local location = assert.is_string(client.response.headers.location)
      assert.matches(const.endpoints.email, location, nil, true)

      local parsed = assert(http.parse_url(location))
      local query = ngx.decode_args(parsed.query)
      local state = assert.is_string(query.s)

      client:add_x_forwarded_headers(addr, "GET", "http://other.test/")
      client:send()
      assert.is_nil(client.err)
      assert.same(302, client.response.status)

      location = assert.is_string(client.response.headers.location)
      assert.matches(const.endpoints.email, location, nil, true)

      parsed = assert(http.parse_url(location))
      query = ngx.decode_args(parsed.query)
      assert.same(state, query.s)
    end)

    it("allows access to the approval endpoint", function()
      client.headers["user-agent"] = "nope"
      for _, method in ipairs({ "GET", "POST" }) do
        client:add_x_forwarded_headers(test.random_ipv4(), method, conf.base_url .. "email-validate")
        client:send()
        assert.is_nil(client.err)
        assert.equals(200, client.response.status)
      end
    end)

    describe("/validate-email", function()
      local state
      before_each(function()
        local url = "http://test/?a=1&b=2"
        client:add_x_forwarded_headers(test.random_ipv4(), "GET", url)
        client.headers["user-agent"] = "unknown"

        client:send()
        assert.is_nil(client.err)
        assert.same(302, client.response.status)

        local location = assert.is_string(client.response.headers.location)
        assert.matches(const.endpoints.email, location, nil, true)

        local parsed = assert(http.parse_url(location))
        local query = ngx.decode_args(parsed.query)
        assert.is_string(query.s)
        state = query.s
      end)

      describe("GET", function()
        it("with s=<state>", function()
          client.request.path = const.endpoints.email
          client.request.query = { s = state }
          client:send()
          assert.same(200, client.response.status)
          assert.same("text/html", client.response.headers["content-type"])
        end)
      end)

      describe("POST", function()
        describe("with s=<state>", function()
          it("requires email", function()
            client.request.method = "POST"
            client.request.path = const.endpoints.email
            client.request.query = { s = state }
            client.request.post = {
              email = nil,
            }

            client:send()
            assert.is_nil(client.err)
            assert.same(400, client.response.status)
          end)

          it("requires state", function()
            client.request.method = "POST"
            client.request.path = const.endpoints.email
            client.request.query = { s = state }
            client.request.post = {
              email = "who@areyou.com",
            }

            client:send()
            assert.is_nil(client.err)
            assert.same(400, client.response.status)
          end)
        end)
      end)
    end)
  end)

  describe("[bugs]", function()
    it("ignores precondition request headers, if forwarded", function()
      client:add_x_forwarded_headers("1.2.3.4", "GET", "http://test/")
      client.headers["user-agent"] = "allow"

      client.headers["If-Match"]            = [["c87e5c4cf8fabe8f75deadb57fba10a2"]]
      client.headers["If-None-Match"]       = [["c87e5c4cf8fabe8f75deadb57fba10a2"]]
      client.headers["If-Modified-Since"]   = [[Sat, 29 Oct 1994 19:43:31 GMT]]
      client.headers["If-Unmodified-Since"] = [[Sat, 29 Oct 1994 19:43:31 GMT]]

      client:send()
      assert.is_nil(client.err)
      assert.equals(200, client.response.status)
    end)

    it("ignores Range request header, if forwarded", function()
      client:add_x_forwarded_headers("1.2.3.4", "GET", "http://test/")
      client.headers["user-agent"] = "allow"

      client.headers["Range"] = "i'm invalid, just ignore me"

      client:send()
      assert.is_nil(client.err)
      assert.equals(200, client.response.status)
    end)
  end)


end)
