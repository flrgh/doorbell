local test = require "spec.testing"
local const = require "spec.testing.constants"
local ms = require "spec.testing.mock-upstream"

local fmt = string.format

describe("jellyfin", function()

  ---@type spec.testing.client
  local client

  ---@type spec.testing.nginx
  local nginx

  ---@type doorbell.config
  local conf

  lazy_setup(function()
    if not conf then
      conf = test.config()

      conf.allow = { { ua = "allow" } }
      conf.deny  = { { ua = "deny" } }
      conf.trusted = { "127.0.0.1/8" }
      conf.plugins = {
        jellyfin = {
          url = "http://jellyfin",
          api = fmt("http://127.0.0.1:%s", const.MOCK_UPSTREAM_PORT),
          allow_ttl = 3,
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

  describe("globally allowed endpoints", function()
    local paths = {
      "/",
      "/Branding/Configuration",
      "/Branding/css",
      "/quickconnect/enabled",
      "/System/Info/Public",
      "/Users/Public",
      "/web/config.json",
      "/web/index.html",
      "/web/main.jellyfin.bundle.js",
      "/web/themes/dark/theme.css",
      "/web/foo.js",
      "/web/blah/blah.png",
      "/web/yep.ico",
    }

    it("frontend paths", function()
      for _, path in ipairs(paths) do
        client:add_x_forwarded_headers("1.2.3.4", "GET", "http://jellyfin" .. path)
        client:send()
        assert.is_nil(client.err)
        assert.equals(200, client.response.status)
      end
    end)

    it("denies them if matched by a `deny` rule", function()
      client.headers["user-agent"] = "deny"
      for _, path in ipairs(paths) do
        client:add_x_forwarded_headers("1.2.3.4", "GET", "http://jellyfin" .. path)
        client:send()
        assert.is_nil(client.err)
        assert.equals(403, client.response.status)
      end
    end)
  end)

  describe("auth token validation", function()
    describe("allows requests when /Users/Me returns 200", function()
      local addr
      local token

      before_each(function()
        addr = test.random_ipv4()
        token = test.random_string()
      end)

      local function assert_access()
        ms.mock.prepare({
          path = "/Users/Me",
          method = "GET",
          response = {
            status = 200,
            headers = { ["Content-Type"] = "application/json" },
            json = {
              Name = "joseph",
            },
          },
        })
        client:send()
        assert.is_nil(client.err)
        assert.equals(200, client.response.status)

        local res, req = ms.mock.get_last()
        assert.is_table(res)
        assert.equals(200, res.status)
        assert.is_table(req)
        assert.is_table(req.headers)
        assert.equals(token, req.headers["x-emby-token"])
      end

      local tpl = [[MediaBrowser Client="Jellyfin Web", ]]
               .. [[Device="Firefox", DeviceId="deadbeef", ]]
               .. [[Version="10.8.10", Token="%s"]]

      it("using X-Emby-Authorization", function()
        client:add_x_forwarded_headers(addr, "GET", "http://jellyfin/Library/MediaFolders")
        client.headers["X-Emby-Authorization"] = tpl:format(token)
        assert_access()
      end)

      it("using Authorization", function()
        client:add_x_forwarded_headers(addr, "GET", "http://jellyfin/Library/MediaFolders")
        client.headers["Authorization"] = tpl:format(token)
        assert_access()
      end)

      it("using X-Mediabrowser-Token", function()
        client:add_x_forwarded_headers(addr, "GET", "http://jellyfin/Library/MediaFolders")
        client.headers["X-Mediabrowser-Token"] = token
        assert_access()
      end)

      it("using the api_key query param", function()
        local query = ngx.encode_args({ Api_Key = token })

        client:add_x_forwarded_headers(addr, "GET",
                                       "http://jellyfin/Library/MediaFolders?" .. query)
        assert_access()
      end)

      it("caches the auth token validation", function()
        client:add_x_forwarded_headers(addr, "GET", "http://jellyfin/Library/MediaFolders")
        client.headers["X-Mediabrowser-Token"] = token
        assert_access()

        ms.mock.prepare({
          path = "/Users/Me",
          method = "GET",
          response = {
            status = 401,
            headers = { ["Content-Type"] = "application/json" },
            json = { message = "nope!" },
          },
        })

        client:send()
        assert.is_Nil(client.err)
        assert.equals(200, client.response.status)
      end)
    end)

    it("adds an allow rule for valid tokens", function()
      local username = "my_username"

      ms.mock.prepare({
        path = "/Users/Me",
        method = "GET",
        response = {
          status = 200,
          headers = { ["Content-Type"] = "application/json" },
          json = {
            blahblah = true,
            Name = username,
          },
        },
      })

      local token = test.random_string()
      local addr = test.random_ipv4()

      client:add_x_forwarded_headers(addr, "GET", "http://jellyfin/Library/MediaFolders")
      client.headers["X-Mediabrowser-Token"] = token
      client:send()
      assert.is_nil(client.err)
      assert.equals(200, client.response.status)

      local res, req = ms.mock.get_last()
      assert.is_table(res)
      assert.equals(200, res.status)
      assert.is_table(req)
      assert.is_table(req.headers)
      assert.equals(token, req.headers["x-emby-token"])

      local api = nginx:add_client(test.client())
      test.await.truthy(function()
        res = api:get("/rules")
        assert.is_nil(api.err)
        assert.equals(200, res.status)
        assert.is_table(res.json)
        assert.is_table(res.json.data)

        for _, rule in ipairs(res.json.data) do
          if rule.host == "jellyfin"
            and rule.addr == addr
            and rule.action == "allow"
            and rule.comment
            and rule.comment:find(username)
          then
            return true
          end
        end

        return false
      end, 5, 1)
    end)

    it("recreates allow rules as necessary", function()
      local username = "my_username"

      ms.mock.prepare({
        path = "/Users/Me",
        method = "GET",
        response = {
          status = 200,
          headers = { ["Content-Type"] = "application/json" },
          json = {
            blahblah = true,
            Name = username,
          },
        },
      })

      local token = test.random_string()
      local addr = test.random_ipv4()

      client:add_x_forwarded_headers(addr, "GET", "http://jellyfin/Library/MediaFolders")
      client.headers["X-Mediabrowser-Token"] = token
      client:send()
      assert.is_nil(client.err)
      assert.equals(200, client.response.status)

      local res, req = ms.mock.get_last()
      assert.is_table(res)
      assert.equals(200, res.status)
      assert.is_table(req)
      assert.is_table(req.headers)
      assert.equals(token, req.headers["x-emby-token"])

      local api = nginx:add_client(test.client())

      local rule_id

      local function have_rule()
        res = api:get("/rules")
        assert.is_nil(api.err)
        assert.equals(200, res.status)
        assert.is_table(res.json)
        assert.is_table(res.json.data)

        for _, rule in ipairs(res.json.data) do
          if rule.host == "jellyfin"
            and rule.addr == addr
            and rule.action == "allow"
            and rule.comment
            and rule.comment:find(username)
            and rule.source == "plugin"
            and rule.plugin == "jellyfin"
          then
            rule_id = rule.id
            return true
          end
        end

        return false
      end

      test.await.truthy(have_rule, 5, 1)
      test.await.falsy(have_rule, 10, 1)

      local old_id = rule_id

      client:send()
      assert.is_nil(client.err)
      assert.equals(200, client.response.status)

      test.await.truthy(have_rule, 5, 1)
      assert.not_equal(rule_id, old_id)
    end)

    it("does not allow requests when /Users/Me returns non-200", function()
      ms.mock.prepare({
        path = "/Users/Me",
        method = "GET",
        response = {
          status = 400,
          headers = { ["Content-Type"] = "application/json" },
          json = {
            message = "nope!",
          },
        },
      })

      local token = test.random_string()
      local addr = test.random_ipv4()

      client:add_x_forwarded_headers(addr, "GET", "http://jellyfin/Library/MediaFolders")
      client.headers["X-Mediabrowser-Token"] = token
      client:send()

      assert.is_nil(client.err)
      assert.equals(401, client.response.status)
    end)

    it("invalidates auth tokens on logout", function()
      local username = "my_username"

      ms.mock.prepare({
        path = "/Users/Me",
        method = "GET",
        response = {
          status = 200,
          headers = { ["Content-Type"] = "application/json" },
          json = {
            blahblah = true,
            Name = username,
          },
        },
      })

      local token = test.random_string()
      local addr = test.random_ipv4()

      client:add_x_forwarded_headers(addr, "GET", "http://jellyfin/Library/MediaFolders")
      client.headers["X-Mediabrowser-Token"] = token
      client:send()
      assert.is_nil(client.err)
      assert.equals(200, client.response.status)

      local res, req = ms.mock.get_last()
      assert.is_table(res)
      assert.equals(200, res.status)
      assert.is_table(req)
      assert.is_table(req.headers)
      assert.equals(token, req.headers["x-emby-token"])

      local api = nginx:add_client(test.client())

      local function have_rule()
        res = api:get("/rules")
        assert.is_nil(api.err)
        assert.equals(200, res.status)
        assert.is_table(res.json)
        assert.is_table(res.json.data)

        for _, rule in ipairs(res.json.data) do
          if rule.host == "jellyfin"
            and rule.addr == addr
            and rule.action == "allow"
            and rule.comment
            and rule.comment:find(username)
          then
            return true
          end
        end

        return false
      end

      test.await.truthy(have_rule, 5, 1)

      client:add_x_forwarded_headers(addr, "POST", "http://jellyfin/Sessions/Logout")
      client.headers["X-Mediabrowser-Token"] = token
      client:send()
      assert.is_nil(client.err)
      assert.equals(200, client.response.status)

      -- wait for the rule to expire
      test.await.falsy(have_rule, 10, 1)

      ms.mock.prepare({
        path = "/Users/Me",
        method = "GET",
        response = {
          status = 401,
          headers = { ["Content-Type"] = "application/json" },
          json = {
            blahblah = true,
            Name = username,
          },
        },
      })

      client:add_x_forwarded_headers(addr, "GET", "http://jellyfin/Library/MediaFolders")
      client.headers["X-Mediabrowser-Token"] = token
      client:send()
      assert.is_nil(client.err)
      assert.equals(401, client.response.status)
    end)
  end)
end)
