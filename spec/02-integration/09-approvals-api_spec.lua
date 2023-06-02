local test = require "spec.testing"
local const = require "doorbell.constants"
local http = require "doorbell.http"
local cjson = require "cjson"

describe("access API", function()

  ---@type spec.testing.client
  local client

  ---@type spec.testing.nginx
  local nginx

  ---@type doorbell.config
  local conf

  local redirect_uri = "http://lolololo.test/"

  local function check_access(addr, url, method, ua)
    method = method or "GET"

    client:reset()
    client:add_x_forwarded_headers(addr, method, url)
    client.headers["user-agent"] = ua
    client:get("/ring")
  end


  ---@param addr    string
  ---@param url     string
  ---@param method? string
  ---@param ua?     string
  ---@param msg?    string
  local function assert_access_approved(addr, url, method, ua, msg)
    check_access(addr, url, method, ua)
    assert.same(200, client.response.status, msg)
  end

  ---@param  addr          string
  ---@param  url           string
  ---@param  method?       string
  ---@param  ua?           string
  ---@param  msg?          string
  ---@return table<string, any>
  local function assert_access_not_approved(addr, url, method, ua, msg, status)
    check_access(addr, url, method, ua)

    status = status or 302
    assert.same(status, client.response.status, msg)

    local location = assert.response(client.response).has.header("location")

    local parsed = assert(http.parse_url(location))
    local query = ngx.decode_args(parsed.query)

    assert.is_string(query.token)
    assert.not_nil(query.scopes)
    assert.not_nil(query.subjects)

    assert.is_string(query.max_ttl)
    assert.is_number(tonumber(query.max_ttl))

    return query
  end


  ---@param addr    string
  ---@param url     string
  ---@param method? string
  ---@param ua?     string
  ---@param msg?    string
  ---@param status? integer
  local function await_access(addr, url, method, ua, msg, status)
    status = status or 200
    local deadline = ngx.now() + 5

    check_access(addr, url, method, ua)

    while ngx.now() < deadline do
      check_access(addr, url, method, ua)

      if client.response.status == status then
        break
      end

      ngx.sleep(0.01)
    end

    assert.same(status, client.response.status, msg)
  end

  ---@param addr    string
  ---@param url     string
  ---@param method? string
  ---@param ua?     string
  ---@param msg?    string
  ---@param status? integer
  local function await_no_access(addr, url, method, ua, msg, status)
    status = status or 302
    await_access(addr, url, method, ua, msg, status)
  end


  ---@param params doorbell.auth.access.api.intent
  local function assert_not_approve(params)
    client:reset()

    client:post("/access/intent", {
      json = params,
    })

    assert.same(400, client.response.status)

    local ct = assert.response(client.response).has.header("content-type")
    assert.same("application/json", ct)
    assert.is_table(client.response.json)
  end


  ---@param params doorbell.auth.access.api.intent
  local function assert_approve(params)
    client:reset()

    client:post("/access/intent", {
      json = params,
    })

    assert.same(201, client.response.status, client.response.body)

    local ct = assert.response(client.response).has.header("content-type")
    assert.same("application/json", ct)
    assert.is_table(client.response.json)
  end


  lazy_setup(function()
    conf = test.config()
    conf.allow = { { ua = "allow" } }
    conf.deny  = { { ua = "deny" } }
    conf.unauthorized = const.unauthorized.redirect_for_approval
    conf.redirect_uri = redirect_uri

    nginx = test.nginx(conf)
    nginx:conf_test()
    nginx:start()

    client = test.client()
    nginx:add_client(client)

    client.raise_on_connect_error = true
    client.raise_on_request_error = true
    client.assert_status.GET = {
      one_of = { 200, 404, 302 },
    }
    client.reopen = true
  end)

  lazy_teardown(function()
    client:close()
    nginx:stop()
  end)

  describe("GET /access/config", function()
    before_each(function()
      nginx:restart()
    end)

    it("returns current access approval configuration", function()
      client:get("/access/config")
      assert.same(200, client.response.status)
      assert.is_table(client.response.json)
      assert.is_table(client.response.json.allowed_scopes)
      assert.is_table(client.response.json.allowed_subjects)
      assert.is_number(client.response.json.max_ttl)
    end)
  end)

  describe("GET /access/pending", function()
    before_each(function()
      nginx:restart()
    end)

    it("encodes an empty array properly", function()
      client:get("/access/pending")
      local data = assert.is_table(client.response.json and client.response.json.data)
      assert.same(0, #data)
      assert.same("[]", cjson.encode(data))
      assert.equals(cjson.array_mt, debug.getmetatable(data))
    end)

    it("lists pending approval requests", function()
      local count = 10
      for _ = 1, count do
        local addr = test.random_ipv4()
        assert_access_not_approved(addr, "http://approvals.test/")
      end

      client:get("/access/pending")
      local data = assert.is_table(client.response.json and client.response.json.data)
      assert.same(count, #data)

      for _, item in ipairs(data) do
        assert.table_shape({
          token = "string",
          request = "table",
          created = "number",
        }, item)
      end
    end)

    it("gets pending approval requests by token", function()
      local addr = test.random_ipv4()
      local url = "http://approvals.test/by-token"
      local method = "GET"
      local ua = "test test test"
      local query = assert_access_not_approved(addr, url, method, ua)

      client:reset()
      client:get("/access/pending/by-token/" .. query.token)
      assert.same(200, client.response.status)

      local json = client.response.json
      assert.is_table(json)
      assert.same(query.token, json.token)
      assert.is_table(json.request)

      assert.is_number(json.max_ttl)
      assert.is_table(json.allowed_scopes)
      assert.is_table(json.allowed_subjects)

      assert.same({
        addr   = addr,
        scheme = "http",
        host   = "approvals.test",
        path   = "/by-token",
        uri    = "/by-token",
        method = method,
        ua     = ua,
      }, json.request)
    end)

    it("gets pending approval requests by IP address", function()
      local addr = test.random_ipv4()
      local url = "http://approvals.test/with-ip-address"
      local method = "GET"
      local ua = "test test test"
      local query = assert_access_not_approved(addr, url, method, ua)

      client:reset()
      client:get("/access/pending/by-addr/" .. addr)
      assert.same(200, client.response.status)

      local json = client.response.json
      assert.is_table(json)
      assert.same(query.token, json.token)
      assert.is_table(json.request)

      assert.is_number(json.max_ttl)
      assert.is_table(json.allowed_scopes)
      assert.is_table(json.allowed_subjects)

      assert.same({
        addr   = addr,
        scheme = "http",
        host   = "approvals.test",
        path   = "/with-ip-address",
        uri    = "/with-ip-address",
        method = method,
        ua     = ua,
      }, json.request)
    end)
  end)

  describe("POST /access/intent", function()
    before_each(function()
      nginx:restart()
    end)

    it("approves pending approval requests", function()
      local uri = "http://approvals.test/"

      ---@type { addr:string, token:string }[]
      local items = {}
      local count = 10
      for i = 1, count do
        local addr = test.random_ipv4()
        local query = assert_access_not_approved(addr, uri)
        items[i] = { addr = addr, token = query.token }
      end

      for i, item in ipairs(items) do
        assert_approve({
          action  = "allow",
          scope   = "global",
          subject = "addr",
          token   = item.token,
          ttl     = 300,
        })

        assert_access_approved(item.addr, uri)

        client:reset()
        client:get("/access/pending")
        local data = assert.is_table(client.response.json and client.response.json.data)
        assert.same(count - i, #data)
      end

    end)

    it("supports application/x-www-form-urlencoded", function()
      local uri = "http://approvals.test/form"
      local addr = test.random_ipv4()
      local query = assert_access_not_approved(addr, uri)

      local ttl = 456

      client:reset()
      client:post("/access/intent", {
        post = {
          action  = "allow",
          scope   = "global",
          subject = "addr",
          token   = query.token,
          ttl     = tostring(ttl),
        },
      })

      assert.same(201, client.response.status)
      assert_access_approved(addr, uri)
    end)
  end)

  describe("pre-approval", function()
    local pre_approval_ttl = 1

    lazy_setup(function()
      conf.approvals = {
        pre_approval_ttl = pre_approval_ttl,
        max_ttl = 60,
      }

      nginx:update_config(conf)
      nginx:restart()
    end)

    before_each(function()
      client:reset()
      nginx:truncate_logs()
    end)

    it("allows requests to be pre-approved by addr", function()
      local ttl = 2

      local method = "GET"
      local addr = test.random_ipv4()
      local ua = "random ua " .. addr
      local url = "http://pre-approval.test/" .. addr

      client.headers["x-forwarded-for"] = addr

      client:post("/access/pre-approval", {
        json = {
          scope   = "global",
          subject = "addr",
          ttl     = ttl,
        },
      })

      assert.same(201, client.response.status, client.response)
      assert.same(addr, client.response.json.subject)

      client:get("/access/pre-approved")
      assert.same(200, client.response.status, client.response)
      local json = assert.is_table(client.response.json)
      assert.is_table(json.data)
      assert.same(1, #json.data)

      local pre = json.data[1]
      assert.is_table(pre)
      assert.is_string(pre.token)
      assert.same("global", pre.scope)
      assert.same("addr", pre.subject)
      assert.same(ttl, pre.ttl)
      assert.is_number(pre.created)
      assert.is_number(pre.expires)

      await_access(addr, url, method, ua)

      -- again, to make sure we match our pre-approval rule
      assert_access_approved(addr, url, method, ua)
      assert_access_approved(addr, url, method, ua)

      await_no_access(addr, url, method, ua)
    end)


    it("expires pre-approvals after a set time period", function()
      local ttl = 2

      local method = "GET"
      local addr = test.random_ipv4()
      local ua = "random ua " .. addr
      local url = "http://pre-approval.test/" .. addr

      client.headers["x-forwarded-for"] = addr

      client:post("/access/pre-approval", {
        json = {
          scope   = "global",
          subject = "addr",
          ttl     = ttl,
        },
      })

      assert.same(201, client.response.status)
      assert.same(addr, client.response.json.subject)

      ngx.sleep(pre_approval_ttl + 1)
      assert_access_not_approved(addr, url, method, ua)
    end)

    it("clears stale pending access requests on approval", function()
      local method = "GET"
      local addr = test.random_ipv4()
      local ua = "random ua " .. addr
      local url = "http://pre-approval.test/" .. addr

      local query = assert_access_not_approved(addr, url, method, ua)
      client:get("/access/pending/by-token/" .. query.token)
      assert.same(200, client.response.status)

      client.headers["x-forwarded-for"] = addr

      client:post("/access/pre-approval", {
        json = {
          scope   = "url",
          subject = "addr",
          ttl     = 30,
        },
      })

      assert.same(201, client.response.status, client.response)
      assert.same(addr, client.response.json.subject)

      await_access(addr, url, method, ua)
      assert_access_approved(addr, url, method, ua)

      client:get("/access/pending/by-token/" .. query.token)
      assert.same(404, client.response.status)

      client:get("/access/pending/by-addr/" .. addr)
      assert.same(404, client.response.status)
    end)


    for _, scope in pairs(const.scopes) do
    for _, subject in pairs(const.subjects) do
      it("scope: " .. scope .. ", subject: " .. subject, function()
        local sub_host          = scope .. "." .. subject .. ".pre-approval.test"
        local sub_method        = "GET"
        local sub_addr          = test.random_ipv4()
        local sub_ua            = "(my user-agent " .. sub_addr .. ")"
        local sub_path          = "/path/" .. sub_addr
        local sub_url           = "http://" .. sub_host .. sub_path

        local alt_host      = "alt." .. sub_host
        local alt_method    = "HEAD"
        local alt_addr      = test.random_ipv4()
        local alt_ua        = sub_ua .. " (alt)"
        local alt_path      = "/alt/" .. sub_addr
        local alt_host_url  = "http://" .. alt_host .. alt_path

        local alt_path_url = "http://" .. sub_host .. alt_path

        client.headers["x-forwarded-for"] = sub_addr
        client.headers["user-agent"] = sub_ua

        local ttl = 2

        client:post("/access/pre-approval", {
          json = {
            scope   = scope,
            subject = subject,
            ttl     = ttl,
          },
        })

        assert.same(201, client.response.status, client.response.json)

        local function ok(addr_, url_, method_, ua_)
          local msg = "expected access approval for request from "
                   .. (addr_ == sub_addr and "subject addr" or "alt addr")
                   .. " to "
                   .. (
                        (url_ == sub_url and "subject url")
                        or
                        (url_ == alt_host_url and "alt url")
                        or
                        (url_ == alt_path_url and "subject host, alt path")
                        or
                        ""
                      )
                   .. " with "
                   .. (ua_ == sub_ua and "subject user-agent" or "alt user-agent")
                   .. " and "
                   .. (method_ == sub_method and "subject method" or "alt method")
                   .. ("\nurl: %q"):format(url_)
                   .. ("\nuser-agent: %q"):format(ua_)

          for _ = 1, 3 do
            assert_access_approved(addr_, url_, method_, ua_, msg)
          end
        end

        local function no(addr_, url_, method_, ua_)
          local msg = "expected access pending/denied for request from "
                   .. (addr_ == sub_addr and "subject addr" or "alt addr")
                   .. " to "
                   .. (
                        (url_ == sub_url and "subject url")
                        or
                        (url_ == alt_host_url and "alt url")
                        or
                        (url_ == alt_path_url and "subject host, alt path")
                        or
                        ""
                      )
                   .. " with "
                   .. (ua_ == sub_ua and "subject user-agent" or "alt user-agent")
                   .. " and "
                   .. (method_ == sub_method and "subject method" or "alt method")
                   .. ("\nurl: %q"):format(url_)
                   .. ("\nuser-agent: %q"):format(ua_)

          for _ = 1, 3 do
            assert_access_not_approved(addr_, url_, method_, ua_, msg)
          end
        end

        -- this is our "control" request, which will trigger the pre-approval
        -- rule creation
        await_access(sub_addr, sub_url, sub_method, sub_ua)

        local start = ngx.now()

        if scope == "global" and subject == "addr" then
          ok(sub_addr, sub_url,      sub_method, sub_ua)
          ok(sub_addr, sub_url,      alt_method, sub_ua)
          ok(sub_addr, alt_path_url, alt_method, sub_ua)
          ok(sub_addr, alt_host_url, alt_method, sub_ua)

          no(alt_addr, sub_url,      sub_method, sub_ua)
          no(alt_addr, sub_url,      alt_method, sub_ua)
          no(alt_addr, alt_path_url, alt_method, sub_ua)
          no(alt_addr, alt_host_url, alt_method, sub_ua)

          ok(sub_addr, sub_url,      sub_method, alt_ua)
          ok(sub_addr, sub_url,      alt_method, alt_ua)
          ok(sub_addr, alt_path_url, alt_method, alt_ua)
          ok(sub_addr, alt_host_url, alt_method, alt_ua)


        elseif scope == "global" and subject == "ua" then
          ok(sub_addr, sub_url,      sub_method, sub_ua)
          ok(sub_addr, sub_url,      alt_method, sub_ua)
          ok(sub_addr, alt_path_url, alt_method, sub_ua)
          ok(sub_addr, alt_host_url, alt_method, sub_ua)

          ok(alt_addr, sub_url,      sub_method, sub_ua)
          ok(alt_addr, sub_url,      alt_method, sub_ua)
          ok(alt_addr, alt_path_url, alt_method, sub_ua)
          ok(alt_addr, alt_host_url, alt_method, sub_ua)

          no(sub_addr, sub_url,      sub_method, alt_ua)
          no(sub_addr, sub_url,      alt_method, alt_ua)
          no(sub_addr, alt_path_url, alt_method, alt_ua)
          no(sub_addr, alt_host_url, alt_method, alt_ua)

        elseif scope == "host" and subject == "addr" then
          ok(sub_addr, sub_url,      sub_method, sub_ua)
          ok(sub_addr, sub_url,      alt_method, sub_ua)
          ok(sub_addr, alt_path_url, alt_method, sub_ua)
          no(sub_addr, alt_host_url, alt_method, sub_ua)

          no(alt_addr, sub_url,      sub_method, sub_ua)
          no(alt_addr, sub_url,      alt_method, sub_ua)
          no(alt_addr, alt_path_url, alt_method, sub_ua)
          no(alt_addr, alt_host_url, alt_method, sub_ua)

          ok(sub_addr, sub_url,      sub_method, alt_ua)
          ok(sub_addr, sub_url,      alt_method, alt_ua)
          ok(sub_addr, alt_path_url, alt_method, alt_ua)
          no(sub_addr, alt_host_url, alt_method, alt_ua)

        elseif scope == "host" and subject == "ua" then
          ok(sub_addr, sub_url,      sub_method, sub_ua)
          ok(sub_addr, sub_url,      alt_method, sub_ua)
          ok(sub_addr, alt_path_url, alt_method, sub_ua)
          no(sub_addr, alt_host_url, alt_method, sub_ua)

          ok(alt_addr, sub_url,      sub_method, sub_ua)
          ok(alt_addr, sub_url,      alt_method, sub_ua)
          ok(alt_addr, alt_path_url, alt_method, sub_ua)
          no(alt_addr, alt_host_url, alt_method, sub_ua)

          no(sub_addr, sub_url,      sub_method, alt_ua)
          no(sub_addr, sub_url,      alt_method, alt_ua)
          no(sub_addr, alt_path_url, alt_method, alt_ua)
          no(sub_addr, alt_host_url, alt_method, alt_ua)

        elseif scope == "url" and subject == "addr" then
          ok(sub_addr, sub_url,      sub_method, sub_ua)
          ok(sub_addr, sub_url,      alt_method, sub_ua)
          no(sub_addr, alt_path_url, alt_method, sub_ua)
          no(sub_addr, alt_host_url, alt_method, sub_ua)

          no(alt_addr, sub_url,      sub_method, sub_ua)
          no(alt_addr, sub_url,      alt_method, sub_ua)
          no(alt_addr, alt_path_url, alt_method, sub_ua)
          no(alt_addr, alt_host_url, alt_method, sub_ua)

          ok(sub_addr, sub_url,      sub_method, alt_ua)
          ok(sub_addr, sub_url,      alt_method, alt_ua)
          no(sub_addr, alt_path_url, alt_method, alt_ua)
          no(sub_addr, alt_host_url, alt_method, alt_ua)

        elseif scope == "url" and subject == "ua" then
          ok(sub_addr, sub_url,      sub_method, sub_ua)
          ok(sub_addr, sub_url,      alt_method, sub_ua)
          no(sub_addr, alt_path_url, alt_method, sub_ua)
          no(sub_addr, alt_host_url, alt_method, sub_ua)

          ok(alt_addr, sub_url,      sub_method, sub_ua)
          ok(alt_addr, sub_url,      alt_method, sub_ua)
          no(alt_addr, alt_path_url, alt_method, sub_ua)
          no(alt_addr, alt_host_url, alt_method, sub_ua)

          no(sub_addr, sub_url,      sub_method, alt_ua)
          no(sub_addr, sub_url,      alt_method, alt_ua)
          no(sub_addr, alt_path_url, alt_method, alt_ua)
          no(sub_addr, alt_host_url, alt_method, alt_ua)

        else
          error("unreachable")
        end

        local remain = (start + ttl) - ngx.now()
        assert(remain > 0, "no TTL remaining, tests ran too slowly")

        while remain > 0 do
          client.headers["user-agent"] = sub_ua
          client:add_x_forwarded_headers(sub_addr, sub_method, sub_url)
          client:get("/ring")

          if client.response.status > 200 then
            break
          end

          remain = (start + ttl) - ngx.now()
          ngx.sleep(0.01)
        end

        await_no_access(sub_addr, sub_url, sub_method, sub_ua)

        no(sub_addr, sub_url,      sub_method, sub_ua)
        no(sub_addr, sub_url,      alt_method, sub_ua)
        no(sub_addr, alt_path_url, alt_method, sub_ua)
        no(sub_addr, alt_host_url, alt_method, sub_ua)

        no(alt_addr, sub_url,      sub_method, sub_ua)
        no(alt_addr, sub_url,      alt_method, sub_ua)
        no(alt_addr, alt_path_url, alt_method, sub_ua)
        no(alt_addr, alt_host_url, alt_method, sub_ua)

        no(sub_addr, sub_url,      sub_method, alt_ua)
        no(sub_addr, sub_url,      alt_method, alt_ua)
        no(sub_addr, alt_path_url, alt_method, alt_ua)
        no(sub_addr, alt_host_url, alt_method, alt_ua)
      end)

    end -- each subject
    end -- each scope

  end)

  describe("configurable limits", function()
    it("subject", function()
      conf.approvals = {
        allowed_subjects = { "addr" },
      }
      nginx:update_config(conf)
      nginx:restart()

      local uri = "http://approvals.test/"

      local addr = test.random_ipv4()
      local query = assert_access_not_approved(addr, uri)
      assert.same("addr", query.subjects)

      local token = assert.is_string(query.token)


      assert_not_approve({
        action  = "allow",
        scope   = "global",
        subject = "ua",
        token   = token,
        ttl     = 300,
      })

      assert_approve({
        action  = "allow",
        scope   = "global",
        subject = "addr",
        token   = token,
        ttl     = 300,
      })

      assert_access_approved(addr, uri)
    end)

    it("scope", function()
      conf.approvals = {
        allowed_scopes = { "url", "host" },
      }
      nginx:update_config(conf)
      nginx:restart()

      local uri = "http://approvals.test/"

      local addr = test.random_ipv4()
      local query = assert_access_not_approved(addr, uri)

      assert.is_table(query.scopes)
      table.sort(query.scopes)
      assert.same({ "host", "url" }, query.scopes)

      local token = assert.is_string(query.token)

      assert_not_approve({
        action  = "allow",
        scope   = "global",
        subject = "addr",
        token   = token,
        ttl     = 300,
      })

      assert_approve({
        action  = "allow",
        scope   = "url",
        subject = "addr",
        token   = token,
        ttl     = 300,
      })

      assert_access_approved(addr, uri)
    end)


    it("ttl", function()
      local max = 90

      conf.approvals = {
        max_ttl = max,
      }
      nginx:update_config(conf)
      nginx:restart()

      local uri = "http://approvals.test/"

      local addr = test.random_ipv4()
      local query = assert_access_not_approved(addr, uri)

      assert.same(tostring(max), query.max_ttl)

      local token = assert.is_string(query.token)

      assert_not_approve({
        action  = "allow",
        scope   = "global",
        subject = "addr",
        token   = token,
        ttl     = max + 1,
      })

      assert_approve({
        action  = "allow",
        scope   = "url",
        subject = "addr",
        token   = token,
        ttl     = max - 1,
      })

      assert_access_approved(addr, uri)
    end)

  end)

end)
