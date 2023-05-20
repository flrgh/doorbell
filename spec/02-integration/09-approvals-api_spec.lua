local test = require "spec.testing"
local const = require "doorbell.constants"
local http = require "doorbell.http"

describe("approvals API", function()

  ---@type spec.testing.client
  local client

  ---@type spec.testing.nginx
  local nginx

  ---@type doorbell.config
  local conf


  ---@param addr string
  ---@param url string
  ---@param method? string
  ---@param ua? string
  local function assert_access_approved(addr, url, method, ua)
    method = method or "GET"
    client:reset()

    client:add_x_forwarded_headers(addr, method, url)
    client.headers["user-agent"] = ua
    client:get("/ring")
    assert.same(200, client.response.status)
  end

  ---@param addr string
  ---@param url string
  ---@param method? string
  ---@param ua? string
  ---@return table<string, any>
  local function assert_access_not_approved(addr, url, method, ua)
    method = method or "GET"
    client:reset()

    client:add_x_forwarded_headers(addr, method, url)
    client.headers["user-agent"] = ua
    client:get("/ring")
    assert.same(302, client.response.status)

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

  ---@param params doorbell.auth.approval.answer
  local function assert_not_approve(params)
    client:reset()

    client:post("/approvals", {
      json = params,
    })

    assert.same(400, client.response.status)

    local ct = assert.response(client.response).has.header("content-type")
    assert.same("application/json", ct)
    assert.is_table(client.response.json)
  end


  ---@param params doorbell.auth.approval.answer
  local function assert_approve(params)
    client:reset()

    client:post("/approvals", {
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
    conf.redirect_uri = "http://lolololo.test/"

    nginx = test.nginx(conf)
    nginx:conf_test()
    nginx:start()

    client = test.client()

    client.raise_on_connect_error = true
    client.raise_on_request_error = true
    client.assert_status.GET = {
      gte = 200,
      lt = 400,
    }
    client.reopen = true
  end)

  lazy_teardown(function()
    client:close()
    nginx:stop()
  end)

  before_each(function()
    nginx:restart()
  end)


  describe("GET /approvals", function()
    it("lists pending approval requests", function()
      local count = 10
      for _ = 1, count do
        local addr = test.random_ipv4()
        assert_access_not_approved(addr, "http://approvals.test/")
      end

      client:get("/approvals")
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
  end)

  describe("POST /approvals", function()
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
        client:get("/approvals")
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
      client:post("/approvals", {
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
