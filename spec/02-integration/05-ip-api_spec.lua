local test = require "spec.testing"
local join = test.fs.join

describe("IP API", function()
  local prefix = os.getenv("DOORBELL_PREFIX") or join(test.ROOT_DIR, "test")
  local conf

  ---@type spec.testing.nginx
  local nginx

  ---@type spec.testing.client
  local client

  describe("/ip/addr", function()
    lazy_setup(function()
      conf = test.config(prefix)
      conf.trusted = { "127.0.0.0/8", "::1"}
      nginx = test.nginx(prefix, conf)
      nginx:conf_test()
      nginx:start()
      client = test.client()
    end)

    lazy_teardown(function()
      client:close()
      nginx:stop()
    end)

    it("returns the client IP address", function()
      local res, err = client:get("/ip/addr")
      assert.is_nil(err)
      assert.same(200, res.status)
      assert.same("127.0.0.1", res.body)
      assert.same("text/plain", res.headers.content_type)
    end)

    for _, header in ipairs({ "X-Forwarded-For", "X-Real-IP" }) do
    it("respects " .. header .. " from trusted client IPs", function()
      client:reset()

      -- one level
      client.headers[header] = "1.2.3.4"
      local res, err = client:get("/ip/addr")
      assert.is_nil(err)
      assert.same(200, res.status)
      assert.same("1.2.3.4", res.body)
      assert.same("text/plain", res.headers["content-type"])

      -- recursive
      client.headers[header] = "1.2.3.4, 127.0.1.2, 127.0.1.3"
      res, err = client:get("/ip/addr")
      assert.is_nil(err)
      assert.same(200, res.status)
      assert.same("1.2.3.4", res.body)
      assert.same("text/plain", res.headers["content-type"])

      -- stops at the first untrusted IP
      client.headers[header] = "1.2.3.4, 127.0.1.2, 4.3.2.1, 127.0.1.3"
      res, err = client:get("/ip/addr")
      assert.is_nil(err)
      assert.same(200, res.status)
      assert.same("4.3.2.1", res.body)
      assert.same("text/plain", res.headers["content-type"])

      -- IPv6
      client.headers[header] = "2607:f8b0:400a:803::200e, ::1"
      res, err = client:get("/ip/addr")
      assert.is_nil(err)
      assert.same(200, res.status)
      assert.same("2607:f8b0:400a:803::200e", res.body)
      assert.same("text/plain", res.headers["content-type"])
    end)
    end
  end)

  local GEOIP_CASES = {
    {
      name = "IPv4 city",
      db = test.constants.GEOIP_CITY_DB,
      exp = {
        addr           = "216.160.83.56",
        city           = "Milton",
        continent      = "North America",
        continent_code = "NA",
        country        = "United States",
        country_code   = "US",
        latitude       = 47.2513,
        longitude      = -122.3149,
        postal_code    = "98354",
        region         = "Washington",
        region_code    = "WA",
        time_zone      = "America/Los_Angeles",
      }
    },
    {
      name = "IPv4 country",
      db = test.constants.GEOIP_COUNTRY_DB,
      exp = {
        addr           = "216.160.83.56",
        continent      = "North America",
        continent_code = "NA",
        country        = "United States",
        country_code   = "US",
      }
    },
  }

  for _, case in ipairs(GEOIP_CASES) do
    describe("/ip/info", function()

      lazy_setup(function()
        conf = test.config(prefix)
        conf.trusted = { "127.0.0.0/8", "::1"}
        conf.geoip_db = case.db
        nginx = test.nginx(prefix, conf)
        nginx:conf_test()
        nginx:start()
        client = test.client()
      end)

      lazy_teardown(function()
        client:close()
        nginx:stop()
      end)

      it("returns " .. case.name .. " data from the request client IP", function()
        local addr = case.exp.addr
        client.headers.x_forwarded_for = addr
        local res, err = client:get("/ip/info")
        assert.is_nil(err)
        assert.same(200, res.status)
        assert.same("application/json", res.headers.content_type)
        assert.same(case.exp, res.json)
      end)

      it("returns " .. case.name .. " for an arbitrary IP", function()
        local addr = case.exp.addr
        local res, err = client:get("/ip/info/" .. addr)
        assert.is_nil(err)
        assert.same(200, res.status)
        assert.same("application/json", res.headers.content_type)
        assert.same(case.exp, res.json)
      end)

      pending("requires a trusted IP for specific lookups", function()
        local addr = case.exp.addr
        client.headers.x_forwarded_for = "1.2.3.4"
        local res, err = client:get("/ip/info/" .. addr)
        assert.is_nil(err)
        assert.same(403, res.status)
      end)
    end)
  end
end)
