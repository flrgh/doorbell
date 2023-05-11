local test = require "spec.testing"

describe("IP API", function()
  local conf

  ---@type spec.testing.nginx
  local nginx

  ---@type spec.testing.client
  local client

  describe("/ip/addr", function()
    lazy_setup(function()
      conf = test.config()
      conf.trusted = { "127.0.0.0/8", "::1"}
      nginx = test.nginx(conf)
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

    it("returns CORS headers", function()
      local res, err = client:get("/ip/addr")
      assert.is_nil(err)
      assert.same(200, res.status)

      assert.response(res).header("access-control-allow-credentials")
      assert.response(res).header("access-control-allow-headers")
      assert.response(res).header("access-control-allow-origin")
      assert.response(res).header("access-control-max-age")
    end)

    it("handles CORS pre-flight OPTIONS requests", function()
      local res, err = client:options("/ip/addr")
      assert.is_nil(err)
      assert.same(200, res.status)

      assert.response(res).header("access-control-allow-credentials")
      assert.response(res).header("access-control-allow-headers")
      assert.response(res).header("access-control-allow-methods")
      assert.response(res).header("access-control-allow-origin")
      assert.response(res).header("access-control-max-age")
    end)

    it("reacts to the Accept header", function()
      local cases = {
        {
          title  = "text/plain is the default",
          accept = nil,
          expect = "plain"
        },

        {
          title  = "JSON is available",
          accept = "application/json",
          expect = "json",
        },

        {
          title  = "JSON over plain",
          accept = "application/json, text/plain",
          expect = "json",
        },

        {
          title  = "plain over JSON",
          accept = "text/plain, application/json",
          expect = "plain",
        },

        {
          title  = "wildcard subtype JSON",
          accept = "application/*",
          expect = "json",
        },

        {
          title  = "weights",
          accept = "application/json;q=0.9, text/plain",
          expect = "plain",
        },

        {
          title  = "with no matching types",
          accept = "foo/bar, baz/bat",
          expect = "plain",
        },
      }

      local res, err, content_type

      for _, case in ipairs(cases) do
        local desc = string.format("%s (Accept: %q => %s)", case.title, case.accept, case.expect)

        client.headers.accept = case.accept
        res, err = client:get("/ip/addr")
        assert.is_nil(err)
        assert.same(200, res.status)

        content_type = assert.response(res).header("content-type")
        if case.expect == "json" then
          assert.same("application/json", content_type, desc)
          assert.is_table(res.json)
          assert.is_string(res.json.data)

        else
          assert(case.expect == "plain")

          assert.same("text/plain", content_type, desc)
          assert.is_string(res.body)
        end
      end
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
      city_db = test.constants.GEOIP_CITY_DB,
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
      country_db = test.constants.GEOIP_COUNTRY_DB,
      exp = {
        addr           = "216.160.83.56",
        continent      = "North America",
        continent_code = "NA",
        country        = "United States",
        country_code   = "US",
      }
    },
    {
      name = "IPv4 ASN",
      asn_db = test.constants.GEOIP_ASN_DB,
      exp = {
        addr = "220.1.2.3",
        asn  = 17676,
        org  = "Softbank BB Corp.",
      }
    },
  }

  for _, case in ipairs(GEOIP_CASES) do
    describe("/ip/info", function()

      lazy_setup(function()
        conf = test.config()
        conf.trusted = { "127.0.0.0/8", "::1"}
        conf.geoip_city_db = case.city_db
        conf.geoip_country_db = case.country_db
        conf.geoip_asn_db = case.asn_db
        nginx = test.nginx(conf)
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

  describe("/ip/info/:addr [errors]", function()
    lazy_setup(function()
      conf = test.config()
      conf.trusted = { "127.0.0.0/8", "::1"}
      conf.geoip_city_db = test.constants.GEOIP_CITY_DB
      nginx = test.nginx(conf)
      nginx:conf_test()
      nginx:start()
      client = test.client()
    end)

    lazy_teardown(function()
      client:close()
      nginx:stop()
    end)

    it("returns 404 if no IP info is found", function()
      local res, err = client:get("/ip/info/1.2.3.4")
      assert.is_nil(err)
      assert.same(404, res.status)
      assert.same("application/json", res.headers.content_type)
      assert.same({ message = "no ip info found" }, res.json)
    end)

    it("returns 400 for invalid input", function()
      local res, err = client:get("/ip/info/not-an-ip")
      assert.is_nil(err)
      assert.same(400, res.status)
      assert.same("application/json", res.headers.content_type)
      assert.same({ message = "invalid IP address" }, res.json)
    end)

  end)
end)
