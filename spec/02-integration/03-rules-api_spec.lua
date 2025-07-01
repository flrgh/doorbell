local test = require "spec.testing"
local const = require "doorbell.constants"
local util = require "doorbell.util"

describe("rules API", function()
  local client
  local nginx
  local res, err

  lazy_setup(function()
    local conf = test.config()
    conf.notify = nil

    nginx = test.nginx(conf)
    nginx:conf_test()
    nginx:start()

    client = test.client()
  end)

  lazy_teardown(function()
    if res and type(res.status) == "number" and res.status >= 500 then
      print(string.rep("-", 120))
      print(nginx:read_error_log())
      print(string.rep("-", 120))
    end

    if client then
      client:close()
    end
    nginx:stop()
  end)

  describe("/rules", function()
    local rules = {}

    lazy_setup(function()
      for i = 1, 10 do
        res = assert(client:post("/rules", {
          json = {
            action = "allow",
            host = "api.test",
            path = "/api/" .. i,
            ua = test.util.uuid(),
          }
        }))
        assert.same(201, res.status)

        rules[i] = res.json
      end
    end)

    lazy_teardown(function()
      for _, rule in ipairs(rules) do
        assert(client:delete("/rules/" .. rule.id))
      end
    end)

    before_each(function()
      client:reset()
    end)

    describe("OPTIONS", function()
      it("handles CORS pre-flight requests", function()
        client:options("/rules")
        assert.is_nil(client.err)
        assert.same(200, client.response.status)

        assert.response(client.response).header("access-control-allow-credentials")
        assert.response(client.response).header("access-control-allow-headers")
        assert.response(client.response).header("access-control-allow-methods")
        assert.response(client.response).header("access-control-allow-origin")
        assert.response(client.response).header("access-control-max-age")

        assert.same("text/plain", client.response.headers["content-type"])
        assert.same("GET, POST, OPTIONS",
                    client.response.headers["access-control-allow-methods"])
      end)
    end)

    describe("GET", function()
      it("returns all current rules", function()
        res, err = client:get("/rules")
        assert.is_nil(err)
        assert.same(200, res.status)

        assert.is_table(res.json)
        assert.is_table(res.json.data)
        assert.same(rules, res.json.data)
      end)
    end)

    describe("POST", function()
      it("creates a new rule", function()
        res, err = client:post("/rules", {
          json = {
            action = "allow",
            host = test.random_string(8) .. ".post.test",
          }
        })

        assert.is_nil(err)
        assert.same(201, res.status, res.json and res.json.error)
        assert.is_table(res.json)
        assert.same("allow", res.json.action)
        assert.matches("post.test", res.json.host)
        assert.same(const.sources.api, res.json.source)
      end)

      it("permits duration strings for .ttl", function()
        local ttl = assert(util.duration("1d12h5m"))

        res, err = client:post("/rules", {
          json = {
            action = "allow",
            host = test.random_string(8) .. ".post.test",
            ttl = "1d12h5m",
          }
        })

        assert.is_nil(err)
        assert.same(201, res.status, res.json and res.json.error)
        assert.is_table(res.json)
        assert.same("allow", res.json.action)
        assert.matches("post.test", res.json.host)
        assert.same(const.sources.api, res.json.source)
        assert.near(ngx.now() + ttl, res.json.expires, 10)
      end)

      it("returns 400 on invalid input", function()
        res, err = client:post("/rules", {
          json = {
            action = "nope",
            host = 123,
          }
        })

        assert.is_nil(err)
        assert.same(400, res.status)
        assert.is_table(res.json)
        assert.is_string(res.json.error)
      end)

      it("returns 400 on invalid input for shorthand fields (ttl)", function()
        local inputs = {
          { "nope" },
          -1,
          "",
          "    ",
          "-1",
          "3y",
          "1h2d",
          "0",
          0,
        }

        for _, ttl in ipairs(inputs) do
          res, err = client:post("/rules", {
            json = {
              action = "allow",
              host = "invalid.ttl.test",
              ttl  = ttl,
            }
          })

          local label = string.format("ttl %q", ttl)

          assert.is_nil(err, label)
          assert.same(400, res.status, label)
          assert.is_table(res.json, label)
          assert.is_string(res.json.error, label)
          assert(res.json.error:match("property ttl validation failed") or
                 res.json.error:match("validation failed"),
                 label)
        end
      end)

      it("returns a 400 if a rule with matching conditions already exists", function()
        res, err = client:post("/rules", {
          json = {
            action = "allow",
            host = "duplicate.test",
          }
        })

        assert.is_nil(err)
        assert.same(201, res.status)

        res, err = client:post("/rules", {
          json = {
            action = "deny",
            host = "duplicate.test",
          }
        })

        assert.is_nil(err)
        assert.same(400, res.status)
        assert.matches("duplicate rule", res.json.error)
        assert.is_table(res.json.conflict)
      end)

      it("returns a 400 if a rule by the same ID already exists", function()
        local id = util.uuid()

        res, err = client:post("/rules", {
          json = {
            id     = id,
            action = "allow",
            host   = "duplicate.id.1",
          }
        })

        assert.is_nil(err)
        assert.same(201, res.status)
        assert.same(id, res.json.id)

        res, err = client:post("/rules", {
          json = {
            id     = id,
            action = "deny",
            host   = "duplicate.id.2",
          }
        })

        assert.is_nil(err)
        assert.same(400, res.status)
        assert.matches("duplicate rule", res.json.error)
        assert.is_table(res.json.conflict)
      end)
    end)

    it("supports application/x-www-form-urlencoded", function()
      local c = 0

      local function seq()
        c = c + 1
        return tostring(c)
      end

      local CASES = {
        {
          label = "truthy (OK)",
          input = {
            action    = "allow",
            ua        = "form-test " .. seq(),
            terminate = "true",
          },
          status = 201,
          err = nil,
        },

        {
          label = "truthy (ERROR)",
          input = {
            action    = "allow",
            ua        = "form-test " .. seq(),
            terminate = "don't coerce me, bro",
          },
          status = 400,
          err = "property terminate validation failed",
        },


        {
          label = "falsy (OK)",
          input = {
            action    = "allow",
            ua        = "form-test " .. seq(),
            terminate = "0",
          },
          status = 201,
        },

        {
          label = "falsy (ERROR)",
          input = {
            action    = "allow",
            ua        = "form-test " .. seq(),
            terminate = "naaaaah",
          },
          status = 400,
          err = "property terminate validation failed",
        },


        {
          label = "tonumber, integer (OK)",
          input = {
            action    = "allow",
            ua        = "form-test " .. seq(),
            asn       = "123",
          },
          status = 201,
        },

        {
          label = "tonumber, integer (ERROR)",
          input = {
            action    = "allow",
            ua        = "form-test " .. seq(),
            asn       = "123.99",
          },
          status = 400,
          err = "property asn validation failed",
        },

        {
          label = "tostring (OK)",
          input = {
            action    = "allow",
            ua        = "form-test " .. seq(),
            org       = 1234,
          },
          status = 201,
        },

        {
          label = "tostring (ERROR)",
          input = {
            action    = true,
            ua        = "form-test " .. seq(),
          },
          status = 400,
          err = "property action validation failed",
        },


      }

      for _, case in ipairs(CASES) do
        client:post("/rules", {
          post = case.input,
        })

        assert.is_nil(client.err, case.label)
        assert.same(case.status, client.response.status, case.label)

        if case.status == 400 and case.err then
          assert.is_table(client.response.json)
          assert.is_string(client.response.json.error)
          assert.matches(case.err, client.response.json.error, nil, true)
        end
      end
    end)
  end)

  describe("/rules/:rule", function()
    describe("GET", function()
      local rule

      lazy_setup(function()
        res = assert(client:post("/rules", {
          json = {
            action = "allow",
            host = "api.test",
            path = "/GET/" .. test.util.uuid(),
          }
        }))

        assert.same(201, res.status)
        rule = assert.is_table(res.json)
      end)

      lazy_teardown(function()
        assert(client:delete("/rule/" .. rule.id))
      end)

      it("fetches a rule by hash", function()
        res = assert(client:get("/rules/" .. rule.hash))
        assert.same(200, res.status)
        assert.is_table(res.json)
        assert.same(rule, res.json)
      end)

      it("fetches a rule by id", function()
        res = assert(client:get("/rules/" .. rule.id))
        assert.same(200, res.status)
        assert.is_table(res.json)
        assert.same(rule, res.json)
      end)

      it("returns 404 for rules that don't exist", function()
        res = assert(client:get("/rules/" .. test.util.uuid()))
        assert.same(404, res.status)
        assert.is_table(res.json)
        assert.same({ error = "rule not found" }, res.json)
      end)
    end)

    describe("PATCH", function()
      local rule

      before_each(function()
        res = assert(client:post("/rules", {
          json = {
            action = "allow",
            host = "api.test",
            path = "/PATCH/" .. test.util.uuid(),
          }
        }))

        assert.same(201, res.status)
        rule = assert.is_table(res.json)
      end)

      after_each(function()
        assert(client:delete("/rule/" .. rule.id))
      end)

      local types = {
        json = "json",
        form = "post",
      }

      for typ, param in pairs(types) do

      it("updates a rule in place (" .. typ .. ")", function()
        res = assert(client:patch("/rules/" .. rule.id, {
          [param] = {
            ua = "patched!",
          }
        }))
        assert.same(200, res.status)
        assert.same("patched!", res.json.ua)

        res = assert(client:get("/rules/" .. rule.id))
        assert.same(200, res.status)
        assert.same("patched!", res.json.ua)
      end)

      end
    end)

    describe("DELETE", function()
      local rule

      lazy_setup(function()
        res = assert(client:post("/rules", {
          json = {
            action = "allow",
            host = "api.test",
            path = "/DELETE/" .. test.util.uuid(),
          }
        }))

        assert.same(201, res.status)
        rule = assert.is_table(res.json)
      end)

      it("deletes a rule", function()
        res, err = client:delete("/rules/" .. rule.id)
        assert.is_nil(err)
        assert.same(204, res.status)

        res = client:get("/rules/" .. rule.id)
        assert.same(404, res.status)
      end)
    end)
  end)
end)
