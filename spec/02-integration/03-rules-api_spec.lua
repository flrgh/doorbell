local test = require "spec.testing"
local join = require("spec.testing.fs").join
local const = require "doorbell.constants"
local util = require "doorbell.util"

describe("rules API", function()
  local prefix = os.getenv("DOORBELL_PREFIX") or join(test.ROOT_DIR, "test")

  local client
  local nginx
  local res, err

  lazy_setup(function()
    local conf = test.config(prefix)
    conf.notify = nil

    nginx = test.nginx(prefix, conf)
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
            host = "post.test",
          }
        })

        assert.is_nil(err)
        assert.same(201, res.status)
        assert.is_table(res.json)
        assert.same("allow", res.json.action)
        assert.same("post.test", res.json.host)
        assert.same(const.sources.api, res.json.source)
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
        res, err = client:post("/rules", {
          json = {
            action = "allow",
            host = "invalid.ttl.test",
            ttl  = { "nope" },
          }
        })

        assert.is_nil(err)
        assert.same(400, res.status)
        assert.is_table(res.json)
        assert.is_string(res.json.error)
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
        assert.same({ error = "exists" }, res.json)
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
        assert.same({ error = "exists" }, res.json)
      end)
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

      lazy_setup(function()
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

      lazy_teardown(function()
        assert(client:delete("/rule/" .. rule.id))
      end)

      it("updates a rule in place", function()
        res = assert(client:patch("/rules/" .. rule.id, {
          json = {
            ua = "patched!",
          }
        }))
        assert.same(200, res.status)
        assert.same("patched!", res.json.ua)

        res = assert(client:get("/rules/" .. rule.id))
        assert.same(200, res.status)
        assert.same("patched!", res.json.ua)
      end)
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
