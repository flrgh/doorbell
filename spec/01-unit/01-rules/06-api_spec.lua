local api = require "doorbell.rules.api"
local manager = require "doorbell.rules.manager"
local uuid = require("resty.jit-uuid").generate_v4

local fmt = string.format

describe("rules.api", function()
  describe("get()", function()
    local rule

    lazy_setup(function()
      manager.reset()
      rule = api.insert({
        source = "user",
        action = "allow",
        addr   = "127.0.0.1",
      })
    end)

    it("fetches a rule by id", function()
      local got = api.get(rule.id)
      assert.same(rule, got)
    end)

    it("fetches a rule by hash", function()
      local got = api.get(rule.hash)
      assert.same(rule, got)
    end)

    it("returns nil, nil when a rule does not exist", function()
      local got, err = api.get("nope")
      assert.is_nil(got)
      assert.is_nil(err)
    end)
  end)

  describe("insert()", function()
    before_each(function()
      manager.reset()
    end)

    it("creates a new rule", function()
      local rule = api.insert({
        source = "user",
        action = "allow",
        addr   = "127.0.0.1",
      })

      assert.same(rule, api.get(rule.id))
    end)

    it("returns an error if a rule with the same hash already exists", function()
      local rule = api.insert({
        source = "user",
        action = "allow",
        addr   = "127.0.0.1",
      })

      local new, err = api.insert({
        source = "user",
        action = "deny",
        addr   = "127.0.0.1"
      })

      assert.is_nil(new)
      assert.matches("duplicate rule", err)

      assert.same(rule, api.get(rule.hash))
    end)
  end)

  describe("upsert()", function()
    before_each(function()
      manager.reset()
    end)

    it("creates a new rule", function()
      local rule = api.insert({
        source = "user",
        action = "allow",
        addr   = "127.0.0.1",
      })

      assert.same(rule, api.get(rule.id))
    end)

    it("overwrites an existing rule", function()
      local rule = api.insert({
        source = "user",
        action = "allow",
        addr   = "127.0.0.1",
      })

      local new, err = api.upsert({
        source = "user",
        action = "deny",
        addr   = "127.0.0.1"
      })

      assert.is_nil(err)
      assert.same(new, api.get(rule.hash))
    end)
  end)

  describe("patch()", function()
    before_each(function()
      manager.reset()
    end)

    it("updates an existing rule", function()
      local rule = api.insert({
        source = "user",
        action = "allow",
        addr   = "127.0.0.1",
      })

      local patched, err = api.patch(rule.id, { addr = "127.0.0.2" })
      assert.is_nil(err)
      assert.equals("127.0.0.2", patched.addr)

      rule = api.get(patched.id)
      assert.equals("127.0.0.2", rule.addr)
    end)

    it("updates the rule hash when conditions are changed", function()
      local rule = api.insert({
        source = "user",
        action = "allow",
        addr   = "127.0.0.1",
      })

      local hash = rule.hash

      local patched, err = api.patch(rule.id, { addr = "127.0.0.2" })
      assert.is_nil(err)
      assert.equals("127.0.0.2", patched.addr)
      assert.not_equals(hash, patched.hash)

      assert.is_nil(api.get(hash))

      rule = api.get(patched.id)
      assert.equals(patched.hash, rule.hash)
    end)

    it("merges metadata updates", function()
      local rule = api.insert({
        source = "user",
        action = "allow",
        addr   = "127.0.0.1",
        meta   = {
          foo = "UNCHANGED",
          bar = "update me",
          baz = "remove me",
        },
      })

      local patched, err = api.patch(rule.id, { meta = {
        foo = nil,       -- leave unchanged
        bar = "CHANGED", -- update
        baz = ngx.null,  -- explicitly remove,
        new = "NEW",     -- insert
      }})

      assert.is_nil(err)

      assert.same({
        foo = "UNCHANGED",
        bar = "CHANGED",
        baz = nil,
        new = "NEW",
      }, patched.meta)
    end)

    it("can update ttl/expires", function()
      local rule = api.insert({
        source = "user",
        action = "allow",
        addr   = "127.0.0.1",
      })

      local patched, err = api.patch(rule.id, { ttl = 60 })
      assert.is_nil(err)
      assert.not_nil(patched.expires)
    end)
  end)

  describe("delete()", function()
    local rule
    before_each(function()
      manager.reset()
      rule = api.insert({
        source = "user",
        action = "allow",
        addr   = "127.0.0.1",
      })
    end)

    it("deletes a rule object", function()
      local ok, err = api.delete(rule)
      assert.truthy(ok)
      assert.is_nil(err)

      local got
      got, err = api.get(rule.hash)
      assert.is_nil(got)
      assert.is_nil(err)
    end)

    it("can delete a rule by hash", function()
      local ok, err = api.delete(rule.hash)
      assert.truthy(ok)
      assert.is_nil(err)

      local got
      got, err = api.get(rule.hash)
      assert.is_nil(got)
      assert.is_nil(err)
    end)

    it("can delete a rule by id", function()
      local ok, err = api.delete(rule.id)
      assert.truthy(ok)
      assert.is_nil(err)

      local got
      got, err = api.get(rule.hash)
      assert.is_nil(got)
      assert.is_nil(err)
    end)

    it("returns 'not found' if the rule does not exist", function()
      assert(api.delete(rule))

      local ok, err = api.delete(rule)
      assert.is_nil(ok)
      assert.matches("not found", err)

      ok, err = api.delete(uuid())
      assert.is_nil(ok)
      assert.matches("not found", err)
    end)
  end)

  describe("list()", function()
    local rules = {}

    lazy_setup(function()
      manager.reset()
      for i = 1, 5 do
        rules[i] = assert(
          api.insert({
            source = "user",
            action = "allow",
            addr   = fmt("127.0.0.%s", i),
          })
        )
      end
    end)

    it("fetches all rules", function()
      local list = api.list()
      table.sort(list, function(a, b) return a.addr < b.addr end)
      assert.same(rules, list)
    end)
  end)

  describe("get_by_meta()", function()
    local rule
    before_each(function()
      manager.reset()
      rule = api.insert({
        source = "user",
        action = "allow",
        addr   = "127.0.0.1",
        meta   = { foo = "bar", alt = "123" },
      })
    end)

    it("fetches a rule by metadata key", function()
      local found = api.get_by_meta("foo")
      assert.same(rule, found)

      found = api.get_by_meta("nope!")
      assert.is_nil(found)
    end)

    it("fetches a rule by metadata key and value", function()
      local found = api.get_by_meta("foo", "bar")
      assert.same(rule, found)

      found = api.get_by_meta("foo", "nope!")
      assert.is_nil(found)
    end)

    it("fetches a rule by multiple metadata key->value pairs", function()
      local found = api.get_by_meta({ foo = "bar" })
      assert.same(rule, found)

      found = api.get_by_meta({ alt = "123" })
      assert.same(rule, found)

      found = api.get_by_meta({ foo = "bar", alt = "123" })
      assert.same(rule, found)

      found = api.get_by_meta({ nope = "nope!" })
      assert.is_nil(found)

      found = api.get_by_meta({ foo = "bar", nope = "nope!" })
      assert.is_nil(found)
    end)

    -- I don't remember if/how we sort the whole rule collection, so this could easily break
    it("returns the first matched rule if there are multiple", function()
      local other = assert(api.insert({
        source = "user",
        action = "allow",
        addr   = "127.0.0.2",
        meta   = { foo = "bar", alt = "456", other = "abc" },
      }))

      local found = api.get_by_meta("foo")
      assert.same(rule, found)

      found = api.get_by_meta("foo", "bar")
      assert.same(rule, found)

      found = api.get_by_meta("alt")
      assert.same(rule, found)

      found = api.get_by_meta("alt", "456")
      assert.same(other, found)

      found = api.get_by_meta("other")
      assert.same(other, found)
    end)

    it("throws for invalid key inputs", function()
      assert.has_error(function()
        api.get_by_meta()
      end)

      assert.has_error(function()
        api.get_by_meta(true)
      end)

      assert.has_error(function()
        api.get_by_meta({})
      end)

      assert.has_error(function()
        api.get_by_meta(ngx.null)
      end)
    end)

    it("throws for invalid value inputs", function()
      assert.has_error(function()
        api.get_by_meta("key", true)
      end)

      assert.has_error(function()
        api.get_by_meta("key", {})
      end)

      assert.has_error(function()
        api.get_by_meta("key", ngx.null)
      end)
    end)
  end)

  describe("get_all_by_meta()", function()
    local rule_a, rule_b

    before_each(function()
      manager.reset()
      rule_a = api.insert({
        source = "user",
        action = "allow",
        addr   = "127.0.0.1",
        meta   = {
          a_only = "a",
          all = "all",
        }
      })

      rule_b = api.insert({
        source = "user",
        action = "allow",
        addr   = "127.0.0.1",
        meta   = {
          b_only = "b",
          all = "all",
        }
      })
    end)

    it("fetches rules by metadata key", function()
      local found = api.get_all_by_meta("all")
      assert.same({ rule_a, rule_b }, found)

      found = api.get_all_by_meta("a_only")
      assert.same({ rule_a }, found)

      found = api.get_all_by_meta("b_only")
      assert.same({ rule_b }, found)

      found = api.get_all_by_meta("nope!")
      assert.same({}, found)
    end)

    it("fetches rules by metadata key and value", function()
      local found = api.get_all_by_meta("all", "all")
      assert.same({ rule_a, rule_b }, found)

      found = api.get_all_by_meta("a_only", "a")
      assert.same({ rule_a }, found)

      found = api.get_all_by_meta("a_only", "nope!")
      assert.same({}, found)

      found = api.get_all_by_meta("b_only", "b")
      assert.same({ rule_b }, found)

      found = api.get_all_by_meta("b_only", "nope!")
      assert.same({}, found)

      found = api.get_all_by_meta("all", "nope!")
      assert.same({}, found)
    end)

    it("fetches rules by multiple metadata key->value pairs", function()
      local found = api.get_all_by_meta({ all = "all" })
      assert.same({ rule_a, rule_b }, found)

      found = api.get_all_by_meta({ all = "all", a_only = "a" })
      assert.same({ rule_a }, found)

      found = api.get_all_by_meta({ a_only = "a" })
      assert.same({ rule_a }, found)

      found = api.get_all_by_meta({ b_only = "b" })
      assert.same({ rule_b }, found)

      found = api.get_all_by_meta({ all = "all", none = "nope!" })
      assert.same({}, found)
    end)

    it("throws for invalid key inputs", function()
      assert.has_error(function()
        api.get_all_by_meta()
      end)

      assert.has_error(function()
        api.get_all_by_meta(true)
      end)

      assert.has_error(function()
        api.get_all_by_meta({})
      end)

      assert.has_error(function()
        api.get_all_by_meta(ngx.null)
      end)
    end)

    it("throws for invalid value inputs", function()
      assert.has_error(function()
        api.get_all_by_meta("key", true)
      end)

      assert.has_error(function()
        api.get_all_by_meta("key", {})
      end)

      assert.has_error(function()
        api.get_all_by_meta("key", ngx.null)
      end)
    end)
  end)
end)
