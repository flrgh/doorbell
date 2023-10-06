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
end)
