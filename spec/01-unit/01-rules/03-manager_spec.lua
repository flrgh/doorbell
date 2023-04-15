local manager = require "doorbell.rules.manager"
local stats = require "doorbell.rules.stats"

local uuid       = require("resty.jit-uuid").generate_v4

local fmt = string.format

describe("doorbell.rules.manager", function()
  describe("get()", function()
    local rule

    lazy_setup(function()
      manager.reset()
      rule = manager.add({
        source = "user",
        action = "allow",
        addr   = "127.0.0.1",
      })
    end)

    it("fetches a rule by id", function()
      local got = manager.get(rule.id)
      assert.same(rule, got)
    end)

    it("fetches a rule by hash", function()
      local got = manager.get(rule.hash)
      assert.same(rule, got)
    end)

    pending("optionally includes stats", function()
      local got = manager.get(rule.hash)
      assert.is_nil(got.match_count)
      assert.is_nil(got.last_match)

      got = manager.get(rule.hash, true)
      assert.equals(0, got.match_count)
      assert.equals(0, got.last_match)
    end)

    it("returns nil, nil when a rule does not exist", function()
      local got, err = manager.get("nope")
      assert.is_nil(got)
      assert.is_nil(err)
    end)
  end)

  describe("add()", function()
    before_each(function()
      manager.reset()
    end)

    it("creates a new rule", function()
      local rule = manager.add({
        source = "user",
        action = "allow",
        addr   = "127.0.0.1",
      })

      assert.same(rule, manager.get(rule.id))
    end)

    it("returns an error if a rule with the same hash already exists", function()
      local rule = manager.add({
        source = "user",
        action = "allow",
        addr   = "127.0.0.1",
      })

      local new, err = manager.add({
        source = "user",
        action = "deny",
        addr   = "127.0.0.1"
      })

      assert.is_nil(new)
      assert.matches("exists", err)

      assert.same(rule, manager.get(rule.hash))
    end)
  end)

  describe("upsert()", function()
    before_each(function()
      manager.reset()
    end)

    it("creates a new rule", function()
      local rule = manager.add({
        source = "user",
        action = "allow",
        addr   = "127.0.0.1",
      })

      assert.same(rule, manager.get(rule.id))
    end)

    it("overwrites an existing rule", function()
      local rule = manager.add({
        source = "user",
        action = "allow",
        addr   = "127.0.0.1",
      })

      local new, err = manager.upsert({
        source = "user",
        action = "deny",
        addr   = "127.0.0.1"
      })

      assert.is_nil(err)
      assert.same(new, manager.get(rule.hash))
    end)
  end)

  describe("delete()", function()
    local rule
    before_each(function()
      manager.reset()
      rule = manager.add({
        source = "user",
        action = "allow",
        addr   = "127.0.0.1",
      })
    end)

    it("deletes a rule object", function()
      local ok, err = manager.delete(rule)
      assert.truthy(ok)
      assert.is_nil(err)

      local got
      got, err = manager.get(rule.hash)
      assert.is_nil(got)
      assert.is_nil(err)
    end)

    it("can delete a rule by hash", function()
      local ok, err = manager.delete(rule.hash)
      assert.truthy(ok)
      assert.is_nil(err)

      local got
      got, err = manager.get(rule.hash)
      assert.is_nil(got)
      assert.is_nil(err)
    end)

    it("can delete a rule by id", function()
      local ok, err = manager.delete(rule.id)
      assert.truthy(ok)
      assert.is_nil(err)

      local got
      got, err = manager.get(rule.hash)
      assert.is_nil(got)
      assert.is_nil(err)
    end)

    it("returns 'not found' if the rule does not exist", function()
      assert(manager.delete(rule))

      local ok, err = manager.delete(rule)
      assert.is_nil(ok)
      assert.matches("not found", err)

      ok, err = manager.delete(uuid())
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
          manager.add({
            source = "user",
            action = "allow",
            addr   = fmt("127.0.0.%s", i),
          })
        )
      end
    end)

    it("fetches all rules", function()
      local list = manager.list()
      table.sort(list, function(a, b) return a.addr < b.addr end)
      assert.same(rules, list)
    end)

    pending("optionally includes stats", function()
      stats.inc_match_count(rules[2])
      local stamp = ngx.now()
      stats.set_last_match(rules[3], stamp)

      local list = manager.list(true)
      table.sort(list, function(a, b) return a.addr < b.addr end)

      assert.equals(0, list[1].last_match)
      assert.equals(0, list[1].match_count)

      assert.equals(1, list[2].match_count)

      assert.equals(stamp, list[3].last_match)
    end)
  end)

  describe("match()", function()
    local rule
    local req

    before_each(function()
      manager.reset()
      rule = manager.add({
        source = "user",
        action = "allow",
        addr   = "127.0.0.1",
      })
      req = {
        addr   = "127.0.0.1",
        host   = "test",
        ua     = "test",
        method = "GET",
        path   = "/",
      }
    end)

    it("returns a matched rule for a request", function()
      local match = manager.match(req)
      assert.same(rule, match)
    end)

    it("returns nil when there is no match", function()
      req.addr = "10.0.0.1"
      local match = manager.match(req)
      assert.is_nil(match)
    end)

    it("caches the results of a positive match", function()
      local match, cached = manager.match(req)
      assert.same(rule, match)
      assert.falsy(cached)

      match, cached = manager.match(req)
      assert.same(rule, match)
      assert.truthy(cached)
    end)

    it("knows to clear the cache when rules are updated", function()
      local match, cached = manager.match(req)
      assert.same(rule, match)
      assert.falsy(cached)

      match, cached = manager.match(req)
      assert.same(rule, match)
      assert.truthy(cached)

      assert(manager.delete(rule))

      match, cached = manager.match(req)
      assert.is_nil(match)
      assert.falsy(cached)
    end)
  end)

  describe("reset()", function()
  end)

  describe("reload()", function()
  end)

  describe("save()", function()
  end)

  describe("version()", function()
  end)
end)
