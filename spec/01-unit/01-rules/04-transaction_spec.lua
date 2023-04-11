require "spec.testing"
local TRX = require "doorbell.rules.transaction"
local rules = require "doorbell.rules"
local manager = require "doorbell.rules.manager"
local const = require "doorbell.constants"


describe("doorbell.rules.transaction", function()
  local function new_rule(rule)
    return assert(rules.new(rule))
  end


  before_each(function()
    ngx.shared[const.shm.rules]:flush_all()
    ngx.shared[const.shm.locks]:flush_all()
    manager.reset()
  end)

  describe("[usage]", function()
    it("manages rule state", function()
      local trx = TRX.new()

      local rule = new_rule({
        source = "user",
        action = "allow",
        ua = "1",
      })

      trx:insert(rule)

      trx:insert(new_rule({
        source = "user",
        action = "allow",
        ua = "2",
      }))

      trx:insert(new_rule({
        source = "user",
        action = "allow",
        ua = "3",
      }))

      trx:update(rule.id, {
        ua = "1-updated",
      })

      trx:insert(new_rule({
        source = "user",
        action = "allow",
        ua = "4",
      }))

      trx:upsert(new_rule({
        source = "user",
        action = "deny",
        ua = "3",
      }))

      trx:delete_where({
        source = "user",
        action = "allow",
        ua = "4",
      })

      local ok, err = trx:commit()
      assert.is_nil(err)
      assert.truthy(ok)

      manager.reload()

      local list = manager.list()
      assert.same(3, #list)

      table.sort(list, function(a, b) return a.ua < b.ua end)

      assert.table_fields({
        source = "user",
        ua = "1-updated",
        action = "allow",
        expires = 0,
      }, list[1])

      assert.table_fields({
        source = "user",
        action = "allow",
        ua = "2",
        expires = 0,
      }, list[2])

      assert.table_fields({
        source = "user",
        action = "deny",
        ua = "3",
        expires = 0,
      }, list[3])

      trx = TRX.new()

      trx:insert(new_rule({
        source = "user",
        action = "allow",
        ua = "5",
      }))

      trx:upsert(new_rule({
        source = "user",
        action = "allow",
        ua = "2",
        ttl = 60,
      }))

      trx:delete_where({ ua = "1-updated" })

      ok, err = trx:commit()
      assert.is_nil(err)
      assert.truthy(ok)

      manager.reload()

      list = manager.list()
      assert.same(3, #list)

      table.sort(list, function(a, b) return a.ua < b.ua end)

      assert.table_fields({
        source = "user",
        ua = "2",
        action = "allow",
      }, list[1])
      assert.is_near(ngx.now() + 60, list[1].expires, 5)

      assert.table_fields({
        source = "user",
        action = "deny",
        ua = "3",
        expires = 0,
      }, list[2])

      assert.table_fields({
        source = "user",
        action = "allow",
        ua = "5",
        expires = 0,
      }, list[3])
    end)
  end)

  describe("new()", function()
    it("creates and returns a transaction", function()
      local trx, err = TRX.new()

      finally(function() trx:abort() end)

      assert.is_nil(err)
      assert.is_table(trx)
      assert.table_shape({
        actions = "table",
        rules   = "table",
        version = "number",
        lock    = "table",
      }, trx)
    end)
  end)

  describe("insert()", function()
    it("adds a rule", function()
      local trx = TRX.new()
      local rule = new_rule({
        action = "allow",
        source = "user",
        ua = "insert",
      })

      local ok, err = trx:insert(rule)
      assert.is_nil(err)
      assert.truthy(ok)

      ok, err = trx:commit()
      assert.is_nil(err)
      assert.truthy(ok)

      manager.update()
      local list = manager.list()
      assert.same(1, #list)
      assert.table_fields(rule, list[1])
    end)

    it("causes the transaction to fail if the rule already exists (prior transaction)", function()
      local rule = new_rule({
        action = "allow",
        source = "user",
        ua = "insert",
      })
      assert(manager.add(rule))

      local trx = TRX.new()
      rule = new_rule({
        action = "deny",
        source = "user",
        ua = "insert",
      })

      assert(trx:insert(rule))
      local ok, err = trx:commit()
      assert.equals("exists", err)
      assert.falsy(ok)
    end)

    it("causes the transaction to fail if the rule already exists (current transaction)", function()
      local trx = TRX.new()

      local rule = new_rule({
        action = "allow",
        source = "user",
        ua = "insert",
      })

      assert(trx:insert(rule))
      assert(trx:insert(rule))

      local ok, err = trx:commit()
      assert.equals("exists", err)
      assert.falsy(ok)
    end)

  end)

  describe("upsert()", function()
    it("adds a rule", function()
      local trx = TRX.new()
      local rule = new_rule({
        action = "allow",
        source = "user",
        ua = "insert",
      })

      local ok, err = trx:insert(rule)
      assert.is_nil(err)
      assert.truthy(ok)

      assert(trx:commit())

      manager.update()

      assert.same(rule, manager.get(rule.id))
    end)

    it("updates an existing rule (prior transaction)", function()
      local rule = new_rule({
        action = "allow",
        source = "user",
        ua = "upsert",
      })
      assert(manager.add(rule))

      local trx = TRX.new()

      rule.action = "deny"
      assert(trx:upsert(rule))

      local ok, err = trx:commit()
      assert.is_nil(err)
      assert.truthy(ok)

      manager.update()

      assert.same("deny", manager.get(rule.id).action)
    end)

    it("updates an existing rule (current transaction)", function()
      local trx = TRX.new()

      local rule = new_rule({
        action = "allow",
        source = "user",
        ua = "upsert",
      })

      assert(trx:insert(rule))

      local new = new_rule({
        action = "deny",
        source = "user",
        ua = "upsert",
      })

      assert(trx:upsert(new))
      assert(trx:commit())

      manager.update()
      assert.same(1, #manager.list())
      assert.same("deny", manager.get(rule.id).action)
    end)
  end)

  describe("update()", function()
    describe("(prior transaction)", function()
      it("updates an existing rule by id", function()
        local rule = manager.add({
          source = "user",
          action = "allow",
          ua = "update",
        })

        assert.same("update", manager.get(rule.id).ua)

        local trx = TRX.new()

        assert(trx:update(rule.id, { ua = "updated" }))
        assert(trx:commit())

        manager.update()
        assert.same("updated", manager.get(rule.id).ua)
      end)

      it("updates an existing rule by hash", function()
        local rule = manager.add({
          source = "user",
          action = "allow",
          ua = "update",
        })

        assert.same("allow", manager.get(rule.id).action)

        local trx = TRX.new()

        assert(trx:update(rule.hash, { ua = "updated" }))
        assert(trx:commit())

        manager.update()
        assert.same("updated", manager.get(rule.id).ua)
      end)
    end)
  end)

  describe("delete_all()", function()
    it("deletes all rules from the data store", function()
      for i = 1, 10 do
        assert(manager.add({
          source = "user",
          action = "allow",
          ua = "delete-all-" .. i
        }))
      end

      assert.same(10, #manager.list())

      local trx = TRX.new()
      assert(trx:delete_all())

      assert(trx:insert(new_rule({
        source = "user",
        action = "allow",
        ua = "delete-all-remaining",
      })))

      assert(trx:commit())

      manager.update()

      local list = manager.list()
      assert.same(1, #list)
      assert.same("delete-all-remaining", list[1].ua)
    end)

    it("also deletes all rules added to the transaction", function()
      for i = 1, 10 do
        assert(manager.add({
          source = "user",
          action = "allow",
          ua = "delete-all-" .. i
        }))
      end

      assert.same(10, #manager.list())

      local trx = TRX.new()

      for i = 11, 20 do
        assert(trx:insert(new_rule({
          source = "user",
          action = "allow",
          ua = "delete-all-" .. i
        })))
      end

      assert(trx:delete_all())

      assert(trx:insert(new_rule({
        source = "user",
        action = "allow",
        ua = "delete-all-remaining",
      })))

      assert(trx:commit())

      manager.update()

      local list = manager.list()
      assert.same(1, #list)
      assert.same("delete-all-remaining", list[1].ua)
    end)


  end)

  describe("delete_where()", function()
    it("deletes rules that match fields", function()
      local ua = "delete-where-test"
      local host = "delete-me.test"

      assert(manager.add({
        source = "user",
        action = "allow",
        ua = ua,
        host = "dont-delete-me.test",
      }))

      assert(manager.add({
        source = "user",
        action = "allow",
        ua = ua,
        host = host,
      }))

      assert(manager.add({
        source = "user",
        action = "allow",
        ua = ua,
      }))

      assert.same(3, #manager.list())

      local trx = TRX.new()

      assert(trx:insert(new_rule({
        source = "user",
        action = "allow",
        ua = ua,
        path = "/do-not-delete",
      })))

      assert(trx:delete_where({ ua = ua, host = host }))

      assert(trx:insert(new_rule({
        source = "user",
        action = "allow",
        ua = ua,
        path = "/also-do-not-delete",
      })))

      assert(trx:commit())

      manager.update()

      assert.same(4, #manager.list())
      for _, rule in ipairs(manager.list()) do
        assert.same(ua, rule.ua)
        assert.not_same(host, rule.host)
      end
    end)
  end)

  describe("commit()", function()
  end)

  describe("abort()", function()
  end)

end)
