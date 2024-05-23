local shm = require "doorbell.shm"

describe("doorbell.shm", function()
  describe("namespaces", function()
    before_each(function()
      shm.reset_shared()
    end)

    it("applies a prefix to all keys", function()
      local a = shm.with_namespace("a")
      local b = shm.with_namespace("b")

      a:set("my-key", 123)
      assert.is_nil(b:get("my-key"))

      b:set("my-key", 456)
      assert.equals(456, b:get("my-key"))
      assert.equals(123, a:get("my-key"))
    end)

    it("stores non-string, non-number values accurately", function()
      local ns = shm.with_namespace("test")
      ns:set("true", true)
      assert.is_true(ns:get("true"))

      ns:set("false", false)
      assert.is_false(ns:get("false"))

      ns:set("table", { a = 1, b = 2, c = { 1, 2, 3 } })
      assert.same({ a = 1, b = 2, c = { 1, 2, 3 } }, ns:get("table"))
    end)

    it("performs add(), get(), set(), delete()", function()
      local ns = shm.with_namespace("test")

      assert.truthy(ns:add("key", 123))
      assert.equals(123, ns:get("key"))

      local ok, err = ns:add("key", 456)
      assert.falsy(ok)
      assert.equals("exists", err)

      assert.equals(123, ns:get("key"))

      assert.truthy(ns:set("key", 456))
      assert.equals(456, ns:get("key"))

      ns:delete("key")

      assert.is_nil(ns:get("key"))
    end)

    it("performs incr()", function()
      local ns = shm.with_namespace("inc")
      assert.equals(1, ns:incr("a", 1, 0))
      assert.equals(2, ns:incr("a", 1, 0))
      assert.equals(3, ns:incr("a", 1))
      assert.equals(4, ns:incr("a"))

      local new, err = ns:incr("b")
      assert.is_nil(new)
      assert.equals("not found", err)

      new, err = ns:incr("b", 1)
      assert.is_nil(new)
      assert.equals("not found", err)

      new, err = ns:incr("b", 0, 0)
      assert.equals(0, new)
      assert.is_nil(err)

      assert(ns:set("c", 100))
      assert.equals(150, ns:incr("c", 50))

      assert(ns:set("not-a-number", "abc"))
      assert.has_error(function()
        ns:incr("not-a-number", 1, 0)
      end)
    end)

    it("performs list operations", function()
      local ns = shm.with_namespace("test")

      assert.equals(0, ns:llen("key"))
      assert.equals(1, ns:lpush("key", "a"))
      assert.equals(2, ns:lpush("key", "b"))
      assert.equals(3, ns:lpush("key", "c"))
      assert.equals(3, ns:llen("key"))

      assert.equals("c", ns:lpop("key"))
      assert.equals("b", ns:lpop("key"))
      assert.equals("a", ns:lpop("key"))
      assert.equals(0, ns:llen("key"))

      assert.equals(1, ns:rpush("key", "a"))
      assert.equals(2, ns:rpush("key", "b"))
      assert.equals(3, ns:rpush("key", "c"))
      assert.equals(3, ns:llen("key"))

      assert.equals("c", ns:rpop("key"))
      assert.equals("b", ns:rpop("key"))
      assert.equals("a", ns:rpop("key"))
      assert.equals(0, ns:llen("key"))

      assert.equals(1, ns:lpush("key", "a"))
      assert.equals("a", ns:rpop("key"))
      assert.equals(1, ns:rpush("key", "b"))
      assert.equals("b", ns:lpop("key"))

      for _, val in ipairs({
        "string",
        1234,
        true,
        false,
        { a = 1, b = 2 }
      }) do
        assert.equals(1, ns:lpush("key", val))
        assert.same(val, ns:rpop("key"))

        assert.equals(1, ns:rpush("key", val))
        assert.same(val, ns:lpop("key"))
      end

      assert(ns:add("not-a-list", 123))

      assert.has_error(function()
        ns:lpop("not-a-list")
      end)

      assert.has_error(function()
        ns:rpop("not-a-list")
      end)

      assert.has_error(function()
        ns:llen("not-a-list")
      end)

      assert.has_error(function()
        ns:lpush("not-a-list", 123)
      end)

      assert.has_error(function()
        ns:rpush("not-a-list", 123)
      end)
    end)

    it("throws for invalid value types", function()
      local ns = shm.with_namespace("err")

      local items = {
        ngx.null,
        function() end,
        "NIL",
      }

      for _, value in ipairs(items) do
        if value == "NIL" then
          value = nil
        end

        assert.has_error(function()
          ns:add("key", value)
        end)

        if value ~= nil then
          assert.has_error(function()
            ns:set("key", value)
          end)

          assert.has_error(function()
            ns:incr("key", value)
          end)
        end

        assert.has_error(function()
          ns:lpush("my-list", value)
        end)

        assert.has_error(function()
          ns:rpush("my-list", value)
        end)
      end
    end)

    it("throws if a duplicate namespace is created", function()
      shm.with_namespace("dupe")
      assert.has_error(function()
        shm.with_namespace("dupe")
      end)
    end)
  end)
end)
