local shm = require "doorbell.rules.shm"
local test = require "spec.testing"
local rules = require "doorbell.rules"

local function call(fn, ...)
  local args = { ... }
  return function()
    return fn(unpack(args))
  end
end

describe("doorbell.rules.shm", function()
  local SHM = shm.SHM

  lazy_setup(shm.reset)
  lazy_teardown(shm.reset)
  before_each(shm.reset)
  after_each(shm.reset)

  describe("get_current_version()", function()
    it("returns 0 when shm is empty", function()
      assert.equals(0, shm.get_current_version())
    end)
  end)

  describe("get_latest_version()", function()
    it("returns nil when shm is empty", function()
      assert.is_nil(shm.get_latest_version())
    end)
  end)

  describe("get()", function()
    it("returns an empty table when shm is empty", function()
      assert.same({}, shm.get())
    end)

    it("returns the current data set", function()
      local rule = assert(rules.new({
        action = "allow",
        ua     = "shm test",
        source = "user",
      }))

      shm.set({ rule }, shm.allocate_new_version())
      assert.same({}, shm.get())
      shm.update_current_version()
      assert.same({ rule }, shm.get())
    end)
  end)

  describe("set()", function()
    it("validates its input types", function()
      assert.has_error(call(shm.set, nil, nil))
      assert.has_error(call(shm.set, 1, nil))
      assert.has_error(call(shm.set, true, nil))
      assert.has_error(call(shm.set, "", nil))
      assert.has_error(call(shm.set, {}, nil))
      assert.has_error(call(shm.set, {}, ""))
      assert.has_error(call(shm.set, {}, {}))
      assert.has_error(call(shm.set, {}, true))
    end)

    it("throws an error if no new version has been allocated", function()
      assert.has_error(call(shm.set, {}, 1))
    end)

    it("throws an error if the new version is the same as the old", function()
      local v = shm.allocate_new_version()
      shm.set({}, v)
      assert.equals(v, shm.update_current_version())
      assert.has_error(call(shm.set, {}, v))
    end)

    it("throws an error if the new version is out of range", function()
      local v = shm.allocate_new_version()
      shm.set({}, v)
      assert.has_error(call(shm.set, {}, v + 1))
    end)

    it("does not allow the same version to be written to twice", function()
      local v = shm.allocate_new_version()
      shm.set({}, v)
      assert.has_error(call(shm.set, {}, v))
    end)

  end)

  describe("allocate_new_version()", function()
    it("returns 1 when shm is empty", function()
      assert.equals(1, shm.allocate_new_version())
    end)

    it("increments the latest version", function()
      shm.allocate_new_version()
      shm.allocate_new_version()
      shm.allocate_new_version()
      assert.equals(3, shm.get_latest_version())
    end)

    it("stores a pending placeholder at the allocated version", function()
      local v = shm.allocate_new_version()
      assert.equals(shm.PENDING, SHM:get(v))
    end)

    it("sets a TTL on pending versions", function()
      local saved = shm.PENDING_TTL
      finally(function() shm.PENDING_TTL = saved end)
      local ttl = 0.1
      shm.PENDING_TTL = ttl

      local v = shm.allocate_new_version()
      assert.equals(shm.PENDING, shm.SHM:get(v))

      test.await.truthy(function()
        return shm.SHM:get(v) == nil
      end, ttl * 10, ttl / 2)
    end)
  end)

  describe("update_current_version()", function()
    it("returns 0 when shm is empty", function()
      assert.equals(0, shm.update_current_version())
    end)

    it("updates the current version after a new one is created and stored", function()
      shm.set({}, shm.allocate_new_version())
      shm.set({}, shm.allocate_new_version())
      shm.set({}, shm.allocate_new_version())
      assert.equals(3, shm.update_current_version())
      assert.equals(3, shm.get_current_version())
    end)

    it("stops incrementing at the first pending version marker", function()
      shm.set({}, shm.allocate_new_version())
      shm.set({}, shm.allocate_new_version())
      shm.set({}, shm.allocate_new_version())
      assert.equals(3, shm.get_latest_version())

      shm.allocate_new_version()
      shm.allocate_new_version()
      shm.allocate_new_version()

      assert.equals(6, shm.get_latest_version())

      assert.equals(3, shm.update_current_version())
      assert.equals(3, shm.get_current_version())
    end)

    it("skips expired pending versions", function()
      local saved = shm.PENDING_TTL
      finally(function() shm.PENDING_TTL = saved end)
      local ttl = 0.1
      shm.PENDING_TTL = ttl

      local first = assert(rules.new({
        action = "allow",
        source = "api",
        ua     = "1",
      }))

      shm.set({ first }, shm.allocate_new_version())
      local last_updated = shm.update_current_version()

      local second = assert(rules.new({
        action = "allow",
        source = "api",
        ua     = "2",
      }))

      shm.allocate_new_version()
      shm.allocate_new_version()
      shm.set({ second }, shm.allocate_new_version())

      shm.allocate_new_version()
      shm.allocate_new_version()
      shm.allocate_new_version()

      local third = assert(rules.new({
        action = "allow",
        source = "api",
        ua     = "3",
      }))

      local latest = shm.allocate_new_version()
      shm.set({ third }, latest)

      assert.equals(last_updated, shm.get_current_version())
      assert.same({ first }, shm.get())

      test.await.truthy(function()
        return shm.update_current_version() == latest
      end, ttl * 2, ttl / 10)

      assert.same({ third }, shm.get())
    end)

    it("never increments beyond the highest valid version", function()
      local version = shm.get_current_version()
      assert.equals(version, shm.update_current_version())

      local new = shm.allocate_new_version()
      assert.equals(version, shm.update_current_version())

      shm.cancel_pending_version(new)
      assert.equals(version, shm.update_current_version())
    end)
  end)

  describe("cancel_pending_version()", function()
    it("removes a previously allocated pending version", function()
      assert(shm.set({}, shm.allocate_new_version()))
      assert(shm.update_current_version())

      local current = shm.get_current_version()

      local new = shm.allocate_new_version()
      assert.is_true(new > current)
      assert.equals(current, shm.get_current_version())
      assert.equals(new, shm.get_latest_version())

      local newer = shm.allocate_new_version()
      assert.is_true(newer > new)
      assert.equals(current, shm.get_current_version())
      assert.equals(newer, shm.get_latest_version())

      local newest = shm.allocate_new_version()
      assert.is_true(newest > newer)
      assert.equals(current, shm.get_current_version())
      assert.equals(newest, shm.get_latest_version())

      assert(shm.set({}, newest))

      assert.equals(current, shm.update_current_version())

      shm.cancel_pending_version(new)
      assert.equals(current, shm.update_current_version())
      assert.equals(current, shm.get_current_version())

      shm.cancel_pending_version(newer)
      assert.equals(newest, shm.update_current_version())
      assert.equals(newest, shm.get_current_version())
    end)
  end)
end)
