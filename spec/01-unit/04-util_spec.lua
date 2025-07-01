local util = require "doorbell.util"
local cjson = require "cjson"
local lfs = require "lfs"

describe("doorbell.util", function()
  describe("current_time()", function()
    it("returns a table of integers", function()
      local t = util.current_time()
      assert.is_table(t)
      assert.is_number(t.year)
      assert.is_number(t.month)
      assert.is_number(t.day)
      assert.is_number(t.hour)
      assert.is_number(t.minute)
      assert.is_number(t.second)
    end)

    it("can return a single component", function()
      assert.is_number(util.current_time("year"))
      assert.is_number(util.current_time("month"))
      assert.is_number(util.current_time("day"))
      assert.is_number(util.current_time("hour"))
      assert.is_number(util.current_time("minute"))
      assert.is_number(util.current_time("second"))
    end)

    it("throws on invalid part input", function()
      assert.has_error(function()
        util.current_time("nope")
      end)
    end)
  end)

  describe("duration()", function()
    local MS = 0.001
    local SECOND = 1
    local MINUTE = 60
    local HOUR = MINUTE * 60
    local DAY = HOUR * 24

    it("expects a string or a number", function()
      assert.has_error(function() util.duration() end)
      assert.has_error(function() util.duration(true) end)
      assert.has_error(function() util.duration({}) end)
    end)

    it("treats numbers as seconds", function()
      assert.equals(SECOND, util.duration(1))
      assert.equals(SECOND * 5, util.duration(5))
    end)

    it("rejects negative values", function()
      local d, err = util.duration(-1)
      assert.is_nil(d)
      assert.same("invalid duration", err)

      d, err = util.duration("-1")
      assert.is_nil(d)
      assert.same("invalid duration string", err)
    end)

    it("rejects 0 values", function()
      local d, err = util.duration(0)
      assert.is_nil(d)
      assert.same("invalid duration", err)

      d, err = util.duration("0")
      assert.is_nil(d)
      assert.same("invalid duration string", err)

      d, err = util.duration("0")
      assert.is_nil(d)
      assert.same("invalid duration string", err)

      d, err = util.duration("0.0")
      assert.is_nil(d)
      assert.same("invalid duration string", err)

      d, err = util.duration("0d")
      assert.is_nil(d)
      assert.same("invalid duration string", err)

      d, err = util.duration("0d0s")
      assert.is_nil(d)
      assert.same("invalid duration string", err)
    end)

    it("rejects invalid strings", function()
      local inputs = {
        "",
        "    ",
        "1d7y",
        "1h3d",
        "0.1.1",
        "7dayz",
        ".1h",
      }

      assert(#inputs > 0)

      for i, input in ipairs(inputs) do
        local d, err = util.duration(input)
        local label = string.format("input #%s: %q", i, input)
        assert.is_nil(d, label)
        assert.equals("invalid duration string", err, label)
      end
    end)

    it("parses d/day", function()
      assert.equals(DAY * 1, util.duration("1d"))
      assert.equals(DAY * 1, util.duration("1.0d"))
      assert.equals(DAY * 1, util.duration("1day"))
      assert.equals(DAY * 1, util.duration("01d"))
      assert.equals(DAY * 1.5, util.duration("1.5d"))
      assert.equals(DAY * 2, util.duration("2d"))
    end)

    it("parses h/hour/hours", function()
      assert.equals(HOUR * 1, util.duration("1h"))
      assert.equals(HOUR * 1, util.duration("1.0h"))
      assert.equals(HOUR * 1, util.duration("1hour"))
      assert.equals(HOUR * 1, util.duration("1hours"))
      assert.equals(HOUR * 1, util.duration("1hr"))
      assert.equals(HOUR * 1.5, util.duration("1.5hr"))
      assert.equals(HOUR * 2, util.duration("2hr"))
    end)

    it("parses m/min/minutes", function()
      assert.equals(MINUTE * 1, util.duration("1m"))
      assert.equals(MINUTE * 1, util.duration("1.0m"))
      assert.equals(MINUTE * 1, util.duration("1min"))
      assert.equals(MINUTE * 1, util.duration("1minute"))
      assert.equals(MINUTE * 1, util.duration("1minutes"))
      assert.equals(MINUTE * 1.5, util.duration("1.5m"))
      assert.equals(MINUTE * 2, util.duration("2m"))
    end)

    it("parses s/sec/seconds", function()
      assert.equals(SECOND * 1, util.duration("1s"))
      assert.equals(SECOND * 1, util.duration("1.0s"))
      assert.equals(SECOND * 1, util.duration("1sec"))
      assert.equals(SECOND * 1, util.duration("1secs"))
      assert.equals(SECOND * 1, util.duration("1second"))
      assert.equals(SECOND * 1, util.duration("1seconds"))
      assert.equals(SECOND * 1.5, util.duration("1.5s"))
      assert.equals(SECOND * 2, util.duration("2s"))
    end)

    it("parses ms/millis/milliseconds", function()
      assert.equals(MS * 1, util.duration("1ms"))
      assert.equals(MS * 1, util.duration("1millis"))
      assert.equals(MS * 1, util.duration("1milliseconds"))
    end)

    it("parses multiple units", function()
      assert.equals(MINUTE + 5, util.duration("1m5s"))
      assert.equals((5 * DAY) + (3 * MINUTE), util.duration("5d3m"))
      assert.equals((1 * DAY) + (1 * HOUR) + (30 * MINUTE), util.duration("1d1h30m"))
      assert.equals((1 * DAY) + (1.5 * HOUR), util.duration("1d1.5h"))
      assert.equals((9 * HOUR) + (2 * MINUTE) + (95 * MS), util.duration("0d9h2m95ms"))
    end)

    it("handles insignificant whitespace", function()
      local inputs = {
        { "1d 2h",    (1 * DAY) + (2 * HOUR) },
        { " 1d 2h  ", (1 * DAY) + (2 * HOUR) },
        { "1d2h  ",   (1 * DAY) + (2 * HOUR) },
        { " 1d2h",    (1 * DAY) + (2 * HOUR) },
      }

      assert(#inputs > 0)

      for i, input in ipairs(inputs) do
        local d, err = util.duration(input[1])
        local label = string.format("input #%s: %q", i, input[1])
        assert.is_nil(err, label)
        assert.equals(input[2], d, label)
      end
    end)
  end)

  describe("truthy()", function()
    it("returns true for explicit truthy values", function()
      assert.is_true(util.truthy("yes"))
      assert.is_true(util.truthy("YES"))
      assert.is_true(util.truthy("YeS"))
      assert.is_true(util.truthy("1"))
      assert.is_true(util.truthy("true"))
      assert.is_true(util.truthy("True"))
      assert.is_true(util.truthy(true))
      assert.is_true(util.truthy(1))
    end)

    it("returns false for falsy values", function()
      assert.is_false(util.truthy("no"))
      assert.is_false(util.truthy(""))
      assert.is_false(util.truthy("false"))
      assert.is_false(util.truthy(false))
      assert.is_false(util.truthy(0))
      assert.is_false(util.truthy(-1))
      assert.is_false(util.truthy(nil))
      assert.is_false(util.truthy({}))
    end)
  end)

  describe("table_values()", function()
    it("returns table values", function()
      assert.same({ 1, 2, 3 }, util.table_values({ a = 1, b = 2, c = 3 }))
    end)

    it("sorts the output", function()
      assert.same({ "a", "b", "c" }, util.table_values({ "b", "c", "a" }))
    end)

    it("can de-duplicate the output", function()
      assert.same({ "a", "a", "b", "c" },
                  util.table_values({ "b", "c", "a", "a" }))

      assert.same({ "a", "b", "c" },
                  util.table_values({ "b", "c", "a", "a" }, true))
    end)
  end)

  describe("table_keys()", function()
    it("returns keys for hash-like tables", function()
      assert.same({ "a", "b" }, util.table_keys({ a = 1, b = 2 }))
    end)

    it("returns keys for array-like tables", function()
      assert.same({ 1, 2 }, util.table_keys({ "a", "b" }))
    end)

    it("sorts its output", function()
      assert.same({ "a", "b" }, util.table_keys({ b = 1, a = 2 }))
    end)
  end)

  describe("sha256()", function()
    it("returns a sh256 checksum in hexadecimal form", function()
      assert.same("c0ddd62c7717180e7ffb8a15bb9674d3ec92592e0b7ac7d1d5289836b4553be2",
                  util.sha256("hi!"))
    end)
  end)

  describe("split_at_comma()", function()
    it("splits a string into a table", function()
      assert.same({"a", "b", "c"}, util.split_at_comma("a,b,c"))
    end)

    it("strips whitespace from each item", function()
      assert.same({"a", "b", "c"}, util.split_at_comma(" a ,b,   c"))
    end)

    it("returns a table with a single item when no comma is found", function()
      assert.same({"abc"}, util.split_at_comma("abc"))
    end)

    it("sets the cjson array metatable on the output", function()
      assert.equals(cjson.array_mt, getmetatable(util.split_at_comma("a,b,c")))
    end)
  end)

  describe("join()", function()
    it("joins filesystem path elements", function()
      assert.equals("a/b/c", util.join("a", "b", "c"))
    end)

    it("does not produce duplicate separators", function()
      assert.equals("a/b/c", util.join("a/", "/b/", "c"))
    end)

    it("does not produce a trailing separator", function()
      assert.equals("a/b/c", util.join("a/", "/b/", "c/"))
      assert.equals("a/b/c", util.join("a/", "/b/", "c////"))

      -- eh, not so sure about this one
      assert.equals("a/b/c", util.join("a/", "/b/", "c", ""))
    end)

    it("does not mangle args with multiple path elements", function()
      assert.equals("a/b/subdir/c", util.join("a", "b/subdir/", "c"))
    end)

    it("does not mangle relative paths", function()
      assert.equals("./a/b/c", util.join("./a", "b/c"))
      assert.equals("./a/b/c", util.join(".//a", "b/c"))
      assert.equals("./a/b/../c", util.join(".//a", "b", "..", "c"))
      assert.equals("./a/b/../c", util.join(".//a", "b", "../", "c"))
      assert.equals("./a/b/../c", util.join(".//a", "b", "../", "/c/"))
      assert.equals("./a/b/../c", util.join(".//a//", "b", "../c/"))
    end)


    it("handles absolute paths", function()
      assert.equals("/a/b/c", util.join("/a", "b", "c"))
      assert.equals("/a/b/c", util.join("/", "a", "b", "c"))
    end)
  end)

  describe("update_json_file()", function()
    it("writes json to a file", function()
      local f = os.tmpname()
      assert(util.update_json_file(f, { a = 1, b = 2 }))
      assert.same({ a = 1, b = 2 }, util.read_json_file(f))
    end)

    it("only writes the file if changes are made", function()
      local f = os.tmpname()
      local j = { a = 1, b = 2 }
      assert(util.update_json_file(f, j))
      assert.same(j, util.read_json_file(f))

      local init = lfs.attributes(f)

      local ok, err, written = util.update_json_file(f, j)
      assert.is_nil(err)
      assert.truthy(ok)
      assert.is_false(written)
      assert.same(j, util.read_json_file(f))

      local no_update = lfs.attributes(f)
      assert.equals(init.ino, no_update.ino)
      assert.equals(init.modification, no_update.modification)

      j.c = 3
      ok, err, written = util.update_json_file(f, j)
      assert.is_nil(err)
      assert.truthy(ok)
      assert.is_true(written)
      assert.same(j, util.read_json_file(f))

      local update = lfs.attributes(f)
      assert.not_equals(init.ino, update.ino)
      -- not doing a mod time check here because I don't want to
      -- add a sleep to this test suite
      -- assert.not_equals(init.modification, update.modification)

      ok, err, written = util.update_json_file(f, j)
      assert.is_nil(err)
      assert.truthy(ok)
      assert.is_false(written)
      assert.same(j, util.read_json_file(f))

      assert(util.write_file(f, "I've changed!"))

      ok, err, written = util.update_json_file(f, j)
      assert.is_nil(err)
      assert.truthy(ok)
      assert.is_true(written)
      assert.same(j, util.read_json_file(f))
    end)
  end)
end)
