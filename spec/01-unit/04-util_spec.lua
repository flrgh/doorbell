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
