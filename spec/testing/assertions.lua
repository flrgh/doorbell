local luassert = require "luassert"
local say = require "say"
local util = require "luassert.util"

local function deep_copy(t)
  local new
  if type(t) == "table" then
    new = {}

    for k, v in pairs(t) do
      new[k] = deep_copy(v)
    end

  else
    new = t
  end

  return new
end

local function delete_nulls(t)
  local new

  if type(t) == "table" then
    new = {}

    for k, v in pairs(t) do
      new[k] = delete_nulls(v)
    end

  elseif t ~= ngx.null then
    new = t
  end

  return new
end

local function copy_from(keys, t)
  local new

  if type(keys) == "table" and type(t) == "table" then
    new = {}
    for k, v in pairs(keys) do
      new[k] = copy_from(v, t[k])
    end
  else
    new = t
  end

  return new
end

local function assert_fields(state, arguments)
  luassert.is_table(arguments[1], "LHS was not a table")
  luassert.is_table(arguments[2], "RHS was not a table")

  local left = deep_copy(arguments[1])
  local right = copy_from(left, arguments[2])

  left = delete_nulls(left)

--  require("spec.testing").inspect({
--    LHS = {
--      original = arguments[1],
--      compare = left,
--    },
--    RHS = {
--      original = arguments[2],
--      compare = right,
--    },
--  })

  local message = arguments[3]
  arguments[3] = nil

  local result, crumbs = util.deepcompare(left, right, true)

  arguments[1] = right
  arguments[2] = left
  arguments.n = 2

  arguments.fmtargs = arguments.fmtargs or {}
  arguments.fmtargs[1] = { crumbs = crumbs }
  arguments.fmtargs[2] = { crumbs = crumbs }

  if message ~= nil then
    state.failure_message = message
  end

  return result
end

luassert:register("assertion", "table_fields", assert_fields, "assertion.same.positive", "assertion.same.negative")

local function table_modifier(state, arguments)
  local t = arguments[1]
  luassert.is_table(t, "expected a table for argument #1")
  rawset(state, "test-table", t)

  return state
end

luassert:register("modifier", "tbl", table_modifier)

local function table_shape(state, arguments)
  luassert.is_table(arguments[1], "LHS was not a table")
  luassert.is_table(arguments[2], "RHS was not a table")

  local left = deep_copy(arguments[1])
  local right = copy_from(left, arguments[2])

  for k, v in pairs(right) do
    right[k] = type(v)
  end

  local message = arguments[3]
  arguments[3] = nil

  local result, crumbs = util.deepcompare(left, right, true)

  arguments[1] = right
  arguments[2] = left
  arguments.n = 2

  arguments.fmtargs = arguments.fmtargs or {}
  arguments.fmtargs[1] = { crumbs = crumbs }
  arguments.fmtargs[2] = { crumbs = crumbs }

  if message ~= nil then
    state.failure_message = message
  end

  return result
end

luassert:register("assertion", "table_shape", table_shape, "assertion.same.positive", "assertion.same.negative")
