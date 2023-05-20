local _M = {}

local log      = require "doorbell.log"
local rules    = require "doorbell.rules"
local schema   = require "doorbell.schema"

local buffer    = require "string.buffer"
local new_tab   = require "table.new"

local type      = type
local ceil      = math.ceil
local assert    = assert
local is_rule   = rules.is_rule
local hydrate   = rules.hydrate
local dehydrate = rules.dehydrate
local debugf    = log.debugf


---@type string.buffer.serialization.opts
local OPTS = {
  metatable = {
    rules.metatable,
  },
}

do
  local dict = {}
  local reserved = {
    -- decode() throws a 'duplicate table key' error if we use this as a
    -- table key, so I assume it's used internally.
    hash = true,
  }

  -- NOTE: this is okay for SHM, but we'll have to be more careful if we start
  -- using this module for external storage (i.e. filesystem).
  for name in pairs(schema.rule.entity.properties) do
    if type(name) == "string" and not reserved[name] then
      table.insert(dict, name)
    end
  end

  -- sanity check
  assert(#dict >= #rules.SERIALIZED_FIELDS)

  table.sort(dict)

  OPTS.dict = dict
end


local SIZE = 1024 * 1024

-- luajit docs say to use different buffers for encode/decode ops
local ENCODER = buffer.new(SIZE, OPTS)
local DECODER = buffer.new(SIZE, OPTS)

local EMPTY = "0"

local AVG_SIZE = 200


---@param list doorbell.rule[]
---@param in_place? boolean
---@return string
function _M.encode(list, in_place)
  assert(type(list) == "table")

  local n = #list
  if n == 0 then
    return EMPTY
  end

  ENCODER:reset()

  -- it's better to over-reserve than under-reserve
  local reserved = ceil(AVG_SIZE * (n + 5))
  ENCODER:reserve(reserved)

  -- store the length as the first item
  ENCODER:encode(n)

  for i = 1, n do
    local rule = list[i]
    assert(is_rule(rule), "invalid rule type")

    rule = dehydrate(rule, in_place)

    ENCODER:encode(rule)
  end

  AVG_SIZE = #ENCODER / n

  debugf("reserved: %s, buf size: %s, #rules: %s, avg rule size: %s",
         reserved, #ENCODER, n, AVG_SIZE)

  return ENCODER:get()
end


---@param str string
---@return doorbell.rule[]
function _M.decode(str)
  assert(type(str) == "string")

  if str == EMPTY then
    return {}
  end

  DECODER:reset():put(str)

  local len = DECODER:decode()
  assert(type(len) == "number", "encoded data is missing length")

  local list = new_tab(len, 0)

  for i = 1, len do
    ---@type doorbell.rule
    local rule = DECODER:decode()
    assert(is_rule(rule), "invalid encoded rule type")
    list[i] = hydrate(rule, true)
  end

  DECODER:reset()

  return list
end


return _M
