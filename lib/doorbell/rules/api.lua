local _M = {
  _VERSION = require("doorbell.constants").version,
}

local rules = require "doorbell.rules"
local manager = require "doorbell.rules.manager"
local empty = require "table.isempty"

---@param  opts           doorbell.rule.new.opts
---@return doorbell.rule? rule
---@return string?        error
---@return integer?       status_code
---@return doorbell.rule? conflict
function _M.insert(opts)
  local rule, err = rules.new(opts)

  if not rule then
    return nil, err, 400
  end

  return manager.add(rule)
end


---@param  opts           doorbell.rule.new.opts|doorbell.rule.update.opts
---@return doorbell.rule? rule
---@return string?        error
---@return integer?       status_code
function _M.upsert(opts)
  local rule, err = rules.new(opts)

  if not rule then
    return nil, err, 400
  end

  return manager.upsert(rule)
end


---@param  id_or_hash     string
---@param  updates        doorbell.rule.update.opts
---@return doorbell.rule? patched
---@return string?        error
---@return integer?       status_code
function _M.patch(id_or_hash, updates)
  return manager.patch(id_or_hash, updates)
end

function _M.list()
  return manager.list()
end

function _M.delete(rule)
  return manager.delete(rule)
end

function _M.get(id_or_hash)
  return manager.get(id_or_hash)
end

local populate_keys, match_by_keys
do
  ---@type string[]
  local keys = {}
  local len_keys = 0

  ---@param key table<string, string>
  function populate_keys(key)
    local i = 0
    for k, v in pairs(key) do
      assert(type(k) == "string")
      assert(type(v) == "string")

      i = i + 1
      keys[i] = k
    end

    len_keys = i
  end

  ---@param key table<string, string>
  ---@param value table<string, string>
  ---@return boolean
  function match_by_keys(key, value)
    for i = 1, len_keys do
      local k = keys[i]
      if key[k] ~= value[k] then
        return false
      end
    end

    return true
  end
end


---@param key string
---@param value? string
---@return doorbell.rule[]
function _M.get_all_by_meta(key, value)
  local ktype = type(key)
  local vtype = type(value)
  local is_table = ktype == "table"

  assert(
         (
           ktype == "string"
           and (value == nil or vtype == "string")
         )
         or
         (
           is_table
           and not empty(key)
           and value == nil
         )
  )

  if is_table then
    populate_keys(key)
  end

  local list = manager.list()
  local found = {}
  local i = 0

  if value then
    for _, rule in ipairs(list) do
      if rule.meta[key] == value then
        i = i + 1
        found[i] = rule
      end
    end

  elseif is_table then
    for _, rule in ipairs(list) do
      if match_by_keys(key, rule.meta) then
        i = i + 1
        found[i] = rule
      end
    end

  else
    for _, rule in ipairs(list) do
      if rule.meta[key] then
        i = i + 1
        found[i] = rule
      end
    end
  end

  return found
end

---@param key string|table<string,string>
---@param value? string
---@return doorbell.rule|nil
function _M.get_by_meta(key, value)
  local ktype = type(key)
  local vtype = type(value)
  local is_table = ktype == "table"

  assert(
         (
           ktype == "string"
           and (value == nil or vtype == "string")
         )
         or
         (
           is_table
           and not empty(key)
           and value == nil
         )
  )

  if is_table then
    populate_keys(key)
  end

  local list = manager.list()

  if value then
    for _, rule in ipairs(list) do
      if rule.meta[key] == value then
        return rule
      end
    end

  elseif is_table then
    for _, rule in ipairs(list) do
      if match_by_keys(key, rule.meta) then
        return rule
      end
    end

  else
    for _, rule in ipairs(list) do
      if rule.meta[key] then
        return rule
      end
    end
  end
end


return _M
