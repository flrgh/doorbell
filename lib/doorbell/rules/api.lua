local _M = {
  _VERSION = require("doorbell.constants").version,
}

local rules = require "doorbell.rules"
local manager = require "doorbell.rules.manager"
local null = ngx.null


---@param  opts           table
---@return doorbell.rule? rule
---@return string?        error
---@return integer?       status_code
function _M.insert(opts)
  local rule, err = rules.new(opts)

  if not rule then
    return nil, err, 400
  end

  return manager.add(rule)
end


---@param  opts           table
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
---@param  updates        doorbell.rule.new.opts
---@return doorbell.rule? patched
---@return string?        error
---@return integer?       status_code
function _M.patch(id_or_hash, updates)
  local current = manager.get(id_or_hash)

  if not current then
    return nil, "rule not found", 404
  end

  local ok, err = rules.validate_update(updates)

  if not ok then
    return nil, err, 400
  end

  for k, v in pairs(updates) do
    if v == null then
      v = nil
    end
    current[k] = v
  end

  current:update_generated_fields()

  ok, err = rules.validate_entity(current)
  if not ok then
    return nil, err, 400
  end

  return manager.upsert(current)
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

return _M
