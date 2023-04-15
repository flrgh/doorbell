local _M = {
  _VERSION = require("doorbell.constants").version,
}

local rules = require "doorbell.rules"
local manager = require "doorbell.rules.manager"


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

return _M
