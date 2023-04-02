local _M = {
  _VERSION = require("doorbell.constants").version,
}

local util = require "doorbell.util"
local rules = require "doorbell.rules"

local ipairs = ipairs

local VERSION = 1

local migrations = {
  {
    version     = 1,
    description = "wrap rules array in an object with _version metadata",
    migrate     = function(data)
      return {
        ---@type doorbell.rule[]
        rules    = data,
        _version = 1,
      }
    end,
  }
}

_M.version = VERSION

function _M.migrate(data)
  local v = data._version or 0

  if v == VERSION then
    return data
  end

  if v > VERSION then
    util.errorf("can't load rules from disk from a newer version (%s)", v)
  end


  for _, m in ipairs(migrations) do
    if m.version > v then
      local err
      data, err = m.migrate(data)
      if err then
        util.errorf("failed running migration %s: %s", m.version, err)
      end
    end
  end

  return data
end

---@class doorbell.rules.storage.json
---@field _version integer
---@field _timestamp string
---@field rules doorbell.rule[]

---@param list doorbell.rule[]
---@return doorbell.rules.storage.json
function _M.serialize(list)
  return {
    _version = VERSION,
    rules    = util.map(list, rules.dehydrate),
  }
end

return _M
