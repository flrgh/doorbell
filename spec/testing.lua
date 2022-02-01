local _M = {}

local util = require "doorbell.util"
local const = require "spec.testing.constants"


local headers_mt = {
  __index = function(self, name)
    name = name:lower():gsub("_", "-")
    return rawget(self, name)
  end,

  __newindex = function(self, name, value)
    name = name:lower():gsub("_", "-")
    return rawset(self, name, value)
  end,
}

---@module 'doorbell.util'
_M.util = util

function _M.headers(t)
  return setmetatable(t or {}, headers_mt)
end

---@param prefix string
---@param conf doorbell.config
---@return spec.testing.nginx
function _M.nginx(prefix, conf)
  return require("spec.testing.nginx").new(prefix, conf)
end

_M.ROOT_DIR = const.ROOT_DIR

return _M
