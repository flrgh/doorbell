local _M = {}

local util = require "doorbell.util"
local const = require "spec.testing.constants"
local config = require "spec.testing.config"
local client = require "spec.testing.client"


---@module 'doorbell.util'
_M.util = util

_M.headers = client.headers

---@param prefix string
---@param conf doorbell.config
---@return spec.testing.nginx
function _M.nginx(prefix, conf)
  return require("spec.testing.nginx").new(prefix, conf)
end

_M.config = config.new

_M.client = client.new

_M.ROOT_DIR = const.ROOT_DIR

return _M
