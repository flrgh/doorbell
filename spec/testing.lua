local _M = {}

local util = require "doorbell.util"
local const = require "spec.testing.constants"
local config = require "spec.testing.config"
local client = require "spec.testing.client"
local await = require "spec.testing.await"

require "spec.testing.assertions"

local inspect = require "inspect"


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

_M.constants = const


_M.await = {
  truthy = function(fn, timeout, step, msg)
    assert(await.truthy(timeout, step, fn), msg or "timeout reached")
  end,

  falsy = function(fn, timeout, step, msg)
    assert(await.falsy(timeout, step, fn), msg or "timeout reached")
  end,
}

---@param v any
function _M.inspect(v)
  require("doorbell.log").stderr(inspect(v))
end

return _M
