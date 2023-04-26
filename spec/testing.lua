local _M = {}

local util = require "doorbell.util"
local const = require "spec.testing.constants"
local config = require "spec.testing.config"
local client = require "spec.testing.client"
local await = require "spec.testing.await"
local assert = require "luassert"
local random = require "resty.random"

require "spec.testing.assertions"

local inspect = require "inspect"
local to_hex = require("resty.string").to_hex

local fmt = string.format


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

_M.fs = require("spec.testing.fs")


_M.await = {
  truthy = function(fn, timeout, step, msg)
    assert(await.truthy(timeout, step, fn), msg or "timeout reached")
  end,

  falsy = function(fn, timeout, step, msg)
    assert(await.falsy(timeout, step, fn), msg or "timeout reached")
  end,

  no_error = function(fn, timeout, step, msg)
    local wrapped = function(...)
      return pcall(fn, ...)
    end

    assert(await.truthy(timeout, step, wrapped), msg or "timeout reached", 2)
  end,
}


---@param v any
function _M.inspect(v)
  require("doorbell.log").stderr(inspect(v))
end


---@param len? integer # length in bytes
---@return string
function _M.random_string(len)
  len = len or 32
  local bytes = random.bytes(len, false)
  return to_hex(bytes)
end


---@return string
function _M.random_ipv4()
  return fmt("%s.%s.%s.%s",
             math.random(1, 254),
             math.random(1, 254),
             math.random(1, 254),
             math.random(1, 254))
end

return _M
