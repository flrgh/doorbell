local _M = {}

require("resty.jit-uuid").seed()

local util = require "doorbell.util"
local const = require "spec.testing.constants"
local config = require "spec.testing.config"
local client = require "spec.testing.client"
local await = require "spec.testing.await"
local assert = require "luassert"
local random = require "resty.random"

require "spec.testing.assertions"

local inspect = require "inspect"

local fmt = string.format


---@module 'doorbell.util'
_M.util = util

_M.headers = client.headers

---@param conf doorbell.config
---@return spec.testing.nginx
function _M.nginx(conf)
  return require("spec.testing.nginx").new(conf)
end


_M.config = config.new
_M.API_KEY = config.API_KEY

_M.client = client.new

_M.ROOT_DIR = const.ROOT_DIR

_M.constants = const

_M.fs = require("spec.testing.fs")


_M.await = {
  ---@param fn       function
  ---@param timeout? number
  ---@param step?    number
  ---@param msg      any
  truthy = function(fn, timeout, step, msg)
    assert(await.truthy(timeout, step, fn), msg or "timeout reached", 2)
  end,

  ---@param fn       function
  ---@param timeout? number
  ---@param step?    number
  ---@param msg      any
  falsy = function(fn, timeout, step, msg)
    assert(await.falsy(timeout, step, fn), msg or "timeout reached", 2)
  end,

  ---@param fn       function
  ---@param timeout? number
  ---@param step?    number
  ---@param msg      any
  no_error = function(fn, timeout, step, msg)
    local wrapped = function(...)
      return pcall(fn, ...)
    end

    assert(await.truthy(timeout, step, wrapped), msg or "timeout reached", 2)
  end,
}


---@param v any
function _M.inspect(v)
  require("doorbell.log").stderr("\n\n" .. inspect(v) .. "\n\n")
end

---@param v any
---@return string
function _M.pretty_print(v)
  return (require("pl.pretty").write(v))
end


---@param len? integer # length in bytes
---@return string
function _M.random_string(len)
  len = len or 32
  local bytes = random.bytes(len, false)
  return ngx.encode_base64(bytes, true)
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
