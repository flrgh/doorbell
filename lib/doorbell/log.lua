local errlog = require "ngx.errlog"
local sys_level = errlog.get_sys_filter_level()
local raw_log = errlog.raw_log

local fmt = string.format
local tostring = tostring
local select = select
local rep = string.rep

local rawset = rawset

local function noop() end

local log_varargs
do
  local funcs = setmetatable(
    {
      [1] = function(lvl, s)
        raw_log(lvl, tostring(s))
      end,
    },
    {
      __index = function(self, n)
        local tpl = rep("%s", n)
        local fn = function(lvl, ...)
          raw_log(lvl, fmt(tpl, ...))
        end
        rawset(self, n, fn)
        return fn
      end,
    }
  )

  function log_varargs(lvl, ...)
    local n = select("#", ...)
    funcs[n](lvl, ...)
  end
end

local function log_f(lvl, ...)
  raw_log(lvl, fmt(...))
end

local function make_log(lvl, fn)
  return function(...)
    return fn(lvl, ...)
  end
end

---@alias doorbell.log.fn fun(...:any)
---@alias doorbell.log.fnf fun(format:string, ...:any)

---@class doorbell.log
---@field debug   doorbell.log.fn
---@field debugf  doorbell.log.fnf
---@field info    doorbell.log.fn
---@field infof   doorbell.log.fnf
---@field notice  doorbell.log.fn
---@field noticef doorbell.log.fnf
---@field warn    doorbell.log.fn
---@field warnf   doorbell.log.fnf
---@field err     doorbell.log.fn
---@field errf    doorbell.log.fnf
---@field crit    doorbell.log.fn
---@field critf   doorbell.log.fnf
---@field alert   doorbell.log.fn
---@field alertf  doorbell.log.fnf
---@field emerg   doorbell.log.fn
---@field emergf  doorbell.log.fnf
local log = setmetatable({}, {
  __index = function(self, k)
    rawset(self, k, noop)
    return noop
  end,
})

do
  local levels = {
    debug  = ngx.DEBUG,
    info   = ngx.INFO,
    notice = ngx.NOTICE,
    warn   = ngx.WARN,
    err    = ngx.ERR,
    crit   = ngx.CRIT,
    alert  = ngx.ALERT,
    emerg  = ngx.EMERG,
  }
  for name, lvl in pairs(levels) do
    if sys_level >= lvl then
      rawset(log, name, make_log(lvl, log_varargs))
      rawset(log, name .. "f", make_log(lvl, log_f))
    end
  end
end

return log
