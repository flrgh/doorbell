local errlog = require "ngx.errlog"

local get_level = errlog.get_sys_filter_level
local raw_log   = errlog.raw_log
local fmt       = string.format
local rep       = string.rep
local tostring  = tostring
local select    = select
local rawset    = rawset
local stdout    = io.stdout
local stderr    = io.stderr

local LEVEL = get_level()
local IS_DEBUG = LEVEL >= ngx.DEBUG

local levels_by_name = {
  debug  = ngx.DEBUG,
  info   = ngx.INFO,
  notice = ngx.NOTICE,
  warn   = ngx.WARN,
  err    = ngx.ERR,
  crit   = ngx.CRIT,
  alert  = ngx.ALERT,
  emerg  = ngx.EMERG,
}

local levels_by_num = {}
do
  for name, num in pairs(levels_by_name) do
    levels_by_num[num] = name
  end
  levels_by_num[ngx.ERR] = "error"
end

if ngx.config.is_console then
  local update_time = ngx.update_time
  local utctime = ngx.utctime
  local getinfo = debug.getinfo

  ---@return string
  local function errlog_timestamp()
    update_time()
    --    1234567890123456789
    local yyyy_mm_dd_hh_mm_ss = utctime()

    return yyyy_mm_dd_hh_mm_ss:sub(1, 4)
      .. "/" .. yyyy_mm_dd_hh_mm_ss:sub(6, 7)
      .. "/" .. yyyy_mm_dd_hh_mm_ss:sub(9)
  end

  raw_log = function(lvl, msg)
    local ts = errlog_timestamp()
    lvl = levels_by_num[lvl] or "info"

    if lvl == "debug" then
      local info = getinfo(3, "Sln")
      local src = (info.short_src or ""):gsub("^[%./]*lib/", "")
      local line = info.currentline
      local caller = info.name

      stderr:write(fmt("%s [%s] %s:%s: %s(): %s\n",
                       ts, lvl, src, line, caller, msg))
    else
      stderr:write(fmt("%s [%s] %s\n", ts, lvl, msg))
    end

    stderr:flush()
  end
end

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
local log = {}

setmetatable(log, {
  __index = function(self, k)
    rawset(self, k, noop)
    return noop
  end,
})

do
  for name, lvl in pairs(levels_by_name) do
    if get_level() >= lvl then
      rawset(log, name, make_log(lvl, log_varargs))
      rawset(log, name .. "f", make_log(lvl, log_f))

      -- add a vararg index by numeric log level
      rawset(log, lvl, make_log(lvl, log_varargs))
    end
  end
end

function log.inspect(...)
  return require("inspect")(...)
end

function log.stdout(...)
  stdout:write(...)
  stdout:write("\n")
  stdout:flush()
end

function log.stderr(...)
  stderr:write(...)
  stderr:write("\n")
  stderr:flush()
end

function log.stdoutf(f, ...)
  log.stdout(fmt(f, ...))
end

function log.stderrf(f, ...)
  log.stderr(fmt(f, ...))
end

log.LEVEL = LEVEL
log.IS_DEBUG = IS_DEBUG

return log
