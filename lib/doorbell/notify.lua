local _M = {
  _VERSION = require("doorbell.constants").version,
}

local log = require "doorbell.log"

local utctime = ngx.utctime

local STRATEGIES = {
  pushover = true,
}

---@class doorbell.notify.period : table
---@field from integer
---@field to integer

---@class doorbell.notify.config : table
---@field strategy '"pushover"'
---@field periods doorbell.notify.period[]
---@field config table|resty.pushover.client.opts

---@type doorbell.notify.period[]
local periods

---@class doorbell.notify.strategy
---@field init fun(conf:doorbell.notify.config)
---@field send fun(req:doorbell.request, url:string):boolean, string, string|table|nil
local strategy

---@param conf doorbell.config
function _M.init(conf)
  local notify = assert(conf.notify, "notify missing")
  local strat = assert(notify.strategy, "notify.strategy missing")
  assert(STRATEGIES[strat], "unsupported notify.strategy: " .. strat)

  strategy = require("doorbell.notify.strategies." .. strat)
  strategy.init(notify.config)

  periods = conf.notify.periods
  if not periods then
    log.warn("no notify periods configured; auth requests will be sent at all hours")
  end

  _M.strategy = strat
end

function _M.send(req, token)
  return strategy.send(req, token)
end

---@return boolean
function _M.in_notify_period()
  if not periods then
    return true
  end

  --    1234567890123456789
  local yyyy_mm_dd_hh_mm_ss = utctime()
  local hours = tonumber(yyyy_mm_dd_hh_mm_ss:sub(12, 13))

  for _, p in ipairs(periods) do
    if hours >= p.from and hours < p.to then
      return true
    end
  end

  return false
end

return _M
