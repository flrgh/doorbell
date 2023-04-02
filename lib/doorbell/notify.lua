local _M = {
  _VERSION = require("doorbell.constants").version,
}

local log = require "doorbell.log"
local util = require "doorbell.util"

local utctime = ngx.utctime

local STRATEGIES = {
  pushover = true,
}

local STATUS = {
  failed   = {"failed"},
  snoozed  = {"snoozed"},
  sent     = {"send"},
  answered = {"answered"},
}

---@enum doorbell.notify.level
_M.level = {
  debug  = 0,
  info   = 1,
  error  = 2,
  alert  = 3,
}

---@class doorbell.notify.message : table
---
---@field title       string
---@field message     string
---@field level       doorbell.notify.level
---@field link?       string
---@field link_title? string

---@type prometheus.counter
local metric

---@class doorbell.notify.period : table
---@field from integer
---@field to integer

---@alias doorbell.notify.strategy.config
---| table
---| resty.pushover.client.opts

---@class doorbell.notify.config : table
---@field strategy string|"pushover"
---@field periods  doorbell.notify.period[]
---@field config   doorbell.notify.strategy.config

---@type doorbell.notify.period[]
local periods

---@class doorbell.notify.strategy
---@field init fun(conf:doorbell.notify.strategy.config)
---@field ring fun(req:doorbell.request, url:string):boolean?, string?, string|table|nil
---@field send fun(msg:doorbell.notify.message):boolean?, string?, string|table|nil
local strategy

---@param conf doorbell.config
function _M.init(conf)
  local notify = conf.notify
  local strat = notify and notify.strategy or "none"

  if strat == "none" then
    log.warn("no configured notify strategy--notifications will be disabled")
    return
  end

  if STRATEGIES[strat] then
    log.info("using builtin notify strategy: ", strat)
    strategy = require("doorbell.notify.strategies." .. strat)
  else
    log.info("using custom notify strategy: ", strat)
    local ok
    ok, strategy = pcall(require, strat)
    if not ok then
      util.errorf("failed loading custom notify strategy %s: %s", strat, strategy)
    end
  end

  strategy.init(notify.config)

  periods = conf.notify.periods
  if not periods then
    log.warn("no notify periods configured; auth requests will be sent at all hours")
  end

  _M.strategy = strat
end

---@param  req               doorbell.request
---@param  url               string
---@return boolean?          ok
---@return string?           err
---@return string|table|nil? res
function _M.ring(req, url)
  return strategy.ring(req, url)
end

function _M.send(msg)
  assert(type(msg) == "table")

  if not _M.enabled() then
    log.debugf("not sending message (%s), notification system is disabled", msg.title)
    return true
  end

  msg.level = msg.level or _M.level.info

  if msg.level <= _M.level.debug and not _M.in_notify_period() then
    log.debugf("not sending debug message (%s), outside of notifcation period", msg.title)
    return true
  end

  return strategy.send(msg)
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

---@param status "sent"|"failed"|"snoozed"|"answered"
function _M.inc(status)
  if not strategy then return end

  if not STATUS[status] then
    log.err("tried to increment unknown notify status: ", status)
    return
  end

  if not metric then
    return
  end

  metric:inc(1, STATUS[status])
end

function _M.init_worker()
  if not strategy then return end

  local metrics = require "doorbell.metrics"
  if metrics.enabled() then
    metric = metrics.prometheus:counter(
      "notifications_total",
      "notifications for authorization requests (status = sent/failed/snoozed/answered)",
      { "status" }
    )
  end
end

function _M.enabled()
  return strategy ~= nil
end

return _M
