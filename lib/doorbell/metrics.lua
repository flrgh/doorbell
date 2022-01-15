local _M = {
  _VERSION = require("doorbell.constants").version,
}

local const = require "doorbell.constants"
local log   = require "doorbell.log"

local ipairs   = ipairs
local pcall    = pcall
local timer_at = ngx.timer.at
local insert   = table.insert
local exiting  = ngx.worker.exiting

local prometheus

---@class doorbell.metrics.config : table
---@field interval number
---@field disable  boolean

local interval = 5
local enabled = true

---@type function[]
local HOOKS = {}

---@type prometheus.counter
local metric_errors

local function run_hooks(premature)
  if premature or exiting() then
    return
  end

  for _, hook in ipairs(HOOKS) do
    local ok, err = pcall(hook)
    if not ok then
      log.err("metric hook threw an error: ", err)
      metric_errors:inc(1)
    end
  end

  if not exiting() then
    assert(timer_at(interval, run_hooks))
  end
end

---@param conf doorbell.config
function _M.init(conf)
  if conf.metrics then
    interval = conf.metrics.interval or interval
    enabled = not conf.metrics.disable
  end

  if enabled then
    require("doorbell.routes").add("/metrics", {
      allow_untrusted = false,
      description     = "prometheus metrics endpoint",
      log_enabled     = false,
      metrics_enabled = false,
      run             = _M.collect,
    })
  end
end

function _M.init_worker()
  if not enabled then return end

  prometheus = require("prometheus").init(
    const.shm.metrics,
    {
      prefix            = "doorbell_",
      error_metric_name = "metric_errors_total",
    }
  )

  _M.prometheus = prometheus

  metric_errors = assert(prometheus.registry[prometheus.error_metric_name])

  assert(timer_at(0, run_hooks))
end

---@return boolean
function _M.enabled()
  return enabled and prometheus ~= nil
end

function _M.collect()
  if not prometheus then
    return
  end

  prometheus:collect()
end

---@param fn function
function _M.add_hook(fn)
  if enabled then
    insert(HOOKS, fn)
  end
end

return _M
