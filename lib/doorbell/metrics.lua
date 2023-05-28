---@class doorbell.metrics
local _M = {
  ---@type table<string, PrometheusGauge|PrometheusCounter|prometheus.counter|prometheus.gauge>
  registry = {}
}

local const = require "doorbell.constants"
local log   = require "doorbell.log"

local ipairs   = ipairs
local pcall    = pcall
local timer_at = ngx.timer.at
local insert   = table.insert
local exiting  = ngx.worker.exiting


local registry = _M.registry

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

local hooks_first_run = false

local function run_hooks(premature, once)
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

  hooks_first_run = true

  if not exiting() and not once then
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
    require("doorbell.router").add("/metrics", {
      description     = "prometheus metrics endpoint",
      allow_untrusted = true,
      GET             = function()
        if enabled and prometheus then
          if not hooks_first_run then
            log.debug("running hooks for the first time in the request path")
            run_hooks(false, true)
          end
          prometheus:collect()
        end
      end,
    })
  end
end

function _M.init_worker()
  if not enabled then return end

  prometheus = assert(require("prometheus").init(
    const.shm.metrics,
    {
      prefix            = "doorbell_",
      error_metric_name = "metric_errors_total",
    }
  ))

  _M.prometheus = prometheus

  metric_errors = assert(prometheus.registry[prometheus.error_metric_name])

  registry.rules_total = prometheus:gauge(
    "rules_total",
    "number of rules",
    { "action", "source" }
  )

  registry.rule_actions = prometheus:counter(
    "rule_actions",
    "actions taken by rules",
    { "action" }
  )

  registry.cache_lookups = prometheus:counter(
    "cache_lookups",
    "LRU cache hit/miss counts",
    { "name", "status" }
  )

  registry.cache_entries = prometheus:gauge(
    "cache_entries",
    "number of items in the LRU cache(s)",
    { "name" }
  )

  registry.notifications_total = prometheus:counter(
    "notifications_total",
    "notifications for authorization requests (status = sent/failed/snoozed/answered)",
    { "status" }
  )

  registry.requests_total = prometheus:counter(
    "requests_total",
    "total number of incoming requests",
    { "status" }
  )

  registry.requests_by_country = prometheus:counter(
    "requests_by_country",
    "total number of incoming requests, by origin country code",
    { "country" }
  )

  registry.requests_by_network = prometheus:counter(
    "requests_by_network",
    "total number of incoming requests, by network tag",
    { "network" }
  )

  registry.requests_by_route = prometheus:counter(
    "requests_by_route",
    "total number of incoming requests, by route id",
    { "route" }
  )

  assert(timer_at(0, run_hooks))
end

---@return boolean
function _M.enabled()
  return enabled
end

---@param fn function
function _M.add_hook(fn)
  if enabled then
    insert(HOOKS, fn)
  end
end


---@param name string
---@param value integer
---@param labels? string[]
function _M.inc(name, value, labels)
  if not enabled then return end

  local metric = registry[name]
  if not metric then
    error("no such metric: " .. name, 2)

  elseif not metric.inc then
    error("invalid operation for metric type", 2)
  end

  metric:inc(value, labels)
end


---@param name string
---@param value integer
---@param labels? string[]
function _M.set(name, value, labels)
  if not enabled then return end

  local metric = registry[name]
  if not metric then
    error("no such metric: " .. name, 2)

  elseif not metric.set then
    error("invalid operation for metric type", 2)
  end

  metric:set(value, labels)
end

return _M
