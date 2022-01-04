local _M = {}

local const = require "doorbell.constants"

local insert = table.insert

local prometheus

---@type function[]
local HOOKS = {}

function _M.init_worker()
  prometheus = require("prometheus").init(
    const.shm.metrics,
    {
      prefix            = "doorbell_",
      error_metric_name = "metric_errors_total",
    }
  )

  _M.requests = prometheus:counter(
    "requests_total",
    "total number of incoming requests",
    { "status" }
  )

  _M.cache_results = prometheus:counter(
    "rules_cache_results",
    "rules cache hit/miss counts",
    { "status" }
  )

  _M.cache_items = prometheus:gauge(
    "rules_cache_items_total",
    "number of items in the rules LRU cache"
  )

  _M.rules = prometheus:gauge(
    "rules_total",
    "number of rules",
    { "action", "source" }
  )

  _M.actions = prometheus:counter(
    "rule_actions",
    "actions taken by rules",
    { "action" }
  )

  _M.notify = prometheus:counter(
    "notifications_total",
    "notifications for authorization requests (status = sent/failed/snoozed/answered)",
    { "status" }
  )
end

---@return boolean
function _M.enabled()
  return prometheus ~= nil
end

function _M.collect()
  if not prometheus then
    return
  end

  for _, hook in ipairs(HOOKS) do
    pcall(hook)
  end

  prometheus:collect()
end

function _M.add_hook(fn)
  insert(HOOKS, fn)
end

return _M
