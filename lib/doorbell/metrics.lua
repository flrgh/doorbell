local _M = {}

local const = require "doorbell.constants"

local prometheus

function _M.init_worker()
  prometheus = require("prometheus").init(
    const.shm.metrics,
    {
      prefix = "doorbell_",
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
end

---@return boolean
function _M.enabled()
  return prometheus ~= nil
end

function _M.collect()
  if prometheus then
    prometheus:collect()
  end
end

return _M
