---@class doorbell.auth
---
---@field access doorbell.auth.access
local _M = {}

local metrics = require "doorbell.metrics"



---@param conf doorbell.config
function _M.init(conf)
  _M.access = require("doorbell.auth.access")
  _M.access.init(conf)
end


function _M.init_worker()
  if ngx.worker.id() == 0 then
    metrics.add_hook(_M.access.update_access_metrics)
  end
end


return _M
