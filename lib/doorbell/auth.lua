---@class doorbell.auth
---
---@field access doorbell.auth.access
---@field openid doorbell.auth.openid
local _M = {}

local metrics = require "doorbell.metrics"



---@param conf doorbell.config
function _M.init(conf)
  _M.access = require("doorbell.auth.access")
  _M.access.init(conf)

  _M.openid = require("doorbell.auth.openid")
  _M.openid.init(conf)
end


function _M.init_worker()
  if ngx.worker.id() == 0 then
    metrics.add_hook(_M.access.update_access_metrics)
  end
end


return _M
