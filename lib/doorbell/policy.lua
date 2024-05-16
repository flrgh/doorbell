local _M = {}

---@type doorbell.policy.strategy
local strategy


---@class doorbell.policy.strategy : table
---
---@field new fun(doorbell.config): doorbell.policy.strategy
---
---@field pre_auth_allow fun(doorbell.policy.strategy, doorbell.forwarded_request):boolean
---
---@field pending fun(doorbell.policy.strategy, doorbell.forwarded_request, doorbell.ctx, string)
---
---@field unknown fun(doorbell.policy.strategy, doorbell.forwarded_request, doorbell.ctx)


---@param conf doorbell.config
function _M.init(conf)
  strategy = require("doorbell.policy." .. conf.unauthorized).new(conf)
end


---@param req doorbell.forwarded_request
---@return boolean allowed
function _M.pre_auth_allow(req)
  return strategy:pre_auth_allow(req)
end

---@param req doorbell.forwarded_request
---@param ctx doorbell.ctx
---@param token string
function _M.pending(req, ctx, token)
  return strategy:pending(req, ctx, token)
end


---@param req doorbell.forwarded_request
---@param ctx doorbell.ctx
function _M.unknown(req, ctx)
  return strategy:unknown(req, ctx)
end



return _M
