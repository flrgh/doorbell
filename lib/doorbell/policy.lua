local _M = {}

---@type doorbell.policy.strategy
local strategy

do
  ---@class doorbell.policy.strategy : table
  local strategy = {}

  ---@param conf doorbell.config
  ---@return doorbell.policy.strategy
  function strategy.new(conf) end

  ---@param req doorbell.forwarded_request
  ---@return boolean allowed
  function strategy:pre_auth_allow(req) end

  ---@param req doorbell.forwarded_request
  ---@param ctx doorbell.ctx
  ---@param token string
  function strategy:pending(req, ctx, token) end

  ---@param req doorbell.forwarded_request
  ---@param ctx doorbell.ctx
  function strategy:unknown(req, ctx) end
end


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
  return strategy:pending(req, req, token)
end


---@param req doorbell.forwarded_request
---@param ctx doorbell.ctx
function _M.unknown(req, ctx)
  return strategy:unknown(req, req)
end



return _M
