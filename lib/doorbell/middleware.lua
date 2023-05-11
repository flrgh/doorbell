local _M = {}

local util = require "doorbell.util"

---@alias doorbell.middleware fun(ctx:doorbell.ctx, route:doorbell.route, match?:doorbell.route_match)

---@enum doorbell.middleware.phase
_M.phase = {
  PRE_AUTH = "pre-auth",
  PRE_HANDLER = "pre-handler",
  PRE_LOG = "pre-log",
  POST_LOG = "log",
}

util.error_on_missing_key(_M.phase, "middleware.phase")


---@param mws doorbell.middleware[]
---@param ctx doorbell.ctx
---@param route doorbell.route
---@param match? doorbell.route_match
function _M.exec(mws, ctx, route, match)
  for i = 1, #mws do
    mws[i](ctx, route, match)
  end
end

return _M
