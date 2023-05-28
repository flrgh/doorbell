local _M = {}

local util = require "doorbell.util"

---@alias doorbell.middleware fun(ctx:doorbell.ctx, route:doorbell.route, match?:doorbell.route_match)

---@enum doorbell.middleware.phase
_M.phase = {
  -- the rewrite phase is for performing any request/context mutations before
  -- checking auth and handling a request
  REWRITE = "rewrite",

  -- the auth phase is for authentication and authorization
  AUTH = "auth",

  -- the pre-handler phase runs just before executing a route's content handler
  PRE_HANDLER = "pre-handler",

  -- the log handler runs before serializing a request log entry and is
  -- ideal for adding data to the request log
  LOG = "log",

  -- the post-response handler runs at the end of the log phase and is ideal
  -- for things like releasing table pool objects, spawning timers for async
  -- tasks, etc
  POST_RESPONSE = "post-response",
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
