local _M = {}

local util = require "doorbell.util"
local log = require "doorbell.log"

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

do
  local function noop() end

  local remove = table.remove

  ---@generic T
  ---@param t T[]
  ---@return T
  local function pop(t)
    local v = remove(t, 1)
    assert(type(v) == "function", "missing or invalid elem at table head")
    return v
  end

  local exec_c = {
    ---@param mws doorbell.middleware[]
    ---@return doorbell.middleware
    [1] = function(mws)
      local mw_1 = pop(mws)
      return mw_1
    end,

    ---@param mws doorbell.middleware[]
    ---@return doorbell.middleware
    [2] = function(mws)
      local mw_1 = pop(mws)
      local mw_2 = pop(mws)

      ---@param ctx doorbell.ctx
      ---@param route doorbell.route
      ---@param match? doorbell.route_match
      return function(ctx, route, match)
        mw_1(ctx, route, match)
        mw_2(ctx, route, match)
      end
    end,

    ---@param mws doorbell.middleware[]
    ---@return doorbell.middleware
    [3] = function(mws)
      local mw_1 = pop(mws)
      local mw_2 = pop(mws)
      local mw_3 = pop(mws)

      ---@param ctx doorbell.ctx
      ---@param route doorbell.route
      ---@param match? doorbell.route_match
      return function(ctx, route, match)
        mw_1(ctx, route, match)
        mw_2(ctx, route, match)
        mw_3(ctx, route, match)
      end
    end,

    ---@param mws doorbell.middleware[]
    ---@return doorbell.middleware
    [4] = function(mws)
      local mw_1 = pop(mws)
      local mw_2 = pop(mws)
      local mw_3 = pop(mws)
      local mw_4 = pop(mws)


      ---@param ctx doorbell.ctx
      ---@param route doorbell.route
      ---@param match? doorbell.route_match
      return function(ctx, route, match)
        mw_1(ctx, route, match)
        mw_2(ctx, route, match)
        mw_3(ctx, route, match)
        mw_4(ctx, route, match)
      end
    end,

    ---@param mws doorbell.middleware[]
    ---@return doorbell.middleware
    [5] = function(mws)
      local mw_1 = pop(mws)
      local mw_2 = pop(mws)
      local mw_3 = pop(mws)
      local mw_4 = pop(mws)
      local mw_5 = pop(mws)


      ---@param ctx doorbell.ctx
      ---@param route doorbell.route
      ---@param match? doorbell.route_match
      return function(ctx, route, match)
        mw_1(ctx, route, match)
        mw_2(ctx, route, match)
        mw_3(ctx, route, match)
        mw_4(ctx, route, match)
        mw_5(ctx, route, match)
      end
    end,

    ---@param mws doorbell.middleware[]
    ---@return doorbell.middleware
    [6] = function(mws)
      local mw_1 = pop(mws)
      local mw_2 = pop(mws)
      local mw_3 = pop(mws)
      local mw_4 = pop(mws)
      local mw_5 = pop(mws)
      local mw_6 = pop(mws)

      ---@param ctx doorbell.ctx
      ---@param route doorbell.route
      ---@param match? doorbell.route_match
      return function(ctx, route, match)
        mw_1(ctx, route, match)
        mw_2(ctx, route, match)
        mw_3(ctx, route, match)
        mw_4(ctx, route, match)
        mw_5(ctx, route, match)
        mw_6(ctx, route, match)
      end
    end,

    ---@param mws doorbell.middleware[]
    ---@return doorbell.middleware
    [7] = function(mws)
      local mw_1 = pop(mws)
      local mw_2 = pop(mws)
      local mw_3 = pop(mws)
      local mw_4 = pop(mws)
      local mw_5 = pop(mws)
      local mw_6 = pop(mws)
      local mw_7 = pop(mws)

      ---@param ctx doorbell.ctx
      ---@param route doorbell.route
      ---@param match? doorbell.route_match
      return function(ctx, route, match)
        mw_1(ctx, route, match)
        mw_2(ctx, route, match)
        mw_3(ctx, route, match)
        mw_4(ctx, route, match)
        mw_5(ctx, route, match)
        mw_6(ctx, route, match)
        mw_7(ctx, route, match)
      end
    end,

    ---@param mws doorbell.middleware[]
    ---@return doorbell.middleware
    [8] = function(mws)
      local mw_1 = pop(mws)
      local mw_2 = pop(mws)
      local mw_3 = pop(mws)
      local mw_4 = pop(mws)
      local mw_5 = pop(mws)
      local mw_6 = pop(mws)
      local mw_7 = pop(mws)
      local mw_8 = pop(mws)

      ---@param ctx doorbell.ctx
      ---@param route doorbell.route
      ---@param match? doorbell.route_match
      return function(ctx, route, match)
        mw_1(ctx, route, match)
        mw_2(ctx, route, match)
        mw_3(ctx, route, match)
        mw_4(ctx, route, match)
        mw_5(ctx, route, match)
        mw_6(ctx, route, match)
        mw_7(ctx, route, match)
        mw_8(ctx, route, match)
      end
    end,
  }

  ---@param mws doorbell.middleware[]
  ---@return doorbell.middleware
  local function exec_n(mws)
    local n = #mws

    local logged = false

    ---@param ctx doorbell.ctx
    ---@param route doorbell.route
    ---@param match? doorbell.route_match
    return function(ctx, route, match)
      if not logged then
        local id = route and route.id or "global"
        log.warn("middleware for ", id, " route was not compiled because it ",
                 "has ", n, " functions")
        logged = true
      end

      for i = 1, n do
        mws[i](ctx, route, match)
      end
    end
  end


  ---@param mws doorbell.middleware[]|nil
  ---@return doorbell.middleware
  function _M.compile(mws)
    if not mws then
      return noop
    end

    if type(mws) ~= "table" then
      error("invalid middleware type", 2)
    end

    local len = #mws
    if len == 0 then
      return noop
    end

    local compiler = exec_c[len] or exec_n
    return compiler(mws)
  end
end

return _M
