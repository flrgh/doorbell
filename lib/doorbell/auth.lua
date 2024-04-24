---@class doorbell.auth
local _M = {}

local metrics = require "doorbell.metrics"
local log = require "doorbell.log"
local http = require "doorbell.http"
local access = require "doorbell.auth.access"
local openid = require "doorbell.auth.openid"
local apikey = require "doorbell.auth.api-key"

local new_tab = require "table.new"

local AUTH_TRUSTED_PROXY          = 1
local AUTH_OPENID                 = 2
local AUTH_API_KEY                = 3
local AUTH_TRUSTED_DOWNSTREAM     = 4

local STRATEGIES = {
  [AUTH_TRUSTED_PROXY] = {
    ---@param ctx doorbell.ctx
    ---@param check_only boolean
    handler = function(ctx, check_only)
      if ctx.is_trusted_proxy then
        return true

      elseif not check_only then
        ctx.auth_http_status = 403
        ctx.auth_client_message = "go away please"
      end
      return false
    end,
  },

  [AUTH_TRUSTED_DOWNSTREAM] = {
    ---@param ctx doorbell.ctx
    ---@param check_only boolean
    handler = function(ctx, check_only)
      if ctx.is_trusted_downstream then
        return true

      elseif not check_only then
        ctx.auth_http_status = 403
        ctx.auth_client_message = "go away please"
      end
      return false
    end,
  },

  [AUTH_API_KEY] = {
    ---@param ctx doorbell.ctx
    ---@param check_only boolean
    handler = function(ctx, check_only)
      local user, err, status = apikey.identify(ctx)
      if user then
        return true

      elseif not check_only then
        ctx.auth_http_status = status
        ctx.auth_client_message = err
      end

      return false
    end,
  },

  [AUTH_OPENID] = {
    ---@param ctx doorbell.ctx
    ---@param check_only boolean
    handler = function(ctx, check_only)
      if check_only and not openid.enabled() then
        return false
      end

      local user, err, status = openid.identify(ctx)
      if user then
        return true

      elseif not check_only then
        ctx.auth_http_status = status
        ctx.auth_client_message = err
      end

      return false
    end,
  }
}

_M.TRUSTED_PROXY_IP      = AUTH_TRUSTED_PROXY
_M.TRUSTED_DOWNSTREAM_IP = AUTH_TRUSTED_DOWNSTREAM
_M.OPENID                = AUTH_OPENID
_M.API_KEY               = AUTH_API_KEY

---@param conf doorbell.config
function _M.init(conf)
  access.init(conf)
  openid.init(conf)
end


function _M.init_worker()
  if ngx.worker.id() == 0 then
    metrics.add_hook(access.update_access_metrics)
  end
end


---@param ctx doorbell.ctx
---@param route doorbell.route
function _M.middleware(ctx, route)
  local strat = route.auth_strategy
  if not strat then
    log.err("route ", route.id, " has no configured auth policy")
    return http.send(500)
  end

  local passed = strat(ctx)
  if ctx.method == "OPTIONS" then
    passed = true
  end

  if passed then
    ctx.auth_http_status = nil
    ctx.auth_client_message = nil

  else
    ---@type string|table
    local msg = ctx.auth_client_message or "access denied"
    local status = ctx.auth_http_status or 403
    if route.content_type == "application/json" then
      msg = { error = msg }
    end

    return http.send(status, msg)
  end
end


local function require_none(ctx)
  STRATEGIES[AUTH_TRUSTED_PROXY].handler(ctx, true)
  STRATEGIES[AUTH_TRUSTED_DOWNSTREAM].handler(ctx, true)
  STRATEGIES[AUTH_API_KEY].handler(ctx, true)
  STRATEGIES[AUTH_OPENID].handler(ctx, true)

  return true
end


function _M.require_none()
  return require_none
end


local function require_any(...)
  local n = select("#", ...)
  assert(n > 0)

  local items = new_tab(n, 0)

  for i = 1, n do
    local idx = select(i, ...)
    items[i] = assert(STRATEGIES[idx].handler)
  end

  if n == 1 then
    local handler = items[1]
    return function(ctx)
      return handler(ctx, false)
    end
  end

  return function(ctx)
    local passed = false

    for i = 1, n do
      if items[i](ctx, passed) then
        passed = true
      end
    end

    return passed
  end
end


---@param ... integer
function _M.require_any(...)
  local n = select("#", ...)
  if n == 0 then
    return require_any(AUTH_TRUSTED_DOWNSTREAM, AUTH_OPENID, AUTH_API_KEY)
  end

  return require_any(...)
end

local function require_all(...)
  local n = select("#", ...)
  assert(n > 0)

  local handlers = new_tab(n, 0)

  for i = 1, n do
    local idx = select(i, ...)
    handlers[i] = assert(STRATEGIES[idx].handler)
  end

  if n == 1 then
    local handler = handlers[1]
    return function(ctx)
      return handler(ctx, false)
    end
  end

  return function(ctx)
    for i = 1, n do
      if not handlers[i](ctx, false) then
        return false
      end
    end

    return true
  end
end


---@param ... integer
function _M.require_all(...)
  local n = select("#", ...)
  if n == 0 then
    return require_all(AUTH_TRUSTED_DOWNSTREAM, AUTH_OPENID, AUTH_API_KEY)
  end
  return require_all(...)
end


function _M.chain(...)
  local n = select("#", ...)
  assert(n > 1)

  local handlers = new_tab(n, 0)

  for i = 1, n do
    local handler = select(i, ...)
    assert(type(handler) == "function")
    handlers[i] = handler
  end

  return function(ctx)
    for i = 1, n do
      if not handlers[i](ctx, false) then
        return false
      end
    end

    return true
  end
end


return _M
