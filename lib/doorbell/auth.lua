---@class doorbell.auth
local _M = {}

local metrics = require "doorbell.metrics"
local log = require "doorbell.log"
local http = require "doorbell.http"
local access = require "doorbell.auth.access"
local openid = require "doorbell.auth.openid"

local bor = bit.bor
local band = bit.band
local lshift = bit.lshift

local REQUIRE_ANY       = lshift(1, 0)
local REQUIRE_ALL       = lshift(1, 1)
local REQUIRE_NONE      = lshift(1, 2)
local AUTH_TRUSTED_IP   = lshift(1, 3)
local AUTH_OPENID       = lshift(1, 4)

local STRATEGIES = {
  {
    code = AUTH_TRUSTED_IP,

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

  {
    code = AUTH_OPENID,

    ---@param ctx doorbell.ctx
    ---@param check_only boolean
    handler = function(ctx, check_only)
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

local NUM_STRATEGIES = #STRATEGIES

_M.TRUSTED_IP = AUTH_TRUSTED_IP
_M.OPENID = AUTH_OPENID

local function is_set(input, flag)
  return band(input, flag) == flag
end

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

  local passed = 0
  local required = 0

  for i = 1, NUM_STRATEGIES do
    local s = STRATEGIES[i]
    local strat_required = is_set(strat, s.code)
    local strat_ok = s.handler(ctx, not strat_required)

    if strat_required then
      required = required + 1

      if strat_ok then
        passed = passed + 1
      end
    end
  end

  local ok = false

  if is_set(strat, REQUIRE_ALL) then
    ok = passed >= required

  elseif is_set(strat, REQUIRE_ANY) then
    ok = passed >= 1

  elseif is_set(strat, REQUIRE_NONE) then
    ok = true

  else
    error("unreachable")
  end


  if ctx.method == "OPTIONS" then
    ok = true
  end

  if ok then
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


function _M.require_none()
  return REQUIRE_NONE
end

---@param ... integer
function _M.require_any(...)
  local n = select("#", ...)
  if n == 0 then
    return _M.require_any(AUTH_TRUSTED_IP, AUTH_OPENID)
  end

  return bor(REQUIRE_ANY, ...)
end


---@param ... integer
function _M.require_all(...)
  local n = select("#", ...)
  if n == 0 then
    return _M.require_all(AUTH_TRUSTED_IP, AUTH_OPENID)
  end
  return bor(REQUIRE_ALL, ...)
end

return _M
