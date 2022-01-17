---@type doorbell.route
local _M = {
  description     = "ring ring",
  log_enabled     = true,
  metrics_enabled = true,
  allow_untrusted = false,
}

local log     = require "doorbell.log"
local const   = require "doorbell.constants"
local auth    = require "doorbell.auth"
local request = require "doorbell.request"
local config  = require "doorbell.config"

local TARPIT_INTERVAL = const.periods.minute * 5
local STATES          = const.states

local sleep                      = ngx.sleep
local ngx                        = ngx
local exit                       = ngx.exit
local HTTP_OK                    = ngx.HTTP_OK
local HTTP_FORBIDDEN             = ngx.HTTP_FORBIDDEN
local HTTP_UNAUTHORIZED          = ngx.HTTP_UNAUTHORIZED
local HTTP_INTERNAL_SERVER_ERROR = ngx.HTTP_INTERNAL_SERVER_ERROR
local HTTP_BAD_REQUEST           = ngx.HTTP_BAD_REQUEST

---@alias doorbell.handler fun(req:doorbell.request, ctx:doorbell.ctx)

---@type table<doorbell.auth_state, doorbell.handler>
local HANDLERS = {
  [STATES.allow] = function(req)
    log.debugf("ALLOW %s => %s %s://%s%s", req.addr, req.method, req.scheme, req.host, req.uri)
    return exit(HTTP_OK)
  end,

  [STATES.deny] = function(req, ctx)
    log.notice("denying access for ", req.addr)
    if ctx.rule.deny_action == const.deny_actions.tarpit then
      log.debugf("tarpit %s for %s seconds", req.addr, TARPIT_INTERVAL)
      sleep(TARPIT_INTERVAL)
    end
    return exit(HTTP_FORBIDDEN)
  end,

  [STATES.none] = function(req)
    log.notice("requesting access for ", req.addr)
    if auth.request(req) and auth.await(req) then
      log.notice("access approved for ", req.addr)
      return exit(HTTP_OK)
    end
    return exit(HTTP_UNAUTHORIZED)
  end,

  [STATES.pending] = function(req)
    log.notice("awaiting access for ", req.addr)
    if auth.await(req) then
      return exit(HTTP_OK)
    end
    return exit(HTTP_UNAUTHORIZED)
  end,

  [STATES.error] = function(req)
    log.err("something went wrong while checking auth for ", req.addr)
    return exit(HTTP_INTERNAL_SERVER_ERROR)
  end,
}

function _M.GET(ctx)
  local req, err = request.new(ctx)
  if not req then
    log.alert("failed building request: ", err)
    return exit(HTTP_BAD_REQUEST)
  end

  if req.host == config.host and req.path == "/answer" then
    log.debugf("allowing request to %s/answer endpoint", config.host)
    return exit(HTTP_OK)
  end

  local state = auth.get_state(req, ctx)

  return HANDLERS[state](req, ctx)
end

return _M
