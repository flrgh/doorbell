local log     = require "doorbell.log"
local const   = require "doorbell.constants"
local access  = require "doorbell.auth.access"
local forward = require "doorbell.auth.forwarded-request"
local http    = require "doorbell.http"
local mware   = require "doorbell.middleware"
local manager = require "doorbell.rules.manager"
local auth    = require "doorbell.auth"
local policy  = require "doorbell.policy"


---@type doorbell.route
local _M = {
  id              = "ring",
  description     = "ring ring",
  log_enabled     = true,
  metrics_enabled = true,
  allow_untrusted = false,
  content_type    = "text/plain",
  auth_strategy   = auth.require_all(auth.TRUSTED_PROXY_IP),
}


local TARPIT_INTERVAL = const.periods.minute * 5
local STATES          = const.states

local sleep = ngx.sleep

---@alias doorbell.auth.ring.handler fun(req:doorbell.forwarded_request, ctx:doorbell.ctx, token:string|nil)


---@type table<doorbell.auth.access.state, doorbell.auth.ring.handler>
local HANDLERS = {
  [STATES.allow] = function(req)
    log.debugf("ALLOW %s => %s %s://%s%s", req.addr, req.method, req.scheme, req.host, req.uri)
    return http.send(200, "access approved, c'mon in")
  end,

  [STATES.deny] = function(req, ctx)
    log.notice("denying access for ", req.addr)
    if ctx.rule.deny_action == const.deny_actions.tarpit then
      log.debugf("tarpit %s for %s seconds", req.addr, TARPIT_INTERVAL)
      sleep(TARPIT_INTERVAL)
    end

    return http.send(403, "access denied, go away")
  end,

  [STATES.none] = function(req, ctx)
    return policy.unknown(req, ctx)
  end,

  [STATES.pending] = function(req, ctx, token)
    return policy.pending(req, ctx, token)
  end,

  [STATES.error] = function(req)
    log.err("something went wrong while checking auth for ", req.addr)
    return http.send(500, "oops...")
  end,
}

function _M.GET(ctx)
  local req, err = forward.new(ctx)
  if not req then
    log.alert("failed building request: ", err)
    return http.send(400, "bad request")
  end

  if policy.pre_auth_allow(req) then
    return http.send(200)
  end

  local state, token
  state, err, token = access.get(req, ctx)
  if err then
    log.err("error checking auth state: ", err)
    state = STATES.error
  end

  return HANDLERS[state](req, ctx, token)
end

_M.middleware = {
  -- /ring is designed for use as a forward-auth endpoint for proxies and such.
  --
  -- If not properly configured, some proxies may forward _all_ headers from
  -- the client, and we'll get some request headers that we didn't quite expect.
  [mware.phase.REWRITE] = {
    -- NGINX, being the well-behaved web server and proxy that it is, will check
    -- HTTP precondition headers and return a 412 response because they are
    -- nonsensical in this context, so we need to clear them.
    --
    -- https://www.rfc-editor.org/rfc/rfc9110.html#name-preconditions
    http.request.middleware.clear_header("If-Match"),
    http.request.middleware.clear_header("If-Modified-Since"),
    http.request.middleware.clear_header("If-None-Match"),
    http.request.middleware.clear_header("If-Range"),
    http.request.middleware.clear_header("If-Unmodified-Since"),

    -- range requests also don't make much sense here
    http.request.middleware.clear_header("Range"),
  },

  [mware.phase.POST_RESPONSE] = {
    manager.stats_middleware,
    forward.release,
  },
}

return _M
