local log     = require("doorbell.log").with_namespace("ring")
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
    if ctx.deny_action == const.deny_actions.tarpit then
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

local run_hooks
do
  ---@alias doorbell.auth.ring.hook fun(req: doorbell.forwarded_request, ctx: doorbell.ctx, state: doorbell.auth.access.state): doorbell.auth.access.state?

  ---@type doorbell.auth.ring.hook[]
  local hooks = {}
  local hooks_by_name = {}
  local n_hooks = #hooks

  ---@param name string
  ---@param hook doorbell.auth.ring.hook
  function _M.add_hook(name, hook)
    if hooks_by_name[name] then
      error("hook " .. name .. " already exists")
    end

    log.notice("added hook: ", name)
    table.insert(hooks, hook)
    hooks_by_name[name] = true
    n_hooks = #hooks
  end

  ---@param req doorbell.forwarded_request
  ---@param ctx doorbell.ctx
  ---@param state doorbell.auth.access.state
  ---@return doorbell.auth.access.state?
  function run_hooks(req, ctx, state)
    local res
    for i = 1, n_hooks do
      res = hooks[i](req, ctx, state)
      if res == STATES.deny then
        return STATES.deny

      elseif res then
        state = res
      end
    end

    return state
  end
end


---@param ctx doorbell.ctx
local function init_forwarded_request(ctx)
  local req, err = forward.new(ctx)
  if not req then
    log.alert("failed building request: ", err)
    return http.send(400, "bad request")
  end
end


---@param ctx doorbell.ctx
local function check_pre_auth_policy(ctx)
  if policy.pre_auth_allow(ctx.forwarded_request) then
    return http.send(200)
  end
end


---@param ctx doorbell.ctx
function _M.GET(ctx)
  local req = ctx.forwarded_request

  local state, err, token = access.get(req, ctx)
  if err then
    log.err("error checking auth state: ", err)
    state = STATES.error

  else
    state = run_hooks(req, ctx, state) or state
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

  [mware.phase.AUTH] = {
    init_forwarded_request,
  },

  [mware.phase.PRE_HANDLER] = {
    check_pre_auth_policy,
  },

  [mware.phase.POST_RESPONSE] = {
    manager.stats_middleware,
    forward.release,
  },
}

return _M
