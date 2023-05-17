---@type doorbell.route
local _M = {
  id              = "ring",
  description     = "ring ring",
  log_enabled     = true,
  metrics_enabled = true,
  allow_untrusted = false,
  content_type    = "text/plain",
}

local log     = require "doorbell.log"
local const   = require "doorbell.constants"
local auth    = require "doorbell.auth"
local request = require "doorbell.auth.request"
local config  = require "doorbell.config"
local http    = require "doorbell.http"
local mware   = require "doorbell.middleware"
local join    = require("doorbell.util").join
local ip      = require "doorbell.ip"

local TARPIT_INTERVAL = const.periods.minute * 5
local STATES          = const.states
local POLICY          = const.unauthorized
local ENDPOINTS       = const.endpoints

---@type doorbell.unauthorized
local UNAUTHORIZED


local sleep = ngx.sleep
local fmt = string.format

local get_redir_location
do
  local encode_args = ngx.encode_args
  local arg_t = {
    addr     = nil,
    next     = nil,
    token    = nil,
    scopes   = nil,
    subjects = nil,
    max_ttl  = nil,
  }

  ---@param req doorbell.forwarded_request
  ---@param token string
  ---@return string
  function get_redir_location(req, token)
    local uri

    if config.redirect_uri then
      uri = config.redirect_uri
    else
      uri = join(config.base_url, ENDPOINTS.get_access)
    end

    arg_t.next     = fmt("%s://%s%s", req.scheme, req.host, req.uri)
    arg_t.token    = token
    arg_t.scopes   = config.approvals.allowed_scopes
    arg_t.subjects = config.approvals.allowed_subjects
    arg_t.max_ttl  = config.approvals.max_ttl
    arg_t.addr     = req.addr

    return uri .. "?" .. encode_args(arg_t)
  end
end

---@alias doorbell.auth.ring.handler fun(req:doorbell.forwarded_request, ctx:doorbell.ctx, token:string|nil)


---@type table<doorbell.auth_state, doorbell.auth.ring.handler>
local UNAUTHORIZED_HANDLERS = {
  [const.unauthorized.return_401] = function()
    return http.send(401, "who are you?")
  end,

  [const.unauthorized.request_approval] = function(req)
    log.notice("requesting access for ", req.addr)

    if auth.request(req) and auth.await(req) then
      log.notice("access approved for ", req.addr)
      return http.send(201, "access approved, c'mon in")
    end

    return http.send(401, "who are you?")
  end,

  [const.unauthorized.redirect_for_approval] = function(req)
    local state, token = auth.new_approval(req)

    if state == STATES.allow then
      return http.send(201, "you may enter")

    elseif state == STATES.deny then
      return http.send(403, "go away dude")

    elseif state == STATES.error then
      return http.send(500, "uh oh")
    end

    assert(state == STATES.pending, "unexpected/invalid state: " .. state)
    assert(token ~= nil, "empty token returned")

    local location = get_redir_location(req, token)

    log.notice("redirecting client to ", location)
    return http.send(302, "there's a system in place", { location = location })
  end,
}


---@type table<doorbell.auth_state, doorbell.auth.ring.handler>
local PENDING_HANDLERS = {
  [const.unauthorized.return_401] = function()
    return http.send(401, "who are you?")
  end,

  [const.unauthorized.request_approval] = function(req)
    log.notice("awaiting access for ", req.addr)
    if auth.await(req) then
      return http.send(201, "access approved, c'mon in")
    end

    return http.send(401, "I dunno man")
  end,

  [const.unauthorized.redirect_for_approval] = function(req, _, token)
    local location = get_redir_location(req, token)

    log.notice("redirecting client to ", location)
    return http.send(302, "there's a system in place", { location = location })
  end,
}

---@type table<doorbell.auth_state, doorbell.auth.ring.handler>
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
    local handler = assert(UNAUTHORIZED_HANDLERS[config.unauthorized])
    return handler(req, ctx)
  end,

  [STATES.pending] = function(req, ctx, token)
    local handler = assert(PENDING_HANDLERS[config.unauthorized])
    return handler(req, ctx, token)
  end,

  [STATES.error] = function(req)
    log.err("something went wrong while checking auth for ", req.addr)
    return http.send(500, "oops...")
  end,
}

function _M.GET(ctx)
  UNAUTHORIZED = UNAUTHORIZED or config.unauthorized

  local req, err = request.new(ctx)
  if not req then
    log.alert("failed building request: ", err)
    return http.send(400, "bad request")
  end

  if UNAUTHORIZED == POLICY.request_approval
    and req.host == config.host
    and req.path == ENDPOINTS.answer
  then
    log.debugf("allowing request to %s endpoint", ENDPOINTS.answer)
    return http.send(200)

  elseif UNAUTHORIZED == POLICY.redirect_for_approval
    and req.host == config.host
    and req.path == ENDPOINTS.get_access
  then
    log.debugf("allowing request to %s endpoint", ENDPOINTS.get_access)
    return http.send(200)
  end

  local state, token
  state, err, token = auth.get_state(req, ctx)
  if err then
    log.err("error checking auth state: ", err)
    state = STATES.error
  end

  return HANDLERS[state](req, ctx, token)
end

_M.middleware = {
  [mware.phase.PRE_HANDLER] = {
    ip.require_trusted_proxy,
  },
  [mware.phase.POST_LOG] = {
    request.release,
  }
}

return _M
