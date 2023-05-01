---@type doorbell.route
local _M = {
  description     = "ring ring",
  log_enabled     = true,
  metrics_enabled = true,
  allow_untrusted = false,
  content_type    = "text/plain",
}

local log     = require "doorbell.log"
local const   = require "doorbell.constants"
local auth    = require "doorbell.auth"
local request = require "doorbell.request"
local config  = require "doorbell.config"
local http    = require "doorbell.http"
local join    = require("doorbell.util").join

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
  local arg_t = { next = nil }

  ---@param req doorbell.request
  ---@return string
  function get_redir_location(req)
    local base = join(config.base_url, ENDPOINTS.get_access)

    arg_t.next = fmt("%s://%s%s", req.scheme, req.host, req.uri)

    return base .. "?" .. encode_args(arg_t)
  end
end

---@alias doorbell.handler fun(req:doorbell.request, ctx:doorbell.ctx)


---@type table<doorbell.auth_state, doorbell.handler>
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
    local location = get_redir_location(req)

    log.notice("redirecting client to ", location)
    return http.send(302, "there's a system in place", { location = location })
  end,
}

---@type table<doorbell.auth_state, doorbell.handler>
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

  [STATES.none] = function(req)
    local handler = assert(UNAUTHORIZED_HANDLERS[config.unauthorized])
    return handler(req)
  end,

  [STATES.pending] = function(req)
    log.notice("awaiting access for ", req.addr)
    if auth.await(req) then
      return http.send(201, "access approved, c'mon in")
    end

    return http.send(401)
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
  end

  local state = auth.get_state(req, ctx)

  return HANDLERS[state](req, ctx)
end

return _M
