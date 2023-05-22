local routes = {}


local access  = require "doorbell.auth.access"
local config  = require "doorbell.config"
local log     = require "doorbell.log"
local mw      = require "doorbell.middleware"
local request = require "doorbell.request"
local schema  = require "doorbell.schema"
local api     = require "doorbell.api"
local const   = require "doorbell.constants"


local send               = api.send
local get_request_input  = api.get_request_input
local get_request_header = request.get_header


local CONF = {
  allowed_scopes   = config.approvals.allowed_scopes,
  allowed_subjects = config.approvals.allowed_subjects,
  max_ttl          = config.approvals.max_ttl,
}

---@param res table
local function add_conf(res)
  res.allowed_subjects = CONF.allowed_subjects
  res.allowed_scopes   = CONF.allowed_scopes
  res.max_ttl          = CONF.max_ttl
end

local not_found
do
  local res = { error = "not found" }
  function not_found()
    return send(404, res)
  end
end


local function send_error(status, err)
  return send(status, { error = err })
end


local  middleware = {
  [mw.phase.PRE_HANDLER] = {
    request.middleware.enable_logging,
  },
}


routes["/access/pending"] = {
  id              = "access-pending-collection",
  description     = "list pending access requests",
  metrics_enabled = true,
  allow_untrusted = false,
  middleware      = middleware,

  GET = function()
    local list = access.list_approvals(const.states.pending)
    return send(200, { data = list })
  end,
}

routes["/access/pre-approved"] = {
  id              = "access-pre-approved-collection",
  description     = "list pre-approved access requests",
  metrics_enabled = true,
  allow_untrusted = false,
  middleware      = middleware,

  GET = function()
    local list = access.list_approvals(const.states.pre_approved)
    return send(200, { data = list })
  end,
}



routes["/access/config"] = {
  id              = "access-config",
  description     = "fetch access control configuration",
  metrics_enabled = true,
  allow_untrusted = false,
  middleware      = middleware,

  GET = function()
    return send(200, CONF)
  end,
}


routes["/access/intent"] = {
  id              = "access-intent",
  description     = "allow, deny, or pre-approve access requests",
  metrics_enabled = true,
  allow_untrusted = false,
  middleware      = middleware,

  POST = function(ctx)
    local data = get_request_input(ctx, schema.auth.access.api.intent)
    local status, err = access.answer(data)

    if status == 404 then
      return not_found()

    elseif status >= 400 then
      return send_error(status, err)
    end

    return send(status, { message = "OK" })
  end,
}


routes["~^/access/pending/by-token/(?<token>[^/]+)$"] = {
  id              = "approvals-by-token",
  description     = "fetch an approval request for a given token",
  metrics_enabled = true,
  allow_untrusted = false,
  middleware      = middleware,

  GET = function(_, match)
    local token = match.token
    local app = access.get_pending_approval(token)
    if not app then
      return not_found()
    end

    add_conf(app)

    return send(200, app)
  end,
}

routes["~^/access/pending/by-addr/(?<addr>[^/]+)$"] = {
  id              = "approvals-by-addr",
  description     = "fetch an approval request for a given IP address",
  metrics_enabled = true,
  allow_untrusted = false,
  middleware      = middleware,

  GET = function(_, match)
    local addr = match.addr
    local pending, token = access.is_pending("addr", addr)

    if not pending or not token then
      return not_found()
    end

    local app = access.get_pending_approval(token)

    -- not impossible but probably weird
    if not app then
      log.warn("access for %s is pending, but no approval found", addr)
      return not_found()
    end

    add_conf(app)

    return send(200, app)
  end,
}

routes["/access/pre-approval"] = {
  id              = "access-pre-approval",
  description     = "pre-approve access for an IP or user-agent",
  metrics_enabled = true,
  allow_untrusted = false,
  middleware      = middleware,

  ---@param ctx doorbell.ctx
  POST = function(ctx)
    ---@type doorbell.auth.access.api.pre-approval
    local pre = get_request_input(ctx, schema.auth.access.api.pre_approval)
    local subject

    local req = {
      ua = get_request_header(ctx, "user-agent"),
      addr = assert(ctx.forwarded_addr),
    }

    if pre.subject == const.subjects.ua then
      subject = req.ua
      if not subject then
        return send_error(400, "pre-approval with `ua` scope must have a `user-agent` header")
      end

    else
      assert(pre.subject == const.subjects.addr)
      subject = req.addr
    end

    local status, err = access.pre_approve(pre, req)
    if status >= 400 then
      return send_error(status, err)
    end

    return send(201, { message = "OK", subject = subject })
  end,
}


return routes
