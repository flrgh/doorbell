local routes = {}

local http = require "doorbell.http"
local mw = require "doorbell.middleware"
local request = require "doorbell.request"
local ip = require "doorbell.ip"

local set_response_header = http.response.set_header
local send = http.send
local get_mime_type = http.get_mime_type
local get_request_headers = request.get_headers
local get_query_arg = request.get_query_arg


local MIME_TYPES = { "text/plain", "application/json" }

local SHARED_MIDDLEWARE = {
  [mw.phase.REWRITE] = {
    request.middleware.enable_logging,
  },
}


routes["/ip/addr"] = {
  id              = "get-forwarded-ip",
  description     = "returns the client IP address",
  metrics_enabled = true,
  allow_untrusted = true,
  auth_required   = false,

  middleware      = {
    [mw.phase.REWRITE] = {
      request.middleware.disable_logging,
    },
  },

  ---@param ctx doorbell.ctx
  GET = function(ctx)
    local accept = get_request_headers(ctx).accept
    local mtype = get_mime_type(accept, MIME_TYPES)

    set_response_header("Content-Type", mtype)

    if mtype == "application/json" then
      return send(200, { data = ctx.forwarded_addr })

    else
      return send(200, ctx.forwarded_addr)
    end
  end,
}


routes["/ip/info"] = {
  id              = "get-forwarded-ip-info",
  description     = "returns IP address info",
  metrics_enabled = true,
  allow_untrusted = true,
  middleware      = SHARED_MIDDLEWARE,
  auth_required   = false,

  ---@param ctx doorbell.ctx
  GET = function(ctx)
    local addr = ctx.forwarded_addr

    local raw = get_query_arg(ctx, "raw")
    local info, err, status = ip.info_api(addr, raw)

    if info then
      return send(200, info)

    else
      return send(status or 500, { message = err or "unknown error" })
    end
  end,
}


routes["~^/ip/info/(?<addr>.+)"] = {
  id              = "get-ip-info",
  description     = "returns IP address info",
  metrics_enabled = true,
  allow_untrusted = false,
  middleware      = SHARED_MIDDLEWARE,
  auth_required   = false,

  GET = function(ctx, match)
    local addr = match.addr
    local raw = get_query_arg(ctx, "raw")
    local info, err, status = ip.info_api(addr, raw)

    if info then
      return send(200, info)

    else
      return send(status or 500, { message = err or "unknown error" })
    end
  end,
}


return routes
