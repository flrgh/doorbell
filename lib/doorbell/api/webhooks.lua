local routes = {}

local http    = require "doorbell.http"
local mw      = require "doorbell.middleware"
local request = require "doorbell.request"
local ip      = require "doorbell.ip"
local auth    = require "doorbell.auth"
local rules     = require "doorbell.rules.api"
local log = require("doorbell.log").with_namespace("webhooks")
local const     = require "doorbell.constants"

local set_response_header = http.response.set_header
local send = http.send
local get_mime_type = http.get_mime_type
local get_request_headers = request.get_headers
local get_query_arg = request.get_query_arg


local SHARED_MIDDLEWARE = {
  [mw.phase.REWRITE] = {
    request.middleware.enable_logging,
  },
}

routes["/webhooks/ip"] = {
  id              = "webhooks-update-ip",
  description     = "Record the current IP address for an authenticated user",
  metrics_enabled = true,
  middleware      = SHARED_MIDDLEWARE,
  auth_strategy   = auth.require_any(auth.API_KEY),
  content_type    = "text/plain",

  ---@param ctx doorbell.ctx
  POST = function(ctx)
    local user = ctx.user
    if not user then
      return send(500, "just what're we doing here?")
    end

    local addr = ctx.forwarded_addr

    local rule, err, status = rules.upsert({
      addr = addr,
      action = const.actions.allow,
      source = const.sources.webhook,
      ttl = 60 * 24,
      comment = "via webhook",
      meta = {
        ["webhook.user.name"] = user.name,
      },
    })

    if rule then
      log.info("created new allow rule for user: ", user.name,
               ", with addr: ", addr, ", id: ", rule.id)

      return send(200, "hey dude!")

    else
      log.warn("failed creating new allow rule for user: ", user.name,
               " with addr: ", addr, ": ", err)

      return send(status or 500, "sorry, can't help ya!")
    end
  end,
}


return routes
