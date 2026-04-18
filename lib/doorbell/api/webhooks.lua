local routes = {}

local http    = require "doorbell.http"
local mw      = require "doorbell.middleware"
local request = require "doorbell.request"
local auth    = require "doorbell.auth"
local rules     = require "doorbell.rules.api"
local log = require("doorbell.log").with_namespace("webhooks")
local const     = require "doorbell.constants"

local send = http.send

local TTL = 60 * 60 * 24

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

    local rule = rules.get_by_meta("webhook.user.name", user.name)

    local action, err, status

    if rule then
      action = "update"
      rule, err, status = rules.patch(rule.id, {
        addr = addr,
        ttl = TTL,
      })
    else
      action = "create"
      rule, err, status = rules.insert({
        addr = addr,
        action = const.actions.allow,
        source = const.sources.webhook,
        ttl = 60 * 60 * 24,
        comment = "via webhook",
        meta = {
          ["webhook.user.name"] = user.name,
        },
      })
    end

    if rule then
      log.info(action, "d allow rule",
               " for user: ", user.name,
               ", with addr: ", addr,
               ", id: ", rule.id)

      return send(200, "hey dude!")

    else
      log.warn("failed to ", action, " allow rule",
               " for user: ", user.name,
               " with addr: ", addr, ": ", err)

      return send(status or 500, "sorry, can't help ya!")
    end
  end,
}


return routes
