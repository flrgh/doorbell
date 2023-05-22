local routes = {}

local api       = require "doorbell.api"
local const     = require "doorbell.constants"
local http      = require "doorbell.http"
local log       = require "doorbell.log"
local mw        = require "doorbell.middleware"
local request   = require "doorbell.request"
local rules     = require "doorbell.rules.api"
local schema    = require "doorbell.schema"
local stats     = require "doorbell.rules.stats"
local util      = require "doorbell.util"


local send = http.send
local get_request_input = api.get_request_input
local get_query_arg = request.get_query_arg


local MIDDLEWARE = {
  [mw.phase.PRE_HANDLER] = {
    request.middleware.enable_logging,
  },
}


routes["/rules"] = {
  id                = "rules-collection",
  description       = "rules API",
  metrics_enabled   = false,
  allow_untrusted   = false,
  middleware        = MIDDLEWARE,

  GET = function(ctx)
    local list, err = rules.list()
    if not list then
      log.err("failed to list rules for API request: ", err)
      return send(500, { error = "internal server error" })
    end

    if util.truthy(get_query_arg(ctx, "stats")) then
      stats.decorate_list(list)
    end

    return send(200, { data = list })
  end,

  POST = function(ctx)
    local json = get_request_input(ctx, schema.rule.create)

    json.source = const.sources.api

    local rule, err, status = rules.insert(json)
    if not rule then
      local msg = { error = err }

      if status >= 500 then
        log.err("failed creating rule: ", err)
        msg.error = "internal server error"
      end

      return send(status, msg)
    end

    return send(201, rule)
  end
}

routes["~^/rules/(?<hash_or_id>[a-z0-9-]+)$"] = {
  id                = "rules-single",
  description       = "rules API",
  metrics_enabled   = false,
  allow_untrusted   = false,
  middleware        = MIDDLEWARE,

  GET = function(ctx, match)
    local rule = rules.get(match.hash_or_id)

    if rule then
      if util.truthy(get_query_arg(ctx, "stats")) then
        stats.decorate(rule)
      end

      return send(200, rule)

    else
      return send(404, { error = "rule not found" })
    end
  end,

  PATCH = function(ctx, match)
    local json = get_request_input(ctx, schema.rule.patch)

    local updated, err, status = rules.patch(match.hash_or_id, json)

    if not updated then
      return send(status, { error = err } )
    end

    return send(200, updated)
  end,

  DELETE = function(_, match)
    local ok, err, status = rules.delete(match.hash_or_id)
    if not ok then
      local msg = { error = err }

      if status >= 500 then
        log.err("failed deleting rule: ", err)
        msg.error = "internal server error"
      end

      return send(status, msg)
    end


    return send(204)
  end
}


return routes
