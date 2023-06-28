local routes = {}

local nginx = require "doorbell.nginx"
local request = require "doorbell.request"
local mw = require "doorbell.middleware"
local http = require "doorbell.http"
local auth = require "doorbell.auth"

routes["/nginx"] = {
  id = "nginx-info",
  description = "returns information about the current nginx process/group",
  metrics_enabled = false,
  content_type = "application/json",
  auth_strategy = auth.require_any(),

  middleware      = {
    [mw.phase.REWRITE] = {
      request.middleware.disable_logging,
    },
  },

  GET = function(ctx)
    local block = tonumber(request.get_query_arg(ctx, "block"))
    local info = nginx.info(block)
    local status = info.ok and 200 or 503
    return http.send(status, info)
  end,
}

return routes
