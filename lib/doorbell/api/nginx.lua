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

    if block and block > 0 then
      ngx.update_time()
      local start = ngx.now()
      local deadline = start + block
      local info
      local tries = 0

      repeat
        tries = tries + 1
        local healthy = true

        info = nginx.info()

        for i = 1, ngx.worker.count() do
          healthy = info.workers[i] and info.workers[i].healthy
          if not healthy then
            break
          end
        end

        if not info.agent.healthy then
          healthy = false
        end

        if not healthy then
          ngx.sleep(0.05)
        end
      until healthy or ngx.now() > deadline

      return http.send(200, info)
    end

    return http.send(200, nginx.info())
  end,
}

return routes
