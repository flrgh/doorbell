local routes = {}

local http    = require "doorbell.http"
local mw      = require "doorbell.middleware"
local request = require "doorbell.request"
local auth    = require "doorbell.auth"
local util    = require "doorbell.util"

local split = require("pl.stringx").split

local send = http.send

local MWARE = {
  [mw.phase.REWRITE] = {
    request.middleware.enable_logging,
  },
}

local function parse_strategies(strategies)
  local list = split(strategies, "+")
  local strats = {}

  for _, item in ipairs(list) do
    if item == "proxy-ip" then
      table.insert(strats, auth.TRUSTED_PROXY_IP)

    elseif item == "downstream-ip" then
      table.insert(strats, auth.TRUSTED_DOWNSTREAM_IP)

    elseif item == "openid" then
      table.insert(strats, auth.OPENID)

    elseif item == "api-key" then
      table.insert(strats, auth.API_KEY)

    else
      error("oops")
    end
  end

  return strats, list
end

local function auth_test(ctx, match, all)
  local strats, list = parse_strategies(match.strategies)

  local handler = all and auth.require_all(util.unpack(strats))
                  or auth.require_any(util.unpack(strats))

  local passed = handler(ctx)
  local status = passed and 200 or ctx.auth_http_status
  send(status, {
    passed             = passed,
    tried              = list,
    error              = ctx.auth_client_message,
    jwt                = ctx.jwt,
    user               = ctx.user,
    trusted_proxy      = not not ctx.is_trusted_proxy,
    trusted_downstream = not not ctx.is_trusted_downstream,
  })
end

local function auth_test_none(ctx)
  send(200, {
    passed             = auth.require_none()(ctx),
    jwt                = ctx.jwt,
    user               = ctx.user,
    trusted_proxy      = not not ctx.is_trusted_proxy,
    trusted_downstream = not not ctx.is_trusted_downstream,
  })
end

routes["/auth-test/none"] = {
  id = "auth-test-none",
  description     = "test authentication (none required)",
  metrics_enabled = false,
  content_type    = "application/json",
  auth_strategy   = auth.require_none(),
  middleware      = MWARE,
  ---@param ctx doorbell.ctx
  GET = function(ctx)
    return auth_test_none(ctx)
  end,

  ---@param ctx doorbell.ctx
  OPTIONS = function(ctx)
    return auth_test_none(ctx)
  end,
}

routes["~^/auth-test/any/(?<strategies>.+)"] = {
  id = "auth-test-any",
  description     = "test authentication (any required)",
  metrics_enabled = false,
  content_type    = "application/json",
  auth_strategy   = auth.require_none(),
  middleware      = MWARE,
  ---@param ctx doorbell.ctx
  GET = function(ctx, match)
    return auth_test(ctx, match, false)
  end,
}

routes["~^/auth-test/all/(?<strategies>.+)"] = {
  id = "auth-test-all",
  description     = "test authentication (all required)",
  metrics_enabled = false,
  content_type    = "application/json",
  auth_strategy   = auth.require_none(),
  middleware      = MWARE,
  ---@param ctx doorbell.ctx
  GET = function(ctx, match)
    return auth_test(ctx, match, true)
  end,
}

return routes
