---@class doorbell.auth.openid
local _M = {}

local http = require "doorbell.http"
local log = require "doorbell.log"
local request = require "doorbell.request"

local oidc = require "resty.openidc"
local validators = require "resty.jwt-validators"

local OIDC_OPTS = {
  auth_accept_token_as_header_name = "Authorization",
  auth_accept_token_as = "header",
}

local VALIDATORS = {
  sub = validators.required(),
  exp = validators.required(),
}

local CONFIGURED = false
local DISABLED = false



---@param conf doorbell.config
function _M.init(conf)
  if not conf.auth then
    log.notice("OpenID auth is not configured")
    return

  elseif conf.auth.disabled then
    log.notice("OpenID auth is disabled")
    DISABLED = true
    return
  end


  if conf.auth.openid_issuer then
    log.notice("Enabling OpenID auth")
    local iss = conf.auth.openid_issuer

    assert(http.parse_url(iss), "invalid issuer url")
    iss = iss:gsub("/+$", "") .. "/"

    OIDC_OPTS.discovery = iss .. ".well-known/openid-configuration"
    VALIDATORS.iss = validators.equals(iss)
    CONFIGURED = true
  end
end


---@param ctx doorbell.ctx
---@param route doorbell.route
function _M.auth_middleware(ctx, route)
  if ctx.method == "OPTIONS" then
    return

  elseif DISABLED then
    return

  elseif route.auth_required == false then
    return

  elseif not CONFIGURED then
    log.alert("got request to OpenID endpoint (", route.id, "), but auth is not enabled")
    return http.send(500, { error = "an unexpected error has occurred" })
  end

  local bearer = request.get_header(ctx, "authorization")
  if not bearer then
    return http.send(401, { error = "nope" })

  elseif type(bearer) == "table" then
    log.err("got a request with more than one auth token")
    return http.send(400, { error = "one token at a time, please" })

  elseif bearer:sub(1, 7):lower() ~= "bearer " then
    return http.send(401, { error = "invalid access token" })
  end

  local t = bearer:sub(8)

  local json, err = oidc.jwt_verify(t, OIDC_OPTS, VALIDATORS)

  if err or not json then
    err = err or "unknown error"

    if err:lower():find("jwt expired") then
      return http.send(401, { error = "access token expired" })
    end

    log.warn("unauthorized request: ", err)
    return http.send(403, { error = "no bad guys can come into this town" })
  end

  ctx.auth_jwt = json
end

return _M
