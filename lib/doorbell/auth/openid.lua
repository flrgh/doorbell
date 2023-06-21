---@class doorbell.auth.openid
local _M = {}

local http = require "doorbell.http"
local log = require "doorbell.log"
local request = require "doorbell.request"
local cache = require "doorbell.cache.shared"
local util = require "doorbell.util"
local httpc = require "resty.http"

local oidc = require "resty.openidc"
local validators = require "resty.jwt-validators"
local cjson = require "cjson"


local sha256 = util.sha256
local substr = string.sub
local lower = string.lower
local type = type
local get_header = request.get_header
local now = ngx.now
local find = string.find

local E_EXPIRED = "access token expired"
local E_INTERNAL = "internal server error"
local E_NO_SUCH_USER = "no such user"
local E_NOT_VERIFIED = "could not validate and/or validate access token"
local E_INVALID_TOKEN = "invalid access token"
local E_NO_TOKEN = "authentication required"
local SLACK = 60

local AUTH_HEADER = "Authorization"

---@alias doorbell.auth.openid.token.source
---| "NONE"
---| "HEADER"
---| "COOKIE"

local SRC_NONE = "NONE"
local SRC_HEADER = "HEADER"
--local SRC_COOKIE = "COOKIE"

local OIDC_OPTS = {
  auth_accept_token_as_header_name = "Authorization",
  auth_accept_token_as = "header",
  iat_slack = SLACK,
}

---@type string
local DISCOVERY_URL

---@type table
local DISCOVERY_DATA

local VALIDATORS = {
  sub = validators.required(),
  exp = validators.required(),
}

---@type table <string, doorbell.config.auth.user>
local USERS = {}

---@type table <string, doorbell.config.auth.user>
local USERS_BY_SUB = {}

---@type table <string, doorbell.config.auth.user>
local USERS_BY_EMAIL = {}

local CONFIGURED = false
local DISABLED = false

local CACHE_KEY_DISCOVERY = "oidc::discovery"


---@param e string|nil
---@return boolean
local function is_expired_err(e)
  return type(e) == "string"
     and (e == "JWT expired"
          or find(lower(e), "expired", nil, true) ~= nil)
end


---@class doorbell.auth.jwt : table
---
---@field aud   string|string[]
---@field azp   string
---@field exp   number
---@field iat   number
---@field iss   string
---@field scope string
---@field sub   string


---@param t doorbell.auth.jwt
local function token_ttl(t)
  local exp = t and t.exp

  if type(exp) ~= "number" then
    error("empty token or empty token.exp", 2)
  end

  local ttl = (exp - now()) + SLACK

  -- never return a ttl of 0 because it probably means we'll get cached
  -- forever
  if ttl == 0 then
    ttl = -1
  end

  return ttl
end


---@param  ctx doorbell.ctx
---@return string? raw_token
---@return string? error
---@return ngx.http.status_code? status
---@return doorbell.auth.openid.token.source? source
local function get_access_token(ctx)
  local src = SRC_NONE

  local bearer = get_header(ctx, AUTH_HEADER)

  if bearer then
    src = SRC_HEADER

    if type(bearer) == "table" then
      log.notice("got a request with more than one auth token")
      return nil, E_INVALID_TOKEN, 400, src

    elseif substr(lower(bearer), 1, 7) ~= "bearer " then
      return nil, E_INVALID_TOKEN, 401, src
    end

    local token = substr(bearer, 8)
    return token, nil, nil, src

  -- TODO: get from cookie
  end

  return nil, E_NO_TOKEN, 401, src
end


local function load_discovery()
  local client = assert(httpc.new())
  client:set_timeouts(5000, 1000, 5000)

  ---@type resty.http.request_uri.params
  local params = {
    method = "GET",
    headers = {},
    keepalive = true,
  }

  local data = DISCOVERY_DATA
  local payload = data and data.payload
  local last_modified = data and data.last_modified
  local stale_if_error = data and data.stale_if_error
  local try_revalidate = data and data.try_revalidate

  if payload and last_modified and try_revalidate then
    params.headers["If-Modified-Since"] = data.last_modified
  end

  local res, err = client:request_uri(DISCOVERY_URL, params)
  if err or not res then
    if stale_if_error and payload then
      log.warn("returning stale discovery data due to error")
      return payload, nil, -1
    end

    error("discovery failed: " .. tostring(err or "unknown error"))
  end

  local body = res.body

  if res.status == 304 and not (payload and try_revalidate) then
    body = body or "<empty>"
    error("discovery returned 304 when it shouldn't have: " .. body)

  elseif res.status ~= 200 then
    body = body or "<empty>"
    error("discovery returned " .. tostring(res.status) .. ": " .. body)

  elseif body == nil or #body == 0 then
    error("discovery returned empty response body")
  end

  payload = cjson.decode(body)
  if type(payload) ~= "table" then
    error("invalid discovery response body")
  end

  data = {
    payload = payload,
    last_modified = nil,
    stale_if_error = nil,
  }

  local ttl = 60

  local cc_header = res.headers["Cache-Control"]
  if cc_header then
    local cc = http.parse_cache_control(cc_header)
    data.stale_if_error = cc["stale-if-error"]
    local age = tonumber(res.headers["Age"]) or 0

    local max_age = cc["max-age"]
    local s_max_age = cc["s-maxage"]

    if     not cc["no-store"]
       and not cc["no-cache"]
       and not cc["private"]
       and not cc["must-understand"]
       and (max_age or s_max_age)
    then
      data.try_revalidate = true
      if max_age then
        ttl = max_age - age
      else
        ttl = s_max_age
      end

    else
      ttl = -1
    end
  end

  oidc.invalidate_caches()

  log.info("discovery data updated")

  DISCOVERY_DATA = data
  return payload, nil, ttl
end

---@param check_only? boolean
local function ensure_discovery(check_only)
  if check_only and type(OIDC_OPTS.discovery) == "table" then
    return true
  end

  local disc, err = cache:get(CACHE_KEY_DISCOVERY, nil, load_discovery)
  if not disc then
    log.err("failed loading OpenID discovery: ", err)
    return nil, err
  end

  OIDC_OPTS.discovery = disc
  return true
end

---@param raw_token string
---@return table? info
---@return string? error
local function load_user_info(raw_token)
  return oidc.call_userinfo_endpoint(OIDC_OPTS, raw_token)
end


---@param jwt       doorbell.auth.jwt
---@param raw_token string
---@return doorbell.config.auth.user?
local function get_user(jwt, raw_token)
  if not ensure_discovery(true) then
    return
  end

  local sub = jwt.sub
  assert(type(sub) == "string")

  local u = USERS_BY_SUB[sub]
  if u then
    return u
  end

  local cache_key = "oidc::userinfo::" .. sub
  local info, err = cache:get(cache_key, nil, load_user_info, raw_token)

  if not info then
    log.err("failed loading userinfo for ", sub, ": ", err)
    return
  end

  if info.email and info.email_verified == true then
    u = USERS_BY_EMAIL[info.email]
  end

  return u
end


---@param  raw_token string
---@return doorbell.auth.jwt? jwt
---@return string? error
---@return number? ttl
local function oidc_verify(raw_token)
  local t, err = oidc.jwt_verify(raw_token, OIDC_OPTS, VALIDATORS)

  if is_expired_err(err) then
    return nil, E_EXPIRED

  elseif err then
    return nil, E_NOT_VERIFIED
  end

  local ttl = token_ttl(t)

  if ttl < 0 then
    return nil, E_EXPIRED
  end

  return t, nil, ttl
end


---@param  raw_token string
---@return doorbell.auth.jwt? jwt
---@return string? error
local function verify_token(raw_token)
  local cache_key = "openid::token::" .. sha256(raw_token)
  local json, err = cache:get(cache_key, nil, oidc_verify, raw_token)

  if err or not json then
    return nil, err
  end

  -- need to check expiration even on a cache HIT
  if token_ttl(json) < 0 then
    return nil, E_EXPIRED
  end

  return json
end


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

    local DEBUG = ngx.DEBUG
    oidc.set_logging(function(lvl, ...)
      -- resty.openid's logging is way too chatty, even for debugging
      if lvl == DEBUG then
        return
      end
      log[lvl](...)
    end, {})

    local iss = conf.auth.openid_issuer

    assert(http.parse_url(iss), "invalid issuer url")
    iss = iss:gsub("/+$", "") .. "/"

    DISCOVERY_URL = iss .. ".well-known/openid-configuration"
    OIDC_OPTS.discovery = DISCOVERY_URL
    VALIDATORS.iss = validators.equals(iss)

    USERS = {}
    USERS_BY_SUB = {}
    USERS_BY_EMAIL = {}

    for _, u in ipairs(conf.auth.users or {}) do
      local user = { name = u.name }
      assert(USERS[u.name] == nil, "duplicate username: " .. u.name)
      USERS[u.name] = user

      for _, id in ipairs(u.identifiers or {}) do
        if id.email then
          assert(USERS_BY_EMAIL[id.email] == nil,
                 "duplicate user email: " .. id.email)

          USERS_BY_EMAIL[id.email] = user
        end

        if id.sub then
          assert(USERS_BY_SUB[id.sub] == nil,
                 "duplicate user sub: " .. id.sub)

          USERS_BY_SUB[id.sub] = user
        end
      end
    end

    CONFIGURED = true
  end
end


function _M.init_worker()
  if not CONFIGURED then return end

  if ngx.worker.id() == 0 then
    assert(ngx.timer.at(0, function(premature)
      if not premature then
        ensure_discovery()
      end
    end))
  end
end


---@param ctx doorbell.ctx
---@return doorbell.config.auth.user? user
---@return string? error
---@return ngx.http.status_code? status
local function identify(ctx)
  if DISABLED or not CONFIGURED then
    return nil, E_INTERNAL, 500
  end

  ensure_discovery()

  local token, err, status = get_access_token(ctx)
  if not token then
    return nil, err, status
  end

  local jwt
  jwt, err = verify_token(token)
  if err or not jwt then
    if is_expired_err(err) then
      return nil, E_EXPIRED, 401

    else
      return nil, err, 403
    end
  end

  ctx.jwt = jwt
  local user = get_user(jwt, token)

  if not user then
    return nil, E_NO_SUCH_USER, 403
  end

  ctx.user = user
  return user
end


_M.identify = identify


---@param ctx doorbell.ctx
---@param route doorbell.route
function _M.auth_middleware(ctx, route)
  if DISABLED then
    return

  elseif not CONFIGURED then
    log.alert("got request to OpenID endpoint (", route.id, "), but auth is not enabled")
    return http.send(500, { error = "an unexpected error has occurred" })
  end

  local user, err, status = identify(ctx)

  if route.auth_required == false or ctx.method == "OPTIONS" then
    return

  elseif not user then
    return http.send(status, { error = err })
  end
end

return _M
