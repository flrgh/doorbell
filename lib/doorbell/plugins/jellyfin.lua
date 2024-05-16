local http = require "resty.http"
local timer = require "doorbell.util.timer"
local const = require "doorbell.constants"
local util = require "doorbell.util"
local rules = require "doorbell.rules.api"
local shm = require "doorbell.shm"
local ring = require "doorbell.auth.ring"
local router = require "doorbell.router"
local middleware = require "doorbell.middleware"
local cjson = require "cjson.safe"

local get_header = require("doorbell.request").get_header
local sha256 = util.sha256
local lower = string.lower
local re_find = ngx.re.find
local re_match = ngx.re.match
local fmt = string.format
local decode_args = ngx.decode_args
local find = string.find
local sub = string.sub

---@class doorbell.plugin.jellyfin
local _M = {
  name = "jellyfin",
}

local log = require("doorbell.log").with_namespace(_M.name)

---@class doorbell.config.plugin.jellyfin
---
---@field url        string # jellyfin address
---@field api?       string # jellyfin API address (derived from `url` if not set)
---@field allow_ttl? integer

local STATES = const.states
local SHM = shm.with_namespace(shm.plugins, "jf")

---@type string
local HOST

---@type string
local API_URL

local ALLOW_TTL = 60 * 60

local LOGIN_PATH = "/users/authenticatebyname"
local LOGOUT_PATH = "/sessions/logout"
local AUTH_QUERY_PARAM = lower("api_key")
local AUTH_SELF = "/Users/Me"
local AUTH_SELF_HEADER = "X-Emby-Token"
local AUTH_CHECK_URL
local UNKNOWN = "<unknown>"

local TOKEN_RE = [=[Token=['"]([^'"]+)['"]]=]
do
  local _, _, err = re_find("nope", TOKEN_RE)
  assert(err == nil, err)
end



local function check_jellyfin_token(token)
  local client = assert(http.new())
  local res, err = client:request_uri(AUTH_CHECK_URL, {
    headers = {
      [AUTH_SELF_HEADER] = token,
    },
  })

  if err then
    return nil, err

  elseif res.status == 200 then
    if not res.body then
      return true
    end

    local json
    json, err = cjson.decode(res.body)
    if not json then
      log.warn("`GET /Users/Me` returned invalid json: ", err)
      return true
    end

    return json.Name or json.name or true

  else
    return false, nil, 5
  end
end

---@param token string
---@return string
local function auth_cache_key(token)
  return "doorbell.auth_token." .. sha256(token)
end

---@param token string
---@return boolean
local function validate_auth(token)
  local cache = require("doorbell.cache.shared")
  local cache_key = auth_cache_key(token)

  return cache:get(cache_key, nil, check_jellyfin_token, token)
end

---@param token string
local function invalidate_auth(token)
  local cache = require("doorbell.cache.shared")
  local cache_key = auth_cache_key(token)

  local user = cache:get(cache_key)
  if user == true then
    user = UNKNOWN
  end

  if user then
    log.infof("user %q is logging out", user)
  end

  assert(cache:delete(cache_key))
end

local is_public_path
do
  ---@type table<string, true>
  local plain_paths = {}

  for _, p in ipairs({
      "/",
      "/branding/configuration",
      "/branding/css",
      "/quickconnect/enabled",
      "/system/info/public",
      "/trickplay/clientscript",
      "/users/public",
      "/web/config.json",
      "/web/index.html",
      "/web/main.jellyfin.bundle.js",
      "/web/themes/dark/theme.css",
    })
  do
    plain_paths[lower(p)] = true
  end

  local regex_paths = {
    "^/users/[a-f0-9]{32}/images/primary$",
    "^/web/.+[.](png|ico|jpe?g|woff2|css|js)$",
  }

  local n_regex_paths = #regex_paths

  ---@param path string
  ---@return boolean
  function is_public_path(path)
    if plain_paths[path] then
      return true
    end

    for i = 1, n_regex_paths do
      if re_find(path, regex_paths[i], "oj") then
        return true
      end
    end

    return false
  end
end

---@param req doorbell.forwarded_request
---@param ctx doorbell.ctx
---@return string?
local function get_auth(req, ctx)
  -- X-Mediabrowser-Token header
  do
    local header = get_header(ctx, "X-Mediabrowser-Token")
    if header then
      return header
    end
  end

  -- X-Emby-Authorization header
  -- Authorization header
  do
    local header = get_header(ctx, "X-Emby-Authorization")
                or get_header(ctx, "Authorization")
    if header then
      local m = re_match(header, TOKEN_RE, "oj")
      if m and m[1] then
        return m[1]
      end
    end
  end

  -- api_key query param
  do
    local uri = req.uri
    local pos = find(uri, "?", nil, true)
    if not pos then
      return
    end

    local query = sub(uri, pos + 1)
    local args = decode_args(query, 100)
    if not args then
      return
    end

    local api_key = args[AUTH_QUERY_PARAM]
    if api_key then
      return api_key
    end

    for name, value in pairs(args) do
      if lower(name) == AUTH_QUERY_PARAM then
        return value
      end
    end
  end
end


---@param req doorbell.forwarded_request
---@param ctx doorbell.ctx
---@param state doorbell.auth.access.state
---@return doorbell.auth.access.state|nil
local function ring_hook(req, ctx, state)
  local host = lower(req.host)

  if host ~= HOST then
    return
  end

  if state == STATES.deny then
    return state
  end

  local path = lower(req.path)
  local auth = get_auth(req, ctx)

  if path == LOGOUT_PATH and req.method == "POST" then
    if auth then
      invalidate_auth(auth)
    end

    return STATES.allow
  end

  if auth then
    local user = validate_auth(auth)
    if user then
      ctx.plugin.jellyfin_authenticated_user = user
      return STATES.allow
    end
  end

  if is_public_path(path) then
    return STATES.allow
  end

  if path == LOGIN_PATH then
    log.debug("new login attempt from ", req.addr)
    return
  end
end


local function timer_handler()
  local existing = {}

  for _, rule in ipairs(rules.list()) do
    if rule.host == HOST
      and rule.source == "plugin"
      and rule.plugin == "jellyfin"
      and rule.addr
      and rule.comment
      and rule.comment:find("jellyfin")
    then
      existing[rule.addr] = true
    end
  end

  local seen = {}

  while true do
    local addr, err = SHM:lpop("addrs")

    if err then
      log.err("failed checking for new queue items: ", err)
      break

    elseif not addr then
      break
    end

    local user = SHM:get(addr) or UNKNOWN
    SHM:delete(addr)

    if seen[addr] then
      goto continue
    end

    seen[addr] = true
    if existing[addr] then
      goto continue
    end

    local rule
    rule, err = rules.insert({
      addr = addr,
      host = HOST,
      ttl  = ALLOW_TTL,
      action = "allow",
      source = "plugin",
      plugin = "jellyfin",
      comment = fmt("allowed via jellyfin plugin for user %q", user),
    })

    if rule then
      log.infof("created 'allow' rule for user %q with addr: %s",
                user, addr)
    else
      log.errf("failed adding allow rule for %s: %s", addr, err)
    end

    ::continue::
  end

  SHM:delete("timer")
end


---@param ctx doorbell.ctx
local function log_handler(ctx)
  local user = ctx.plugin.jellyfin_authenticated_user
  if not user then
    return
  end

  local addr = ctx.forwarded_request.addr

  if user == true then
    user = UNKNOWN
  end

  local added, err = SHM:add(addr, user, 60)
  if added then
    assert(SHM:rpush("addrs", addr))

    if SHM:add("timer", 1) then
      timer.at(0, "jellyfin", timer_handler)
    end

  elseif err ~= "exists" then
    log.err("unexpected error recording valid auth token address: ", err)
  end
end


---@param conf doorbell.config.plugin.jellyfin
function _M.init(conf)
  assert(type(conf.url) == "string", "Jellyfin `url` is required")

  assert(conf.api == nil or type(conf.api) == "string",
         "Jellyfin API url must be a string (if set)")

  do
    local parsed = assert(http:parse_uri(conf.url), "Jellyfin URL is invalid")
    HOST = lower(parsed[2])
  end

  if conf.api then
    assert(http:parse_uri(conf.api), "Jellyfin API address is invalid")
    API_URL = conf.api
  else
    API_URL = conf.url
  end

  AUTH_CHECK_URL = API_URL .. AUTH_SELF

  assert(conf.allow_ttl == nil or type(conf.allow_ttl) == "number",
         "invalid allow_ttl")

  ALLOW_TTL = conf.allow_ttl or ALLOW_TTL

  ring.add_hook("jellyfin", ring_hook)
  router.add_middleware(ring, middleware.phase.LOG, log_handler)

  -- TODO: jellyfin server webhook
end


return _M
