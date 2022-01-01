local _M = {
  _VERSION = "0.1.0",
}

local ngx = ngx
local var = ngx.var
local log = ngx.log
local WARN = ngx.WARN
local ERR = ngx.ERR
local DEBUG = ngx.DEBUG
local NOTICE = ngx.NOTICE
local fmt = string.format
local now = ngx.now
local sleep = ngx.sleep

local resty_lock = require "resty.lock"
local random = require "resty.random"
local pushover = require "resty.pushover"
local cjson = require "cjson"
local ipmatcher = require "resty.ipmatcher"

local cache
do
  local lru = require "resty.lrucache"
  cache = assert(lru.new(1000))
end

local EMPTY = {}

---@type resty.pushover.client.opts
local PUSHOVER_OPTS

---@type string
local SHM_NAME = "doorbell"

local BASE_URL

local ALLOW
local DENY

---@type ngx.shared.DICT
local SHM

---@alias doorbell.auth_state
---| '"allow"'   # allowed
---| '"deny"'    # explicitly denied
---| '"pending"' # awaiting approval
---| '"none"'    # never seen this IP before
---| '"error"'   # something's wrong

local STATES = {
  allow      = "allow",
  deny       = "deny",
  pending    = "pending",
  none       = "none",
  error      = "error",
}

local WAIT_TIME = 60
local TTL
do
  local minute = 60
  local hour = 60 * minute
  local day = hour * 24
  local week = day * 7

  TTL = {
    [STATES.allow]   = day,
    [STATES.deny]    = week,
    [STATES.pending] = minute * 5,
  }
end

---@param addr string
---@return doorbell.auth_state state
---@return string? error
local function get_auth_state(addr)
  local key = "auth:" .. addr
  local state, err = SHM:get(key)
  if state == nil then
    state = STATES.none
    if err then
      log(ERR, fmt("shm:get(%s) returned error: %s", key, err))
      state = STATES.error
    end
  elseif not STATES[state] then
    log(ERR, fmt("shm:get(%s) returned invalid state: %s", key, state))
    state = STATES.error
  end

  return state
end

---@param addr string
---@return string? token
---@return string? error
local function generate_request_token(addr)
  local bytes = random.bytes(32, true)
  local token = ngx.escape_uri(ngx.encode_base64(bytes))
  local key = "token:" .. token
  local ok, err = SHM:safe_set(key, addr, TTL.pending)
  if not ok then
    return nil, err
  end
  return token
end

---@param token string
---@return string? addr
---@return string? error
local function get_token_address(token)
  local key = "token:" .. token
  return SHM:get(key)
end

---@param addr string
---@param state doorbell.auth_state
---@return boolean ok
local function set_auth_state(addr, state)
  assert(STATES[state], "invalid state: " .. state)

  -- populate the LRU cache as well
  if state == STATES.allow or state == STATES.deny then
    cache:set(addr, state, TTL[state])
  end

  return SHM:safe_set("auth:" .. addr, state, TTL[state])
end

---@param addr string
---@return resty.lock? lock
---@return string? error
local function lock_addr(addr)
  local lock, err = resty_lock:new(SHM_NAME)
  if not lock then
    log(ERR, "failed to create lock: ", err)
    return nil, err
  end

  local elapsed
  elapsed, err = lock:lock("lock:" .. addr)
  if not elapsed then
    log(ERR, "failed to lock auth state for ", addr)
    return nil, err
  end

  return lock
end

local function await_allow(addr)
  local start = now()
  while (now() - start) < WAIT_TIME do
    local state = get_auth_state(addr)
    if state == STATES.allow then
      return true
    elseif state == STATES.deny then
      return false
    end
    sleep(1)
  end

  return false
end


---@param addr string
---@return boolean
local function request_auth(addr)
  local lock, err = lock_addr(addr)
  if not lock then
    return nil, err
  end

  local state
  state, err = get_auth_state(addr)
  if state == STATES.allow then
    log(DEBUG, "acccess for ", addr, " was allowed before requesting it")
    lock:unlock()
    return true
  elseif state == STATES.deny then
    log(NOTICE, "access was denied for ", addr, " before requesting it")
    lock:unlock()
    return false
  end

  local po
  po, err = pushover.new(PUSHOVER_OPTS)
  if not po then
    log(ERR, "failed creating pushover client: ", err)
    lock:unlock()
    return false
  end

  local token
  token, err = generate_request_token(addr)
  if not token then
    log(ERR, "failed creating auth request token for ", addr, ": ", err)
    lock:unlock()
    return false
  end

  local base_url = BASE_URL or ("https://" .. (var.http_x_forwarded_host or var.host))

  local approve_url = fmt("%s/answer?t=%s&intent=approve", base_url, token)
  local deny_url = fmt("%s/answer?t=%s&intent=deny", base_url, token)

  local request = fmt(
    "%s %s://%s%s",
    var.http_x_forwarded_method,
    var.http_x_forwarded_proto,
    var.http_x_forwarded_host,
    var.http_x_forwarded_uri
  )

  local message = fmt(
    [[
      IP address: %s
      User-Agent: %s
      Request: %s

      * <a href="%s">click to approve</a>

      * <a href="%s">click to deny</a>
    ]],
    addr,
    var.http_user_agent or "<NONE>",
    request,
    approve_url,
    deny_url
  )


  local ok, res
  ok, err, res = po:notify({
    title = "access requested for " .. addr,
    message = message,
    html = true,
  })

  if res then
    log(DEBUG, "pushover notify response: ", cjson.encode(res))
  end

  if not ok then
    log(ERR, "failed sending auth request: ", err)
    lock:unlock()
    return false
  end

  set_auth_state(addr, STATES.pending)
  lock:unlock()

  return await_allow(addr)
end

---@param addr string
---@param token string
---@param intent '"approve"'|'"deny"'
local function approve_or_deny(addr, token, intent)
  if not intent then
    log(ERR, "received request with no intent")
    return ngx.exit(ngx.HTTP_BAD_REQUEST)
  end

  if not (intent == "approve" or intent == "deny") then
    log(ERR, "received invalid intent (", intent, ")")
  end

  local lock, err = lock_addr(addr)
  if not lock then
    log(ERR, "failed locking ", addr, " for update: ", err)
    return ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
  end

  local ok
  local state = (intent == "approve" and STATES.allow) or STATES.deny
  ok, err = set_auth_state(addr, state)
  if ok then
    SHM:delete("token:" .. token)
  end

  lock:unlock()

  if not ok then
    log(ERR, "failed updating ", addr, " auth state to ", state, ": ", err)
    return ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
  end

  ngx.header["content-type"] = "text/plain"
  ngx.say("success")
  return ngx.exit(ngx.HTTP_OK)
end

---@alias doorbell.handler fun(addr:string)

---@type table<doorbell.auth_state, doorbell.handler>
local HANDLERS = {
  [STATES.allow] = function(addr)
    log(DEBUG, "allowing access for ", addr)
    return ngx.exit(ngx.HTTP_OK)
  end,

  [STATES.deny] = function(addr)
    log(NOTICE, "denying access for ", addr)
    return ngx.exit(ngx.HTTP_FORBIDDEN)
  end,

  [STATES.none] = function(addr)
    log(NOTICE, "requesting access for ", addr)
    if request_auth(addr) then
      log(NOTICE, "access approved for ", addr)
      return ngx.exit(ngx.HTTP_OK)
    end
    return ngx.exit(ngx.HTTP_UNAUTHORIZED)
  end,

  [STATES.pending] = function(addr)
    log(NOTICE, "awaiting access for ", addr)
    if await_allow(addr) then
      return ngx.exit(ngx.HTTP_OK)
    end
    return ngx.exit(ngx.HTTP_UNAUTHORIZED)
  end,

  [STATES.error] = function(addr)
    log(ERR, "something went wrong while checking auth for ", addr)
    return ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
  end,
}

---@class doorbell.init.opts : table
---@field shm      string
---@field base_url string
---@field allow    string[]
---@field deny     string[]
---@field pushover resty.pushover.client.opts

---@param opts doorbell.init.opts
function _M.init(opts)
  opts = opts or EMPTY
  SHM_NAME = opts.shm or SHM_NAME

  SHM = assert(ngx.shared[SHM_NAME], "missing shm " .. SHM_NAME)

  PUSHOVER_OPTS = opts.pushover or EMPTY

  BASE_URL = opts.base_url

  ALLOW = assert(ipmatcher.new(opts.allow or EMPTY))
  DENY = assert(ipmatcher.new(opts.deny or EMPTY))
end

function _M.ring()
  assert(SHM, "doorbell was not initialized")

  local addr = var.http_x_forwarded_for
  if not addr then
    log(WARN, "X-Forwarded-For header missing; using client IP")
    addr = var.remote_addr
  end

  local res = cache:get(addr)
  if res == STATES.allow then
    log(DEBUG, "cache HIT for ", addr, " => allowed")
    return ngx.exit(ngx.HTTP_OK)
  elseif res == STATES.deny then
    log(DEBUG, "cache HIT for ", addr, " => denied")
    return ngx.exit(ngx.HTTP_FORBIDDEN)
  end

  if ALLOW:match(addr) then
    log(DEBUG, "access for ", addr, " allowed from config")
    cache:set(addr, STATES.allow)
    return ngx.exit(ngx.HTTP_OK)
  elseif DENY:match(addr) then
    log(DEBUG, "access for ", addr, " denied from config")
    cache:set(addr, STATES.deny)
    return ngx.exit(ngx.HTTP_FORBIDDEN)
  end

  local state = get_auth_state(addr)
  local handler = HANDLERS[state]
  return handler(addr)
end

function _M.answer()
  assert(SHM, "doorbell was not initialized")
  local intent = var.arg_intent

  if not (intent == "approve" or intent == "deny") then
    log(NOTICE, "received request with invalid intent: ", intent or "<NONE>")
    return ngx.exit(ngx.HTTP_NOT_FOUND)
  end

  local t = var.arg_t
  if not t then
    log(NOTICE, "/answer accessed with no token")
    return ngx.exit(ngx.HTTP_NOT_FOUND)
  end

  local addr = get_token_address(t)

  if not addr then
    log(NOTICE, "/answer token ", t, " not found")
    return ngx.exit(ngx.HTTP_NOT_FOUND)
  end

  return approve_or_deny(addr, t, intent)
end

return _M
