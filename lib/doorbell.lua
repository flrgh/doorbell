local _M = {
  _VERSION = "0.1.0",
}

local ngx = ngx
local var = ngx.var

local now = ngx.now
local sleep = ngx.sleep

local re_find = ngx.re.find

local log    = ngx.log
local WARN   = ngx.WARN
local ERR    = ngx.ERR
local DEBUG  = ngx.DEBUG
local NOTICE = ngx.NOTICE

local exit = ngx.exit
local HTTP_OK                    = ngx.HTTP_OK
local HTTP_FORBIDDEN             = ngx.HTTP_FORBIDDEN
local HTTP_UNAUTHORIZED          = ngx.HTTP_UNAUTHORIZED
local HTTP_INTERNAL_SERVER_ERROR = ngx.HTTP_INTERNAL_SERVER_ERROR
local HTTP_CREATED               = ngx.HTTP_CREATED
local HTTP_BAD_REQUEST           = ngx.HTTP_BAD_REQUEST
local HTTP_NOT_FOUND             = ngx.HTTP_NOT_FOUND

local read_body = ngx.req.read_body
local get_post_args = ngx.req.get_post_args

local fmt = string.format

local intent     = require "doorbell.intent"

local cjson      = require "cjson"
local ipmatcher  = require "resty.ipmatcher"
local pushover   = require "resty.pushover"
local random     = require "resty.random"
local resty_lock = require "resty.lock"
local template   = require "resty.template"

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

local IP
local TRUSTED

local BASE_URL, HOST

---@type ngx.shared.DICT
local SHM

local PATHS = {
  plain = {},
  regex = {}
}

---@class doorbell.request : table
---@field addr string
---@field scheme string
---@field host string
---@field uri string
---@field path string
---@field method string
---@field ua string

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

---@alias doorbell.action '"allow"'|'"deny"'

---@class doorbell.intent
---@field action  doorbell.action
---@field addr    string
---@field host?   string
---@field path?   string
---@field created number
---@field expires number


local WAIT_TIME = 60
local TTL
local PERIODS = {}
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

  PERIODS.minute = minute
  PERIODS.hour = hour
  PERIODS.day  = day
  PERIODS.week = week
  PERIODS.forever = 0
end

local CACHED = {
  [STATES.allow] = true,
  [STATES.deny] = true,
}

local UNDEFINED = {
  [STATES.none] = true,
  [STATES.error] = true,
}

local DEFAULT_TTL = 60

local function store_cache(req, value, global, ttl)
  local cache_key
  if global then
    cache_key = req.addr
  else
    cache_key = req.addr .. ":" .. req.host .. ":" .. req.path
  end

  if ttl == nil then
    ttl = DEFAULT_TTL
  elseif ttl == 0 then
    ttl = nil
  end
  cache:set(cache_key, value, ttl)
end

local function is_pending(addr)
  return SHM:get("pending:" .. addr)
end

local function set_pending(addr, pending)
  local key = "pending:" .. addr
  if pending then
    assert(SHM:delete(key))
  else
    assert(SHM:safe_set(key, true, TTL.pending))
  end
end

---@param req doorbell.request
---@return doorbell.auth_state state
---@return string? error
local function get_auth_state(req)
  local cache_key = req.addr
  local res = cache:get(cache_key)

  if not res then
    cache_key = req.addr .. ":" .. req.host .. ":" .. req.path
    res = cache:get(cache_key)
  end

  if res then
    log(DEBUG, "cache HIT for ", cache_key, " => ", res)
    return res
  end

  local int, err, global, ttl = intent.get(req.addr, req.host, req.path)
  if err then
    log(ERR, "intent.get() returned error: ", err)
    return STATES.error
  end

  if int == nil then
    if is_pending(req.addr) then
      return STATES.pending
    end
    return STATES.none
  end

  if ttl and ttl <= 0 then
    log(WARN, "intent EXPIRE for ", cache_key, " => ", int)
    return STATES.none
  end

  if CACHED[int] then
    store_cache(req, int, global, ttl)
  end

  return int
end

---@param req doorbell.request
---@return string? token
---@return string? error
local function generate_request_token(req)
  local bytes = random.bytes(32, true)
  local token = ngx.escape_uri(ngx.encode_base64(bytes))
  local key = "token:" .. token
  local value = cjson.encode(req)
  local ok, err = SHM:safe_set(key, value, TTL.pending)
  if not ok then
    return nil, err
  end
  return token
end

---@param token string
---@return doorbell.request req
---@return string? error
local function get_token_address(token)
  local key = "token:" .. token
  local v = SHM:get(key)
  if v then
    return cjson.decode(v)
  end
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

---@param req doorbell.request
local function await_allow(req)
  local start = now()
  while (now() - start) < WAIT_TIME do
    local state = get_auth_state(req)
    if state == STATES.allow then
      return true
    elseif state == STATES.deny then
      return false
    end
    sleep(1)
  end

  return false
end


---@param req doorbell.request
---@return boolean
local function request_auth(req)
  local addr = req.addr
  local lock, err = lock_addr(addr)
  if not lock then
    return nil, err
  end

  local state
  state, err = get_auth_state(req)
  if state == STATES.allow then
    log(DEBUG, "acccess for ", addr, " was allowed before requesting it")
    lock:unlock()
    return true
  elseif state == STATES.deny then
    log(NOTICE, "access was denied for ", addr, " before requesting it")
    lock:unlock()
    return false
  elseif state == STATES.pending then
    log(NOTICE, "access for ", addr, " is already waiting on a pending request")
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
  token, err = generate_request_token(req)
  if not token then
    log(ERR, "failed creating auth request token for ", addr, ": ", err)
    lock:unlock()
    return false
  end


  local request = fmt(
    "%s %s://%s%s",
    req.method,
    req.scheme,
    req.host,
    req.uri
  )

  local message = fmt(
    [[
      IP address: %s
      User-Agent: %s
      Request: %s
    ]],
    addr,
    req.ua or "<NONE>",
    request
  )


  local ok, res
  ok, err, res = po:notify({
    title = "access requested for " .. addr,
    message = message,
    monospace = true,
    url = fmt("%s/answer?t=%s", BASE_URL, token),
    url_title = "approve or deny",
  })

  if res then
    log(DEBUG, "pushover notify response: ", cjson.encode(res))
  end

  if not ok then
    log(ERR, "failed sending auth request: ", err)
    lock:unlock()
    return false
  end

  set_pending(addr, true)
  lock:unlock()

  return await_allow(req)
end

---@param addr string
---@param token string
---@param intent '"approve"'|'"deny"'
local function approve_or_deny(addr, token, intent)
  if not intent then
    log(ERR, "received request with no intent")
    return exit(HTTP_BAD_REQUEST)
  end

  if not (intent == "approve" or intent == "deny") then
    log(ERR, "received invalid intent (", intent, ")")
  end

  local lock, err = lock_addr(addr)
  if not lock then
    log(ERR, "failed locking ", addr, " for update: ", err)
    return exit(HTTP_INTERNAL_SERVER_ERROR)
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
    return exit(HTTP_INTERNAL_SERVER_ERROR)
  end

  ngx.header["content-type"] = "text/plain"
  ngx.say("success")
  return exit(HTTP_OK)
end

---@alias doorbell.handler fun(req:doorbell.request)

---@type table<doorbell.auth_state, doorbell.handler>
local HANDLERS = {
  [STATES.allow] = function(req)
    log(DEBUG, "allowing access for ", req.addr)
    return exit(HTTP_OK)
  end,

  [STATES.deny] = function(req)
    log(NOTICE, "denying access for ", req.addr)
    return exit(HTTP_FORBIDDEN)
  end,

  [STATES.none] = function(req)
    log(NOTICE, "requesting access for ", req.addr)
    if request_auth(req) then
      log(NOTICE, "access approved for ", req.addr)
      return exit(HTTP_OK)
    end
    return exit(HTTP_UNAUTHORIZED)
  end,

  [STATES.pending] = function(req)
    log(NOTICE, "awaiting access for ", req.addr)
    if await_allow(req) then
      return exit(HTTP_OK)
    end
    return exit(HTTP_UNAUTHORIZED)
  end,

  [STATES.error] = function(req)
    log(ERR, "something went wrong while checking auth for ", req.addr)
    return exit(HTTP_INTERNAL_SERVER_ERROR)
  end,
}

local function require_trusted_ip()
  local ip = assert(var.realip_remote_addr, "no $realip_remote_addr")
  local key = "trusted:" .. ip
  local trusted = cache:get(key)
  if trusted == nil then
    trusted = TRUSTED:match(ip) or false
    cache:set(key, trusted)
  end

  if not trusted then
    log(WARN, "denying connection from untrusted IP: ", ip)
    return exit(HTTP_FORBIDDEN)
  end
end

---@class doorbell.path
---@field path? string
---@field pattern? string
---@field action '"allow"'|'"deny"'

---@class doorbell.init.opts : table
---@field shm      string
---@field base_url string
---@field allow    string[]
---@field deny     string[]
---@field trusted  string[]
---@field pushover resty.pushover.client.opts
---@field paths    doorbell.path[]

---@param opts doorbell.init.opts
function _M.init(opts)
  opts = opts or EMPTY
  SHM_NAME = opts.shm or SHM_NAME

  SHM = assert(ngx.shared[SHM_NAME], "missing shm " .. SHM_NAME)
  intent.init(SHM_NAME)

  PUSHOVER_OPTS = assert(opts.pushover, "missing pushover API config")

  BASE_URL = assert(opts.base_url, "opts.base_url required")
  local m = ngx.re.match(BASE_URL, "^(http(s)://)?(?<host>[^/]+)")
  assert(m and m.host, "failed to parse hostname from base_url: " .. BASE_URL)
  HOST = m.host:lower()

  log(DEBUG, "doorbell BASE_URL: ", BASE_URL, ", HOST: ", HOST)

  local ips = {}
  for _, ip in ipairs(opts.allow or EMPTY) do
    log(DEBUG, "IP allow: ", ip)
    ips[ip] = "allow"
  end

  for _, ip in ipairs(opts.deny or EMPTY) do
    log(DEBUG, "IP deny: ", ip)
    ips[ip] = "deny"
  end

  IP = assert(ipmatcher.new_with_value(ips))

  TRUSTED = assert(ipmatcher.new(opts.trusted or EMPTY))

  for _, p in ipairs(opts.paths or EMPTY) do
    if p.pattern then
      table.insert(PATHS.regex, p)
    elseif p.path then
      PATHS.plain[p.path] = p.action
    else
      error("invalid config path")
    end
  end
end

function _M.ring()
  assert(SHM, "doorbell was not initialized")
  require_trusted_ip()

  ---@type doorbell.request
  local req = {
    addr    = var.http_x_forwarded_for,
    scheme  = var.http_x_forwarded_proto,
    host    = var.http_x_forwarded_host,
    uri     = var.http_x_forwarded_uri,
    method  = var.http_x_forwarded_method,
    ua      = var.http_user_agent,
  }

  req.path = req.uri:gsub("?.*", "")
  local addr = req.addr

  if req.host == HOST and req.path == "/answer" then
    log(DEBUG, "allowing request to ", HOST, "/answer endpoint")
    return exit(HTTP_OK)
  end

  local state
  local path = req.path
  state = PATHS.plain[path] or STATES.none

  if UNDEFINED[state] then
    state = get_auth_state(req)
  end

  if UNDEFINED[state] then
    local reg = PATHS.regex
    for i = 1, #reg do
      local p = reg[i]
      if re_find(path, p.pattern, "oj") then
        state = p.action
        store_cache(req, state)
      end
    end
  end

  if UNDEFINED[state] then
    local ip = IP:match(addr)
    if ip == "allow" then
      state = STATES.allow
      log(DEBUG, "access for ", addr, " allowed from config")
      store_cache(req, state, true, 0)

    elseif ip == "deny" then
      state = STATES.deny
      log(DEBUG, "access for ", addr, " denied from config")
      store_cache(req, state, true, 0)
    end
  end


  return HANDLERS[state](req)
end

local function render_form(req, err)
  local tpl = [[
    <!DOCTYPE html>
    <html>
      <h1>Access Request</h1>
      <body>
        {% if err then %}
        <h2>ERROR: {{err}}</h2>
        {% end %}
        <ul>
          <li>IP: {{req.addr}}</li>
          <li>User-Agent: {{req.ua}}</li>
          <li>Request: {{req.method}} {{req.url}}</li>
        </ul>
        <br>
        <form action="" method="post">
          <ul>
            <li>
              <input type="radio" id="approve" name="action" value="approve">
              <label for="approve">approve</label><br>

              <input type="radio" id="deny" name="action" value="deny">
              <label for="deny">deny</label><br>
            </li>

            <li>
              <input type="radio" id="global" name="scope" value="global">
              <label for="global">global (all apps)</label><br>

              <input type="radio" id="host" name="scope" value="host">
              <label for="host">this app ({{req.host}})</label><br>

              <input type="radio" id="url" name="scope" value="url">
              <label for="url">this URL ({{req.url}})</label><br>
            </li>

            <li>
              <input type="radio" id="minute" name="period" value="minute">
              <label for="minute">1 minute</label><br>

              <input type="radio" id="hour" name="period" value="hour">
              <label for="hour">1 hour</label><br>

              <input type="radio" id="day" name="period" value="day">
              <label for="day">1 day</label><br>

              <input type="radio" id="week" name="period" value="week">
              <label for="week">1 week</label><br>

              <input type="radio" id="forever" name="period" value="forever">
              <label for="forever">forever</label><br>
            </li>

          </ul>
          <button type="submit">submit</button>
        </form>
      </body>
    </html>
  ]]

  return template.render(tpl, {req = req, err = err })
end

local SCOPES = {
  global = "global",
  host = "host",
  url = "url",
}

function _M.answer()
  assert(SHM, "doorbell was not initialized")
  require_trusted_ip()

  local t = var.arg_t
  if not t then
    log(NOTICE, "/answer accessed with no token")
    return exit(HTTP_NOT_FOUND)
  end

  local req = get_token_address(t)

  if not req then
    log(NOTICE, "/answer token ", t, " not found")
    return exit(HTTP_NOT_FOUND)
  end

  req.url = req.scheme .. "://" .. req.host .. req.uri

  local method = ngx.req.get_method()
  if not (method == "GET" or method == "POST") then
    exit(HTTP_BAD_REQUEST)
  end

  if method == "GET" then
    ngx.header["content-type"] = "text/html"
    ngx.print(render_form(req))
    return exit(HTTP_OK)
  end

  read_body()
  local args = get_post_args()
  local action = args.action or "NONE"
  local scope = args.scope or "NONE"
  local period = args.period or "NONE"

  local err

  if not (action == "approve" or action == "deny") then
    err = "invalid action: " .. tostring(action)
  elseif not SCOPES[scope] then
    err = "invalid scope: " .. tostring(scope)
  elseif not PERIODS[period] then
    err = "invalid period: " .. tostring(period)
  end

  if err then
    ngx.header["content-type"] = "text/html"
    ngx.print(render_form(req, err))
    return exit(HTTP_BAD_REQUEST)
  end

  local host, path = req.host, req.path
  if scope == SCOPES.global then
    host = "*"
    path = "*"
  elseif scope == SCOPES.host then
    path = "*"
  end

  if action == "approve" then
    assert(intent.allow(req.addr, host, path, PERIODS[period]))
  else
    assert(intent.deny(req.addr, host, path, PERIODS[period]))
  end

  set_pending(req.addr, false)

  local msg = fmt(
    "%s access for %s to %s %s",
    (action == "approve" and "Approved") or "Denied",
    req.addr,
    (scope == SCOPES.global and "all apps.") or (scope == SCOPES.host and req.host) or req.url,
    (PERIODS[period] == PERIODS.forever and "for all time") or ("for one " .. period)
  )

  ngx.header["content-type"] = "text/plain"
  ngx.say(msg)
  return exit(HTTP_CREATED)
end

return _M
