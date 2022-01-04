local _M = {
  _VERSION = "0.1.0",
}

local ngx = ngx
local var = ngx.var
local header = ngx.header
local now = ngx.now
local sleep = ngx.sleep

local exit = ngx.exit
local HTTP_OK                    = ngx.HTTP_OK
local HTTP_FORBIDDEN             = ngx.HTTP_FORBIDDEN
local HTTP_UNAUTHORIZED          = ngx.HTTP_UNAUTHORIZED
local HTTP_INTERNAL_SERVER_ERROR = ngx.HTTP_INTERNAL_SERVER_ERROR
local HTTP_CREATED               = ngx.HTTP_CREATED
local HTTP_BAD_REQUEST           = ngx.HTTP_BAD_REQUEST
local HTTP_NOT_FOUND             = ngx.HTTP_NOT_FOUND
local HTTP_NOT_ALLOWED           = ngx.HTTP_NOT_ALLOWED

local read_body     = ngx.req.read_body
local get_post_args = ngx.req.get_post_args
local get_headers   = ngx.req.get_headers
local http_version  = ngx.req.http_version
local start_time    = ngx.req.start_time
local get_resp_headers = ngx.resp.get_headers
local get_method = ngx.req.get_method
local get_uri_args = ngx.req.get_uri_args

local fmt = string.format

local rules = require "doorbell.rules"
local const = require "doorbell.constants"
local log   = require "doorbell.log"
local metrics = require "doorbell.metrics"

local cjson      = require "cjson"
local ipmatcher  = require "resty.ipmatcher"
local pushover   = require "resty.pushover"
local random     = require "resty.random"
local resty_lock = require "resty.lock"
local template   = require "resty.template"
local str        = require "resty.string"

local cache
do
  local lru = require "resty.lrucache"
  cache = assert(lru.new(1000))
end

local EMPTY = {}

---@type string
local SAVE_PATH

---@type string
local LOG_PATH

---@type resty.pushover.client.opts
local PUSHOVER_OPTS

---@type string
local SHM_NAME = const.shm.doorbell

---@type resty.ipmatcher
local TRUSTED

local BASE_URL, HOST

---@type ngx.shared.DICT
local SHM

---@class doorbell.request : table
---@field addr string
---@field scheme string
---@field host string
---@field uri string
---@field path string
---@field method string
---@field ua string

local STATES      = const.states
local SCOPES      = const.scopes
local SUBJECTS    = const.subjects
local WAIT_TIME   = const.wait_time
local TTL_PENDING = const.ttl.pending
local PERIODS     = const.periods

---@type doorbell.notify_period[]
local NOTIFY_PERIODS = {
  -- UTC
  { from = 15, to = 24 },
  { from = 00, to = 07 },
}

---@return boolean
local function in_notify_period()
  --    1234567890123456789
  local yyyy_mm_dd_hh_mm_ss = ngx.utctime()
  local hours = tonumber(yyyy_mm_dd_hh_mm_ss:sub(12, 13))

  for _, p in ipairs(NOTIFY_PERIODS) do
    if hours >= p.from and hours < p.to then
      return true
    end
  end

  return false
end

---@class doorbell.notify_period : table
---@field from integer
---@field to integer


---@param addr string
---@return boolean
local function is_pending(addr)
  return SHM:get("pending:" .. addr)
end

---@param addr string
---@param pending boolean
local function set_pending(addr, pending)
  local key = "pending:" .. addr
  if not pending then
    assert(SHM:delete(key))
  else
    assert(SHM:safe_set(key, true, TTL_PENDING))
  end
end

---@param req doorbell.request
---@return doorbell.auth_state state
---@return string? error
local function get_auth_state(req, ctx)
  local rule, cached = rules.match(req)
  if rule then
    if ctx then
      ctx.rule = rule
      ctx.cached = cached
    end
    return rule.action
  end

  if is_pending(req.addr) then
    return STATES.pending
  end

  return STATES.none
end

---@param req doorbell.request
---@return string? token
---@return string? error
local function generate_request_token(req)
  local bytes = random.bytes(32, true)
  local token = str.to_hex(bytes)
  local key = "token:" .. token
  local value = cjson.encode(req)
  local ok, err = SHM:safe_add(key, value, TTL_PENDING)
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
    log.err("failed to create lock: ", err)
    return nil, err
  end

  local elapsed
  elapsed, err = lock:lock("lock:" .. addr)
  if not elapsed then
    log.err("failed to lock auth state for ", addr)
    return nil, err
  end

  return lock
end

---@param req doorbell.request
local function await_allow(req)
  local start = now()
  while (now() - start) < WAIT_TIME do
    if not is_pending(req.addr) then
      break
    end
    sleep(1)
  end

  if is_pending(req.addr) then
    return false
  end

  local state = get_auth_state(req)
  if state == STATES.allow then
    return true
  elseif state == STATES.deny then
    return false
  end
end


---@param req doorbell.request
---@return boolean
local function request_auth(req)
  local addr = req.addr
  local lock, err = lock_addr(addr)
  if not lock then
    log.errf("failed acquiring addr lock for %s: %s", addr, err)
    return false
  end

  if is_pending(addr) then
    log.notice("access for ", addr, " is already waiting on a pending request")
    lock:unlock()
    return false
  else
    local rule = rules.match(req)
    local state = (rule and rule.action)

    if state == STATES.allow then
      log.debug("acccess for ", addr, " was allowed before requesting it")
      lock:unlock()
      return true

    elseif state == STATES.deny then
      log.notice("access was denied for ", addr, " before requesting it")
      lock:unlock()
      return false
    end
  end

  local po
  po, err = pushover.new(PUSHOVER_OPTS)
  if not po then
    log.err("failed creating pushover client: ", err)
    lock:unlock()
    return false
  end

  local token
  token, err = generate_request_token(req)
  if not token then
    log.errf("failed creating auth request token for %s: %s", addr, err)
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

  local url = fmt("%s/answer?t=%s", BASE_URL, token)
  log.debug("approve/deny link: ", url)

  local ok, res
  ok, err, res = po:notify({
    title     = "access requested for " .. addr,
    message   = message,
    monospace = true,
    url       = url,
    url_title = "approve or deny",
  })

  if res then
    log.debug("pushover notify response: ", cjson.encode(res))
  end

  if not ok then
    log.err("failed sending auth request: ", err)
    lock:unlock()
    metrics.notify:inc(1, {"failed"})
    return false
  end

  metrics.notify:inc(1, {"sent"})
  set_pending(addr, true)
  lock:unlock()

  return await_allow(req)
end

---@alias doorbell.handler fun(req:doorbell.request)

---@type table<doorbell.auth_state, doorbell.handler>
local HANDLERS = {
  [STATES.allow] = function(req)
    log.debugf("ALLOW %s => %s %s://%s%s", req.addr, req.method, req.scheme, req.host, req.uri)
    return exit(HTTP_OK)
  end,

  [STATES.deny] = function(req)
    log.notice("denying access for ", req.addr)
    return exit(HTTP_FORBIDDEN)
  end,

  [STATES.none] = function(req)
    if in_notify_period() then
      log.notice("requesting access for ", req.addr)
      if request_auth(req) then
        log.notice("access approved for ", req.addr)
        return exit(HTTP_OK)
      end
    else
      log.notice("not sending request outside of notify hours for ", req.addr)
      metrics.notify:inc(1, {"snoozed"})
    end
    return exit(HTTP_UNAUTHORIZED)
  end,

  [STATES.pending] = function(req)
    log.notice("awaiting access for ", req.addr)
    if await_allow(req) then
      return exit(HTTP_OK)
    end
    return exit(HTTP_UNAUTHORIZED)
  end,

  [STATES.error] = function(req)
    log.err("something went wrong while checking auth for ", req.addr)
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
    log.warn("denying connection from untrusted IP: ", ip)
    return exit(HTTP_FORBIDDEN)
  end
end

---@class doorbell.init.opts : table
---@field shm      string
---@field base_url string
---@field allow    doorbell.rule[]
---@field deny     doorbell.rule[]
---@field trusted  string[]
---@field pushover resty.pushover.client.opts
---@field save_path string
---@field log_path  string
---@field notify_periods doorbell.notify_period[]

---@param opts doorbell.init.opts
function _M.init(opts)
  opts = opts or EMPTY
  SHM_NAME = opts.shm or SHM_NAME

  SHM = assert(ngx.shared[SHM_NAME], "missing shm " .. SHM_NAME)

  PUSHOVER_OPTS = assert(opts.pushover, "missing pushover API config")

  BASE_URL = assert(opts.base_url, "opts.base_url required")
  local m = ngx.re.match(BASE_URL, "^(http(s)?://)?(?<host>[^/]+)")
  assert(m and m.host, "failed to parse hostname from base_url: " .. BASE_URL)
  HOST = m.host:lower()

  log.debug("doorbell BASE_URL: ", BASE_URL, ", HOST: ", HOST)

  SAVE_PATH = opts.save_path or (ngx.config.prefix() .. "/rules.json")

  LOG_PATH = opts.log_path or (ngx.config.prefix() .. "/request.json.log")

  if opts.notify_periods then
    NOTIFY_PERIODS = opts.notify_periods
  end

  TRUSTED = assert(ipmatcher.new(opts.trusted or EMPTY))

  local proc = require "ngx.process"
  assert(proc.enable_privileged_agent(10))

  local ok, err = rules.load(SAVE_PATH)
  if not ok then
    log.err("failed loading rules from disk: ", err)
  end

  if opts.allow then
    for _, rule in ipairs(opts.allow) do
      rule.action = "allow"
      rule.source = "config"
      assert(rules.upsert(rule, true))
    end
  end

  if opts.deny then
    for _, rule in ipairs(opts.deny) do
      rule.action = "deny"
      rule.source = "config"
      assert(rules.upsert(rule, true))
    end
  end

  rules.reload()
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

  if req.host == HOST and req.path == "/answer" then
    log.debugf("allowing request to %s/answer endpoint", HOST)
    return exit(HTTP_OK)
  end

  local state = get_auth_state(req, ngx.ctx)

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

              <input type="radio" id="deny" name="action" value="deny" checked="checked">
              <label for="deny">deny</label><br>
            </li>

            <li>
              <input type="radio" id="addr" name="subject" value="addr" checked="checked">
              <label for="addr">this ip ({{req.addr}})</label><br>

              <input type="radio" id="ua" name="subject" value="ua">
              <label for="ua">this user agent ({{req.ua}})</label><br>
            </li>


            <li>
              <input type="radio" id="global" name="scope" value="global" checked="checked">
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

              <input type="radio" id="day" name="period" value="day" checked="checked">
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

function _M.answer()
  assert(SHM, "doorbell was not initialized")
  require_trusted_ip()

  local t = var.arg_t
  if not t then
    log.notice("/answer accessed with no token")
    return exit(HTTP_NOT_FOUND)
  end

  local req = get_token_address(t)

  if not req then
    log.noticef("/answer token %s not found", t)
    return exit(HTTP_NOT_FOUND)
  end

  req.url = req.scheme .. "://" .. req.host .. req.uri

  local method = ngx.req.get_method()
  if not (method == "GET" or method == "POST") then
    exit(HTTP_BAD_REQUEST)
  end

  if method == "GET" then
    header["content-type"] = "text/html"
    ngx.print(render_form(req))
    return exit(HTTP_OK)
  end

  read_body()
  local args = get_post_args()
  local action = args.action or "NONE"
  local scope = args.scope or "NONE"
  local period = args.period or "NONE"
  local subject = args.subject or "NONE"

  local err

  if not (action == "approve" or action == "deny") then
    err = "invalid action: " .. tostring(action)
  elseif not SCOPES[scope] then
    err = "invalid scope: " .. tostring(scope)
  elseif not PERIODS[period] then
    err = "invalid period: " .. tostring(period)
  elseif not SUBJECTS[subject] then
    err = "invalid subject: " .. tostring(subject)
  end

  if err then
    header["content-type"] = "text/html"
    ngx.print(render_form(req, err))
    return exit(HTTP_BAD_REQUEST)
  end

  local terminate = false
  local host, path = req.host, req.path
  if scope == SCOPES.global then
    host = nil
    path = nil
    terminate = true
  elseif scope == SCOPES.host then
    path = nil
  end

  local addr, ua = req.addr, req.ua
  if subject == SUBJECTS.addr then
    ua = nil
  elseif subject == SUBJECTS.ua then
    addr = nil
  end

  local rule = {
    action    = (action == "approve" and "allow") or "deny",
    source    = "user",
    addr      = addr,
    host      = host,
    path      = path,
    ua        = ua,
    ttl       = PERIODS[period],
    terminate = terminate,
  }

  assert(rules.add(rule))

  metrics.notify:inc(1, {"answered"})

  set_pending(req.addr, false)

  local msg = fmt(
    "%s access for %q to %s %s",
    (action == "approve" and "Approved") or "Denied",
    (addr or ua),
    (scope == SCOPES.global and "all apps.") or (scope == SCOPES.host and req.host) or req.url,
    (PERIODS[period] == PERIODS.forever and "for all time") or ("for one " .. period)
  )

  header["content-type"] = "text/plain"
  ngx.say(msg)
  return exit(HTTP_CREATED)
end

function _M.list()
  assert(SHM, "doorbell was not initialized")
  header["content-type"] = "application/json"
  ngx.say(cjson.encode(rules.list()))
end

local function init_worker()
  metrics.init_worker()
end

local function init_agent()
  local save
  local last = rules.version()
  local timer_at = ngx.timer.at
  local interval = 15

  save = function(premature)
    if premature then
      return
    end
    rules.flush_expired()

    local version = rules.version()
    if version ~= last then
      log.notice("saving rules...")
      local v = rules.save(SAVE_PATH)
      last = v or last
    end
    assert(timer_at(interval, save))
  end
  assert(timer_at(0, save))
end

function _M.init_worker()
  assert(SHM, "doorbell was not initialized")

  local proc = require "ngx.process"
  if proc.type() == "privileged agent" then
    return init_agent()
  end

  return init_worker()
end

function _M.reload()
  assert(SHM, "doorbell was not initialized")
  if ngx.req.get_method() ~= "POST" then
    return exit(HTTP_NOT_ALLOWED)
  end
  header["content-type"] = "text/plain"
  local ok, err = rules.load()
  if ok then
    ngx.say("success")
    return exit(HTTP_CREATED)
  end
  log.err("failed reloading rules from disk: ", err)
  ngx.say("failure")
  exit(HTTP_INTERNAL_SERVER_ERROR)
end

function _M.metrics()
  -- rule counts
  do
    local counts = {
      allow = {
        config = 0,
        user   = 0,
      },
      deny = {
        config = 0,
        user =  0,
      }
    }
    for _, rule in ipairs(rules.list()) do
      counts[rule.action][rule.source] = counts[rule.action][rule.source] + 1
    end
    for action, sources in pairs(counts) do
      for source, num in pairs(sources) do
        metrics.rules:set(num, {action, source})
      end
    end
  end

  metrics.collect()
end

function _M.log()
  local ctx = ngx.ctx

  metrics.requests:inc(1, {ngx.status})

  if ctx.rule then
    metrics.actions:inc(1, {ctx.rule.action})
    metrics.cache_results:inc(1, {ctx.cached and "HIT" or "MISS" })
  end

  local fh, err = io.open(LOG_PATH, "a+")
  if not fh then
    log.errf("failed opening log file (%s): %s", LOG_PATH, err)
    return
  end

  local entry = {
    addr                = var.remote_addr,
    client_addr         = var.realip_remote_addr,
    connection          = var.connection,
    connection_requests = var.connection_requests,
    connection_time     = var.connection_time,
    host                = var.host,
    http_version        = http_version(),
    log_time            = now(),
    method              = get_method(),
    path                = var.uri:gsub("?.*", ""),
    query               = get_uri_args(1000),
    remote_port         = var.remote_port,
    request_headers     = get_headers(1000),
    request_uri         = var.request_uri,
    response_headers    = get_resp_headers(1000),
    rule                = ctx.rule,
    scheme              = var.scheme,
    start_time          = start_time(),
    status              = ngx.status,
    uri                 = var.uri,
    worker = {
      id = ngx.worker.id(),
      pid = ngx.worker.pid(),
    },
  }

  fh:write(cjson.encode(entry) .. "\n")
  fh:close()
end

return _M
