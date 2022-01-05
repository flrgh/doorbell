local _M = {
  _VERSION = "0.1.0",
}

local rules   = require "doorbell.rules"
local const   = require "doorbell.constants"
local log     = require "doorbell.log"
local metrics = require "doorbell.metrics"

local cjson      = require "cjson"
local ipmatcher  = require "resty.ipmatcher"
local pushover   = require "resty.pushover"
local random     = require "resty.random"
local resty_lock = require "resty.lock"
local str        = require "resty.string"
local proc       = require "ngx.process"

local ngx               = ngx
local var               = ngx.var
local header            = ngx.header
local now               = ngx.now
local sleep             = ngx.sleep
local run_worker_thread = ngx.run_worker_thread
local timer_at          = ngx.timer.at
local utctime           = ngx.utctime
local say               = ngx.say
local print             = ngx.print
local read_body         = ngx.req.read_body
local get_post_args     = ngx.req.get_post_args
local get_headers       = ngx.req.get_headers
local http_version      = ngx.req.http_version
local start_time        = ngx.req.start_time
local get_resp_headers  = ngx.resp.get_headers
local get_method        = ngx.req.get_method
local get_uri_args      = ngx.req.get_uri_args
local exit              = ngx.exit
local exiting = ngx.worker.exiting

local HTTP_OK                    = ngx.HTTP_OK
local HTTP_FORBIDDEN             = ngx.HTTP_FORBIDDEN
local HTTP_UNAUTHORIZED          = ngx.HTTP_UNAUTHORIZED
local HTTP_INTERNAL_SERVER_ERROR = ngx.HTTP_INTERNAL_SERVER_ERROR
local HTTP_CREATED               = ngx.HTTP_CREATED
local HTTP_BAD_REQUEST           = ngx.HTTP_BAD_REQUEST
local HTTP_NOT_FOUND             = ngx.HTTP_NOT_FOUND
local HTTP_NOT_ALLOWED           = ngx.HTTP_NOT_ALLOWED

local fmt      = string.format
local tonumber = tonumber
local ipairs   = ipairs
local assert   = assert
local encode   = cjson.encode
local decode   = cjson.decode


local cache
do
  local lru = require "resty.lrucache"
  cache = assert(lru.new(1000))
end

local EMPTY = {}

local WORKER_ID
local WORKER_PID

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

local GEOIP

local template = {}
local ASSET_PATH = "/opt/doorbell/assets"
do
  local tpl = assert(
    require("resty.template").new({
      root = ASSET_PATH,
    })
  )
  template.rules_list = assert(tpl.compile("rule_list.template.html"))
  template.answer     = assert(tpl.compile("answer.template.html"))
end

---@param addr string
---@return string?
local function get_country(addr)
  if not GEOIP then
    return
  end

  local result, err = GEOIP:lookup_value(addr, "country", "iso_code")
  if not result then
    log.errf("failed looking up %s in geoip db: %s", addr, err)
    return
  end

  return result
end


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
  local yyyy_mm_dd_hh_mm_ss = utctime()
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
  local value = encode(req)
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
    return decode(v)
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
    log.debug("pushover notify response: ", encode(res))
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
    ngx.sleep(300)
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

local function require_trusted_ip(ctx)
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

  ctx.trusted_ip = trusted
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
---@field geoip_db string

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

  if opts.geoip_db then
    local geoip = require("geoip")
    local err
    GEOIP, err = geoip.load_database(opts.geoip_db)
    if not GEOIP then
      log.alertf("failed loading geoip database file (%s): %s", opts.geoip_db, err)
    end
  end

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

---@class doorbell.request : table
---@field addr     string
---@field scheme   string
---@field host     string
---@field uri      string
---@field path     string
---@field method   string
---@field ua       string
---@field country? string


local new_request, release_request
do
  local tb = require "tablepool"
  local fetch = tb.fetch
  local release = tb.release
  local pool = "doorbell.request"

  local narr = 0
  local nrec = 8

  ---@param ctx table
  ---@return doorbell.request
  function new_request(ctx)
    assert(ctx.trusted_ip, "tried to build a request from an untrusted IP")

    local r = fetch(pool, narr, nrec)
    ctx.request = r

    local headers = get_headers(1000)
    ctx.request_headers = headers

    r.addr    = assert(headers["x-forwarded-for"], "missing x-forwarded-for")
    r.scheme  = assert(headers["x-forwarded-proto"], "missing x-forwarded-proto")
    r.host    = assert(headers["x-forwarded-host"], "missing x-forwarded-host")
    r.uri     = headers["x-forwarded-uri"] or "/"
    r.path    = r.uri:gsub("?.*", "")
    r.method  = assert(headers["x-forwarded-method"], "missing x-forwarded-method")
    r.ua      = headers["user-agent"]
    r.country = get_country(r.addr)

    return r
  end

  function release_request(ctx)
    local r = ctx.request
    if r then
      release(pool, r, true)
    end
  end
end


function _M.ring()
  assert(SHM, "doorbell was not initialized")
  local ctx = ngx.ctx

  require_trusted_ip(ctx)
  local req = new_request(ctx)

  if req.host == HOST and req.path == "/answer" then
    log.debugf("allowing request to %s/answer endpoint", HOST)
    return exit(HTTP_OK)
  end

  local state = get_auth_state(req, ctx)

  return HANDLERS[state](req)
end

---@param req doorbell.request
local function render_form(req, err, current)
  return template.answer({
    req = {
      { "IP Address",   req.addr    },
      { "Country Code", req.country },
      { "User-Agent",   req.ua     },
      { "Host",         req.host   },
      { "Method",       req.method },
      { "URI",          req.uri    },
    },
    err = err,
    current_ip = current,
  })
end

function _M.answer()
  assert(SHM, "doorbell was not initialized")
  require_trusted_ip(ngx.ctx)

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

  local method = get_method()
  if not (method == "GET" or method == "POST") then
    exit(HTTP_BAD_REQUEST)
  end

  local current_ip = req.addr == var.http_x_forwarded_for

  if method == "GET" then
    header["content-type"] = "text/html"
    print(render_form(req, nil, current_ip))
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
    print(render_form(req, err, current_ip))
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
  say(msg)
  return exit(HTTP_CREATED)
end

function _M.list()
  assert(SHM, "doorbell was not initialized")
  header["content-type"] = "application/json"
  say(encode(rules.list()))
end

local date = os.date

local function tfmt(stamp)
  return date("%Y-%m-%d %H:%M:%S", stamp)
end

function _M.list_html()
  assert(SHM, "doorbell was not initialized")
  local list = rules.list()
  local keys = {"addr", "cidr", "host", "ua", "method", "path"}
  local t = now()
  table.sort(list, function(a, b)
    return a.created > b.created
  end)
  for _, rule in ipairs(list) do
    local matches = {}
    for _, key in ipairs(keys) do
      if rule[key] then
        table.insert(matches, key)
      end
    end
    rule.match = table.concat(matches, ",")
    rule.created = tfmt(rule.created)
    if rule.expires == 0 then
      rule.expires = "never"
    elseif rule.expires < t then
      rule.expires = "expired"
    else
      rule.expires = tfmt(rule.expires)
    end
  end
  header["content-type"] = "text/html"
  say(template.rules_list({ rules = list }))
end

local LOG_BUF = { n = 0 }

local function write_logs()
  if LOG_BUF.n > 0 then
    local entries = LOG_BUF
    local n = entries.n

    LOG_BUF = { n = 0 }

    local ok, log_err, written

    if run_worker_thread then
      local thread_ok
      thread_ok, ok, log_err, written = run_worker_thread(
        "doorbell.log.writer",
        "doorbell.log.request",
        "write",
        LOG_PATH,
        entries
      )

      if not thread_ok then
        log.alert("log writer thread failed: ", ok)
        written = 0
      end
    else
      -- ngx.run_worker_thread is new

      ok, log_err, written = require("doorbell.log.request").write(
        LOG_PATH,
        entries
      )
    end

    if not ok then
      local failed = n - written
      log.alertf("failed writing %s/%s to the log: %s", failed, n, log_err)
    end

    log.debugf("wrote %s entries to the log file", written)
  end

  local ok, err = timer_at(1, write_logs)
  if not ok then
    log.alert("failed to reschedule log writer: ", err)
  end
end

local function append_log_entry(entry)
  local n = LOG_BUF.n + 1
  LOG_BUF[n] = entry
  LOG_BUF.n = n
end

local function init_worker()
  metrics.init_worker()
  rules.init_worker()
  assert(timer_at(1, write_logs))
  WORKER_PID = ngx.worker.pid()
  WORKER_ID  = ngx.worker.id()
end

local function init_agent()
  local save
  local last = rules.version()
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

  if proc.type() == "privileged agent" then
    return init_agent()
  end

  return init_worker()
end

function _M.reload()
  ngx.ctx.no_log = true
  ngx.ctx.no_metrics = true

  assert(SHM, "doorbell was not initialized")
  if get_method() ~= "POST" then
    return exit(HTTP_NOT_ALLOWED)
  end
  header["content-type"] = "text/plain"
  local ok, err = rules.load(SAVE_PATH)
  if ok then
    say("success")
    return exit(HTTP_CREATED)
  end
  log.err("failed reloading rules from disk: ", err)
  say("failure")
  exit(HTTP_INTERNAL_SERVER_ERROR)
end

function _M.metrics()
  ngx.ctx.no_log = true
  ngx.ctx.no_metrics = true

  metrics.collect()
end

function _M.log()
  local ctx = ngx.ctx

  release_request(ctx)

  if not ctx.no_metrics then
    metrics.requests:inc(1, {ngx.status})

    if ctx.rule then
      metrics.actions:inc(1, {ctx.rule.action})
      metrics.cache_results:inc(1, {ctx.cached and "HIT" or "MISS" })
    end
  end

  if ctx.no_log then
    return
  end

  local duration
  local log_time = now()
  local start = start_time()
  if start then
    duration = now() - start
  end

  local entry = {
    addr                = var.remote_addr,
    client_addr         = var.realip_remote_addr,
    connection          = var.connection,
    connection_requests = tonumber(var.connection_requests),
    connection_time     = var.connection_time,
    duration            = duration,
    host                = var.host,
    http_version        = http_version(),
    log_time            = log_time,
    method              = get_method(),
    path                = var.uri:gsub("?.*", ""),
    query               = get_uri_args(1000),
    remote_port         = tonumber(var.remote_port),
    request_headers     = ctx.request_headers or get_headers(1000),
    request_uri         = var.request_uri,
    response_headers    = get_resp_headers(1000),
    rule                = ctx.rule,
    scheme              = var.scheme,
    start_time          = start,
    status              = ngx.status,
    uri                 = var.uri,
    worker = {
      id = WORKER_ID,
      pid = WORKER_PID,
      exiting = exiting()
    },
  }

  append_log_entry(entry)
end

return _M
