local _M = {
  _VERSION = require("doorbell.constants").version,
}

local rules   = require "doorbell.rules"
local const   = require "doorbell.constants"
local log     = require "doorbell.log"
local metrics = require "doorbell.metrics"
local request = require "doorbell.request"
local ip      = require "doorbell.ip"
local auth       = require "doorbell.auth"

local cjson      = require "cjson"
local proc       = require "ngx.process"

local ngx               = ngx
local var               = ngx.var
local header            = ngx.header
local now               = ngx.now
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
local sleep = ngx.sleep

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
local date = os.date

local cache

local EMPTY = {}

local WORKER_ID
local WORKER_PID

local TARPIT_INTERVAL = const.periods.minute * 5

---@type string
local SAVE_PATH

---@type string
local LOG_PATH

---@type string
local SHM_NAME = const.shm.doorbell

local BASE_URL, HOST

---@type ngx.shared.DICT
local SHM

local GEOIP

local STATES      = const.states
local SCOPES      = const.scopes
local SUBJECTS    = const.subjects
local WAIT_TIME   = const.wait_time
local PERIODS     = const.periods

---@type doorbell.notify_period[]
local NOTIFY_PERIODS = {
  -- UTC
  { from = 15, to = 24 },
  { from = 00, to = 07 },
}


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

local is_pending = auth.is_pending

---@alias doorbell.handler fun(req:doorbell.request, ctx:doorbell.ctx)

---@type table<doorbell.auth_state, doorbell.handler>
local HANDLERS = {
  [STATES.allow] = function(req)
    log.debugf("ALLOW %s => %s %s://%s%s", req.addr, req.method, req.scheme, req.host, req.uri)
    return exit(HTTP_OK)
  end,

  [STATES.deny] = function(req, ctx)
    log.notice("denying access for ", req.addr)
    if ctx.rule.deny_action == const.deny_actions.tarpit then
      log.debugf("tarpit %s for %s seconds", req.addr, TARPIT_INTERVAL)
      sleep(TARPIT_INTERVAL)
    end
    return exit(HTTP_FORBIDDEN)
  end,

  [STATES.none] = function(req)
    if in_notify_period() then
      log.notice("requesting access for ", req.addr)
      if auth.request(req) and auth.await(req) then
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
    if auth.await(req) then
      return exit(HTTP_OK)
    end
    return exit(HTTP_UNAUTHORIZED)
  end,

  [STATES.error] = function(req)
    log.err("something went wrong while checking auth for ", req.addr)
    return exit(HTTP_INTERNAL_SERVER_ERROR)
  end,
}

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
---@field cache_size integer

---@param opts doorbell.init.opts
function _M.init(opts)
  opts = opts or EMPTY

  cache = require("doorbell.cache").new(opts.cache_size)

  SHM_NAME = opts.shm or SHM_NAME
  SHM = assert(ngx.shared[SHM_NAME], "missing shm " .. SHM_NAME)


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

  if opts.geoip_db then
    local geoip = require("geoip.mmdb")
    local err
    GEOIP, err = geoip.load_database(opts.geoip_db)
    if not GEOIP then
      log.alertf("failed loading geoip database file (%s): %s", opts.geoip_db, err)
    end
  end

  ip.init({ geoip = GEOIP, cache = cache, trusted = opts.trusted })

  assert(proc.enable_privileged_agent(10))

  local ok, err = rules.load(SAVE_PATH, true)
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

---@class doorbell.ctx : table
---@field rule            doorbell.rule
---@field request_headers table
---@field trusted_ip      boolean
---@field private_ip      boolean
---@field localhost_ip    boolean
---@field request         doorbell.request
---@field country_code    string
---@field geoip_error     string
---@field cached          boolean
---@field no_log          boolean
---@field no_metrics      boolean

---@class doorbell.addr
---@field country? string
---@field localhost_ip boolean
---@field private_ip boolean

function _M.ring()
  assert(SHM, "doorbell was not initialized")
  local ctx = ngx.ctx

  ip.require_trusted(ctx)

  local req, err = request.new(ctx)
  if not req then
    log.alert("failed building request: ", err)
    return exit(HTTP_BAD_REQUEST)
  end

  if req.host == HOST and req.path == "/answer" then
    log.debugf("allowing request to %s/answer endpoint", HOST)
    return exit(HTTP_OK)
  end

  local state = auth.get_state(req, ctx)

  return HANDLERS[state](req, ctx)
end

---@param req doorbell.request
local function render_form(req, errors, current)
  return template.answer({
    req = {
      { "addr",   req.addr    },
      { "country", req.country },
      { "user-agent",   req.ua     },
      { "host",         req.host   },
      { "method",       req.method },
      { "uri",          req.uri    },
    },
    errors = errors or {},
    current_ip = current,
  })
end

function _M.answer()
  assert(SHM, "doorbell was not initialized")
  ip.require_trusted(ngx.ctx)

  local t = var.arg_t
  if not t then
    log.notice("/answer accessed with no token")
    return exit(HTTP_NOT_FOUND)
  end

  if t == "TEST" then
    ---@type doorbell.request
    local req = {
      addr = "178.45.6.125",
      ua = "Mozilla/5.0 (X11; Ubuntu; Linux i686) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2830.76 Safari/537.36",
      host = "prometheus.pancakes2.com",
      uri = "/wikindex.php?f=/NmRtJOUjAdutReQj/scRjKUhleBpzmTyO.txt",
      scheme = "https",
      country = "US",
      method = "GET",
      path = "/wikindex.php",
    }

    local errors
    if var.arg_errors then
      errors = { "error: invalid action 'nope'" }
    end

    local current_ip = (var.arg_current and true) or false

    header["content-type"] = "text/html"
    print(render_form(req, errors, current_ip))
    return exit(HTTP_OK)
  end

  local req = auth.get_token_address(t)

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
    print(render_form(req, { err }, current_ip))
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

  auth.set_pending(req.addr, false)

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

local function tfmt(stamp)
  return date("%Y-%m-%d %H:%M:%S", stamp)
end

function _M.list_html()
  assert(SHM, "doorbell was not initialized")
  local list = rules.list()
  local keys = {"addr", "cidr", "host", "ua", "method", "path", "country"}
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

    if rule.last_match then
      rule.last_match = tfmt(rule.last_match)
    else
      rule.last_match = "never"
    end

    rule.match_count = rule.match_count or 0

  end
  header["content-type"] = "text/html"
  say(template.rules_list({ rules = list, conditions = keys }))
end

local LOG_BUF = { n = 0 }

local function write_logs()
  for _, = 1, 1000 do
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
    else
      sleep(1)
    end
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
  metrics.init_worker(5)
  rules.init_worker()
  assert(timer_at(0, write_logs))
  WORKER_PID = ngx.worker.pid()
  WORKER_ID  = ngx.worker.id()
end

local function init_agent()
  local save
  local last = rules.version()
  local interval = 15
  local last_stamp = now()

  save = function(premature)
    if premature then
      return
    end
    rules.flush_expired()

    local version = rules.version()
    local stamp = now()

    if version ~= last or (stamp - last_stamp) > 60 then
      log.notice("saving rules...")
      local v = rules.save(SAVE_PATH)
      last = v or last
      last_stamp = stamp
    end
    assert(timer_at(interval, save))
  end
  assert(timer_at(0, save))
end

function _M.save()
  local ctx = ngx.ctx
  request.no_log(ctx)
  request.no_metrics(ctx)

  assert(SHM, "doorbell was not initialized")
  if get_method() ~= "POST" then
    return exit(HTTP_NOT_ALLOWED)
  end
  header["content-type"] = "text/plain"
  local ok, err = rules.save(SAVE_PATH)
  if ok then
    say("success")
    return exit(HTTP_CREATED)
  end
  log.err("failed saving rules to disk: ", err)
  say("failure")
  exit(HTTP_INTERNAL_SERVER_ERROR)

end

function _M.init_worker()
  assert(SHM, "doorbell was not initialized")

  if proc.type() == "privileged agent" then
    return init_agent()
  end

  return init_worker()
end

function _M.reload()
  local ctx = ngx.ctx
  request.no_log(ctx)
  request.no_metrics(ctx)

  assert(SHM, "doorbell was not initialized")
  if get_method() ~= "POST" then
    return exit(HTTP_NOT_ALLOWED)
  end
  header["content-type"] = "text/plain"
  local ok, err = rules.load(SAVE_PATH, false)
  if ok then
    say("success")
    return exit(HTTP_CREATED)
  end
  log.err("failed reloading rules from disk: ", err)
  say("failure")
  exit(HTTP_INTERNAL_SERVER_ERROR)
end

function _M.metrics()
  local ctx = ngx.ctx
  request.no_log(ctx)
  request.no_metrics(ctx)

  metrics.collect()
end

function _M.log()
  local ctx = ngx.ctx

  request.release(ctx)
  local start = start_time()

  if not ctx.no_metrics then
    metrics.requests:inc(1, {ngx.status})
    rules.log(ctx, start)
  end

  if ctx.no_log then
    return
  end

  local duration
  local log_time = now()

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
    country_code        = ctx.country_code,
    localhost_ip        = ctx.localhost_ip or false,
    private_ip          = ctx.private_ip or false,
    geoip_error         = ctx.geoip_error,
    worker = {
      id = WORKER_ID,
      pid = WORKER_PID,
      exiting = exiting()
    },
  }

  append_log_entry(entry)
end

return _M
