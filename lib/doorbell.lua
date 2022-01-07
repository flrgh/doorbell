local _M = {
  _VERSION = require("doorbell.constants").version,
}

local rules   = require "doorbell.rules"
local const   = require "doorbell.constants"
local log     = require "doorbell.log"
local metrics = require "doorbell.metrics"
local request = require "doorbell.request"
local ip      = require "doorbell.ip"
local auth    = require "doorbell.auth"
local views   = require "doorbell.views"
local notify  = require "doorbell.notify"

local cjson      = require "cjson"
local proc       = require "ngx.process"

local ngx               = ngx
local var               = ngx.var
local header            = ngx.header
local now               = ngx.now
local run_worker_thread = ngx.run_worker_thread
local timer_at          = ngx.timer.at
local say               = ngx.say
local get_headers       = ngx.req.get_headers
local http_version      = ngx.req.http_version
local start_time        = ngx.req.start_time
local get_resp_headers  = ngx.resp.get_headers
local get_method        = ngx.req.get_method
local get_uri_args      = ngx.req.get_uri_args
local exit              = ngx.exit
local exiting           = ngx.worker.exiting
local sleep             = ngx.sleep

local HTTP_OK                    = ngx.HTTP_OK
local HTTP_FORBIDDEN             = ngx.HTTP_FORBIDDEN
local HTTP_UNAUTHORIZED          = ngx.HTTP_UNAUTHORIZED
local HTTP_INTERNAL_SERVER_ERROR = ngx.HTTP_INTERNAL_SERVER_ERROR
local HTTP_CREATED               = ngx.HTTP_CREATED
local HTTP_BAD_REQUEST           = ngx.HTTP_BAD_REQUEST
local HTTP_NOT_ALLOWED           = ngx.HTTP_NOT_ALLOWED

local tonumber = tonumber
local ipairs   = ipairs
local assert   = assert
local encode   = cjson.encode

---@class doorbell.config : table
local config

local EMPTY = {}

local WORKER_ID
local WORKER_PID

local TARPIT_INTERVAL = const.periods.minute * 5

---@type string
local SHM_NAME = const.shm.doorbell
---@type ngx.shared.DICT
local SHM = assert(ngx.shared[SHM_NAME], "missing shm " .. SHM_NAME)

local STATES = const.states

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
---@field template        fun(env:table):string


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
    if notify.in_notify_period() then
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

---@param opts doorbell.config
function _M.init(opts)
  config = require("doorbell.config").new(opts)

  require("doorbell.cache").init(config)

  ip.init(config)
  views.init(config)
  notify.init(config)
  auth.init(config)
  rules.init(config)

  assert(proc.enable_privileged_agent(10))

  rules.reload()
end

function _M.ring()
  assert(SHM, "doorbell was not initialized")
  local ctx = ngx.ctx

  ip.require_trusted(ctx)

  local req, err = request.new(ctx)
  if not req then
    log.alert("failed building request: ", err)
    return exit(HTTP_BAD_REQUEST)
  end

  if req.host == config.host and req.path == "/answer" then
    log.debugf("allowing request to %s/answer endpoint", config.host)
    return exit(HTTP_OK)
  end

  local state = auth.get_state(req, ctx)

  return HANDLERS[state](req, ctx)
end

function _M.answer()
  assert(SHM, "doorbell was not initialized")
  local ctx = ngx.ctx
  ip.require_trusted(ctx)
  return views.answer(ctx)
end

function _M.list()
  assert(SHM, "doorbell was not initialized")
  header["content-type"] = "application/json"
  say(encode(rules.list()))
end

function _M.list_html()
  assert(SHM, "doorbell was not initialized")
  local ctx = ngx.ctx
  ip.require_trusted(ctx)
  return views.rule_list(ctx)
end

local LOG_BUF = { n = 0 }

local function write_logs()
  for _ = 1, 1000 do
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
          config.log_path,
          entries
        )

        if not thread_ok then
          log.alert("log writer thread failed: ", ok)
          written = 0
        end
      else
        -- ngx.run_worker_thread is new

        ok, log_err, written = require("doorbell.log.request").write(
          config.log_path,
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
      local v = rules.save(config.save_path)
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
  local ok, err = rules.save(config.save_path)
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
  local ok, err = rules.load(config.save_path, false)
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
