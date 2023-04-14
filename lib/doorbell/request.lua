local _M = {
  _VERSION = require("doorbell.constants").version,
}

local ip = require "doorbell.ip"
local logger = require "doorbell.log.request"

local tb = require "tablepool"

local ngx               = ngx
local var               = ngx.var
local now               = ngx.now
local get_headers       = ngx.req.get_headers
local http_version      = ngx.req.http_version
local start_time        = ngx.req.start_time
local get_resp_headers  = ngx.resp.get_headers
local get_method        = ngx.req.get_method
local get_uri_args      = ngx.req.get_uri_args
local exiting           = ngx.worker.exiting
local tonumber = tonumber
local get_country = ip.get_country

local pool    = "doorbell.request"
local narr    = 0
local nrec    = 8
local fetch   = tb.fetch
local release = tb.release

local WORKER_ID, WORKER_PID
local LOG = true

---@type prometheus.counter
local counter
---@type prometheus.counter
local countries


---@class doorbell.request : table
---@field addr     string
---@field scheme   string
---@field host     string
---@field uri      string
---@field path     string
---@field method   string
---@field ua       string
---@field country? string


---@param ctx doorbell.ctx
---@param headers? table
---@return doorbell.request
function _M.new(ctx, headers)
  if not ctx.trusted_ip then
    return nil, "untrusted client IP address"
  end

  local r = fetch(pool, narr, nrec)
  ctx.request = r

  headers = headers or get_headers(1000)
  ctx.request_headers = headers

  local addr = headers["x-forwarded-for"]
  if not addr then
    return nil, "missing x-forwarded-for"
  end
  r.addr = addr

  local scheme = headers["x-forwarded-proto"]
  if not scheme then
    return nil, "missing x-forwarded-proto"
  end
  r.scheme = scheme

  local host = headers["x-forwarded-host"]
  if not host then
    return nil, "missing x-forwarded-host"
  end
  r.host = host

  local uri = headers["x-forwarded-uri"]
  if not uri then
    return nil, "missing x-forwarded-uri"
  end
  r.uri = uri
  r.path = uri:gsub("?.*", "")

  local method = headers["x-forwarded-method"]
  if not method then
    return nil, "missing x-forwarded-method"
  end
  r.method = method

  r.ua      = headers["user-agent"]

  local code, name_or_err = get_country(addr)
  r.country = code
  ctx.country_code = code

  if code then
    ctx.country_name = name_or_err
  else
    ctx.geoip_error = name_or_err
  end

  return r
end

---@param ctx doorbell.ctx
function _M.release(ctx)
  local r = ctx.request
  if r then
    release(pool, r, true)
  end
end

---@param ctx doorbell.ctx
function _M.no_metrics(ctx)
  ctx.no_metrics = true
end

---@param ctx doorbell.ctx
function _M.no_log(ctx)
  ctx.no_log = true
end

---@param ctx doorbell.ctx
function _M.log(ctx)
  if counter and not ctx.no_metrics then
    counter:inc(1, { ngx.status })

    if countries and ctx.country_code then
      countries:inc(1, { ctx.country_code })
    end
  end

  if LOG == false or ctx.no_log then
    return
  end

  local start = start_time()
  local log_time = now()

  local duration
  if start then
    duration = log_time - start
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
    geoip_error         = ctx.geoip_error,
    worker = {
      id = WORKER_ID,
      pid = WORKER_PID,
      exiting = exiting()
    },
  }

  logger.add(entry)
end

function _M.init_worker()
  WORKER_PID = ngx.worker.pid()
  WORKER_ID  = ngx.worker.id()
  if LOG then
    logger.init_worker()
  end

  local metrics = require "doorbell.metrics"
  if metrics.enabled() then
    counter = metrics.prometheus:counter(
      "requests_total",
      "total number of incoming requests",
      { "status" }
    )

    if ip.geoip_enabled() then
      countries = metrics.prometheus:counter(
        "request_by_country",
        "total number of incoming requests, by origin country code",
        { "country" }
      )
    end
  end
end

---@param opts doorbell.config
function _M.init(opts)
  if opts.log_dir == "/dev/null" then
    LOG = false
  else
    logger.init(opts)
  end
end

return _M
