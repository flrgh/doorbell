local _M = {
  _VERSION = require("doorbell.constants").version,
}

local get_country = require("doorbell.ip").get_country
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

local pool    = "doorbell.request"
local narr    = 0
local nrec    = 8
local fetch   = tb.fetch
local release = tb.release

local WORKER_ID, WORKER_PID

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

  local country, err = get_country(addr)
  r.country = country
  ctx.country_code = country
  ctx.geoip_error = err

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
  if ctx.no_log then
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
  logger.init_worker()
end

---@param opts doorbell.config
function _M.init(opts)
  logger.init(opts)
end

return _M
