local _M = {}

local logger  = require "doorbell.log.request"
local context = require "doorbell.request.context"
local const   = require "doorbell.constants"
local log     = require "doorbell.log"
local metrics = require "doorbell.metrics"


local ngx              = ngx
local var              = ngx.var
local now              = ngx.now
local http_version     = ngx.req.http_version
local start_time       = ngx.req.start_time
local get_resp_headers = ngx.resp.get_headers
local tonumber         = tonumber
local tostring         = tostring
local update_time      = ngx.update_time

local WORKER_ID, WORKER_PID
local LOG = true

_M.new              = context.new
_M.get_headers      = context.get_request_headers
_M.get_query_args   = context.get_query_args
_M.get_json_body    = context.get_json_body
_M.get_query_arg    = context.get_query_arg
_M.get_header       = context.get_request_header
_M.get_post_args    = context.get_post_args
_M.get              = context.get


---@type table<string, doorbell.middleware>
_M.middleware = {}


---@param ctx doorbell.ctx
---@param route doorbell.route
function _M.middleware.pre_handler(ctx, route)
  if route.metrics_enabled == false then
    ctx.no_metrics = true
  end
end


---@param ctx doorbell.ctx
function _M.middleware.disable_logging(ctx)
  var.doorbell_log = 0
  ctx.no_log = true
end


function _M.middleware.enable_logging(ctx)
  var.doorbell_log = 1
  ctx.no_log = false
end


---@param ctx doorbell.ctx
function _M.log(ctx)
  local incomplete

  if not ctx.doorbell_init then
    log.warn("generating a JSON log entry for a request that was not properly ",
             "initialized--some log fields may be missing or incomplete")

    incomplete = true
  end

  if metrics.enabled() and not ctx.no_metrics then
    metrics.inc("requests_total", 1, { tostring(ngx.status) })

    if ctx.geoip_country_code then
      metrics.inc("requests_by_country", 1, { ctx.geoip_country_code })
    end

    local net = ctx.forwarded_network_tag
    if net then
      metrics.inc("requests_by_network", 1, { net })
    end

    local route = (ctx.route and ctx.route.id) or "NONE"
    metrics.inc("requests_by_route", 1, { route })
  end

  if LOG == false or ctx.no_log then
    return
  end

  local start = start_time()

  update_time()
  local log_time = now()

  local duration = tonumber(var.request_time)
  if not duration then
    duration = log_time - start
  end

  local res_size = tonumber(var.bytes_sent)
  local res_body_size
  if res_size then
    res_body_size = tonumber(var.body_bytes_sent)
  end

  ---@class doorbell.request.log.entry
  local entry = {
    -- client info
    addr                = ctx.forwarded_addr,
    network_tag         = ctx.forwarded_network_tag,
    client_addr         = ctx.client_addr,
    client_network_tag  = ctx.client_network_tag,
    country_code        = ctx.geoip_country_code,
    is_trusted_proxy    = ctx.is_trusted_proxy,
    auth_jwt            = ctx.auth_jwt,

    -- connection data
    connection          = tonumber(var.connection),
    connection_requests = tonumber(var.connection_requests),
    connection_time     = tonumber(var.connection_time),

    -- timings
    start_time          = start,
    log_time            = log_time,
    duration            = duration,

    -- request
    request_id             = ctx.id,
    request_http_version   = http_version(),
    request_http_method    = ctx.method,
    request_scheme         = ctx.scheme,
    request_http_host      = var.host,
    request_path           = ctx.path,
    request_query          = context.get_query_args(ctx),
    request_headers        = context.get_request_headers(ctx),
    request_uri            = ctx.uri,
    request_normalized_uri = var.uri,
    request_total_bytes    = tonumber(var.request_length),

    -- routing
    route_path = ctx.route and ctx.route.path,
    route_id   = ctx.route and ctx.route.id,

    -- response
    status               = ngx.status,
    response_headers     = get_resp_headers(1000),
    response_total_bytes = res_size,
    response_body_bytes  = res_body_size,

    -- rule match info
    rule                = ctx.rule,
    rule_cache_hit      = ctx.rule_cache_hit,
    forwarded_request   = ctx.forwarded_request,

    -- debug things
    worker_id           = WORKER_ID,
    worker_pid          = WORKER_PID,

    -- meta
    version = const.version,
    incomplete_entry = incomplete,
  }

  logger.add(entry)
end


function _M.init_worker()
  WORKER_PID = ngx.worker.pid()
  WORKER_ID  = ngx.worker.id()

  if LOG then
    logger.init_worker()
  end
end


---@param opts doorbell.config
function _M.init(opts)
  if opts.log_path == "/dev/null" then
    LOG = false
  else
    logger.init(opts)
  end
end

return _M
