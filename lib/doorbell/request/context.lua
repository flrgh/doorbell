local _M = {}


local ip = require "doorbell.ip"
local util = require "doorbell.util"
local http = require "doorbell.http"


local ip_init_request = ip.init_request_ctx
local uuid            = util.uuid
local get_query       = http.request.get_query_args
local req_headers     = http.request.get_headers
local get_json        = http.request.get_json_body
local ngx             = ngx
local var             = ngx.var
local get_method      = ngx.req.get_method
local get_path        = http.extract_path


---@class doorbell.ctx : table
---
---@field id                string
---
---@field client_addr         string
---@field forwarded_addr      string
---@field is_trusted_proxy    boolean
---@field forwarded_request   doorbell.forwarded_request
---@field geoip_country_code? string
---@field geoip_net_asn?      integer
---@field geoip_net_org?      string
---
---@field no_log            boolean
---@field no_metrics        boolean
---@field route             doorbell.route
---
---@field rule              doorbell.rule
---@field rule_cache_hit    boolean
---
---@field method            ngx.http.method
---@field query?            doorbell.http.query
---@field json?             table
---@field headers?          doorbell.http.headers
---@field uri               string
---@field path              string
---@field scheme            string
---
---@field template?         any


---@param ctx? table
---@return doorbell.ctx
function _M.new(ctx)
  ---@type doorbell.ctx
  ctx = ctx or ngx.ctx

  ctx.id = uuid()

  ctx.no_log = false
  ctx.no_metrics = false

  ip_init_request(ctx)

  ctx.schema = var.scheme
  ctx.method = get_method()

  local uri = var.request_uri
  ctx.uri = uri
  ctx.path = get_path(ctx.uri)


  return ctx
end


--- Cached method for reading request headers.
---
---@param ctx doorbell.ctx
---@return doorbell.http.headers
function _M.get_request_headers(ctx)
  local headers = ctx.headers

  if not headers then
    headers = req_headers()
    ctx.headers = headers
  end

  return headers
end


--- Cached method for parsing the request query string args.
---
---@param ctx doorbell.ctx
---@return doorbell.http.query
function _M.get_query_args(ctx)
  local query = ctx.query

  if not query then
    query = get_query()
    ctx.query = query
  end

  return query
end

local get_query_args = _M.get_query_args


---@param ctx doorbell.ctx
---@param name string
---@return any?
function _M.get_query_arg(ctx, name)
  return get_query_args(ctx)[name]
end


--- Cached method for parsing the request JSON body.
---
---@generic T
---@param ctx doorbell.ctx
---@param typ? `T`
---@param optional? boolean
---@return T?
function _M.get_json_body(ctx, typ, optional)
  local json = ctx.json
  if json == nil then
    json = get_json(typ, optional)
  end

  return json
end

return _M