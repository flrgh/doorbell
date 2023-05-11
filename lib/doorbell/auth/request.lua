local _M = {}

local request = require "doorbell.request"
local http   = require "doorbell.http"

local tb = require "tablepool"

local get_req_headers = request.get_headers
local get_path        = http.extract_path

local pool    = "doorbell.auth.forwarded_request"
local narr    = 0
local nrec    = 8
local fetch   = tb.fetch
local release = tb.release

---@class doorbell.forwarded_request : table
---@field addr     string
---@field asn?     integer
---@field scheme   string
---@field host     string
---@field uri      string
---@field org?     string
---@field path     string
---@field method   string
---@field ua       string
---@field country? string
---
---@field geoip_country_err? string
---@field geoip_asn_err?     string


---@param  ctx                         doorbell.ctx
---@param  headers?                    doorbell.http.headers
---@return doorbell.forwarded_request? request
---@return string?                     error
function _M.new(ctx, headers)
  if not ctx.is_trusted_proxy then
    return nil, "untrusted client IP address"
  end

  local r = fetch(pool, narr, nrec)
  ctx.forwarded_request = r

  headers = headers or get_req_headers(ctx)

  local addr = ctx.forwarded_addr
  if not addr then
    return nil, "missing x-forwarded-for"
  end
  r.addr = ctx.forwarded_addr

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
  r.path = get_path(uri)

  local method = headers["x-forwarded-method"]
  if not method then
    return nil, "missing x-forwarded-method"
  end
  r.method = method

  r.ua = headers["user-agent"]

  r.country = ctx.geoip_country_code

  r.asn = ctx.geoip_net_asn
  r.org = ctx.geoip_net_org

  return r
end


---@param ctx doorbell.ctx
function _M.release(ctx)
  local r = ctx.forwarded_request
  if r then
    release(pool, r, true)
  end
end


return _M
