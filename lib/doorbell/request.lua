local _M = {
  _VERSION = require("doorbell.constants").version,
}

local ip_get = require("doorbell.ip").get

local tb = require "tablepool"

local get_headers = ngx.req.get_headers
local fetch = tb.fetch
local release = tb.release

local pool = "doorbell.request"
local narr = 0
local nrec = 8

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

  local ip = ip_get(addr, ctx)
  r.country = ip.country

  return r
end

function _M.release(ctx)
  local r = ctx.request
  if r then
    release(pool, r, true)
  end
end

function _M.no_metrics(ctx)
  ctx.no_metrics = true
end

function _M.no_log(ctx)
  ctx.no_log = true
end

return _M
