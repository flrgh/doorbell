---@class doorbell.auth.forwarded-request
local _M = {}

local request = require "doorbell.request"
local uri_lib = require "doorbell.util.uri"

local tb = require "tablepool"

local get_req_headers = request.get_headers
local tostring = tostring
local type     = type
local concat   = table.concat
local lower    = string.lower
local sha = require "resty.sha256"

local normalize_forwarded = uri_lib.normalize_forwarded

local pool    = "doorbell.auth.forwarded_request"
local narr    = 0
local nrec    = 10
local fetch   = tb.fetch
local release = tb.release


---@param  headers  doorbell.http.headers
---@param  name     string
---@return string?  value
---@return string?  err
local function required_header(headers, name)
  local v = headers[name]

  if not v then
    return nil, "missing " .. name
  end

  local typ = type(v)

  if typ == "string" and v ~= "" then
    return v

  elseif typ == "table" then
    return nil, "duplicate " .. name
  end

  return nil, "empty/invalid " .. name
end


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
  r.addr = addr

  local scheme, err = required_header(headers, "x-forwarded-proto")
  if not scheme then
    return nil, err
  end
  scheme = lower(scheme)

  local host
  host, err = required_header(headers, "x-forwarded-host")
  if not host then
    return nil, err
  end

  local uri
  uri, err = required_header(headers, "x-forwarded-uri")
  if not uri then
    return nil, err
  end

  local method
  method, err = required_header(headers, "x-forwarded-method")
  if not method then
    return nil, err
  end

  local hostname, path
  hostname, path, err = normalize_forwarded(scheme, host, uri)
  if not hostname then
    return nil, err
  end

  r.scheme = scheme
  r.host   = hostname
  r.uri    = uri
  r.path   = path
  r.method = method

  local ua = headers["user-agent"]
  if type(ua) == "table" then
    ua = concat(ua, ",")
  end
  r.ua = ua

  r.country = ctx.geoip_country_code
  r.asn = ctx.geoip_net_asn
  r.org = ctx.geoip_net_org

  return r
end


do
  local pid = ngx.worker.pid
  local now = ngx.now
  local random = math.random
  local update_time = ngx.update_time

  local checksum = sha:new()
  local to_hex = require("resty.string").to_hex
  local DELIM = "|"

  local SALT

  local function calculate_salt()
    update_time()
    SALT = tostring(pid())
        .. DELIM
        .. tostring(random())
        .. DELIM
        .. tostring(now())
        .. DELIM
        .. tostring(random())
  end

  calculate_salt()

  --- generate a cache key for a request object
  ---@param  req doorbell.forwarded_request
  ---@return string
  function _M.cache_key(req)
    checksum:reset()
    checksum:update(SALT)

    -- scheme and uri are not included for now

    checksum:update(req.method)
    checksum:update(req.host)
    checksum:update(req.path)
    checksum:update(req.ua or "")
    checksum:update(req.country or "")
    checksum:update(tostring(req.asn) or "0")
    checksum:update(req.org or "")

    local final = to_hex(checksum:final())

    return req.addr
        .. DELIM .. req.host
        .. DELIM .. final
  end

  function _M.reset_cache()
    calculate_salt()
  end
end


---@param ctx doorbell.ctx
function _M.release(ctx)
  local r = ctx.forwarded_request
  ctx.forwarded_request = nil
  if r then
    r.addr = nil
    r.asn = nil
    r.country = nil
    r.host = nil
    r.method = nil
    r.org = nil
    r.path = nil
    r.scheme = nil
    r.ua = nil
    r.uri = nil
    release(pool, r, true)
  end
end


return _M
