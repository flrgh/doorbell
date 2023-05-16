local _M = {}

local request = require "doorbell.request"
local http   = require "doorbell.http"

local tb = require "tablepool"

local get_req_headers = request.get_headers
local get_path        = http.extract_path
local tostring = tostring
local sha = require "resty.sha256"

local pool    = "doorbell.auth.forwarded_request"
local narr    = 0
local nrec    = 10
local fetch   = tb.fetch
local release = tb.release


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
  if r then
    release(pool, r, true)
  end
end


return _M
