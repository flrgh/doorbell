local _M = {
  _VERSION = require("doorbell.constants").version,
}

local log = require "doorbell.log"

local ipmatcher = require "resty.ipmatcher"
local new_tab = require "table.new"

local assert = assert
local var = ngx.var
local exit = ngx.exit
local HTTP_FORBIDDEN = ngx.HTTP_FORBIDDEN

local private = ipmatcher.new({
  "10.0.0.0/8",
  "172.16.0.0/12",
  "192.168.0.0/16",
})

local localhost = ipmatcher.new({
  "127.0.0.0/8",
})

---@type resty.ipmatcher
local trusted

local geoip
local cache

---@param addr string
---@return string?
local function get_country(addr)
  if not geoip then
    return
  end

  return geoip:lookup_value(addr, "country", "iso_code")
end

---@param ctx doorbell.ctx
function _M.require_trusted(ctx)
  local ip = assert(var.realip_remote_addr, "no $realip_remote_addr")
  local trust = cache:get("trusted", ip)
  if trust == nil then
    trust = trusted:match(ip) or false
    cache:set("trusted", ip, trust)
  end

  if not trust then
    log.warn("denying connection from untrusted IP: ", ip)
    return exit(HTTP_FORBIDDEN)
  end

  ctx.trusted_ip = trusted
end

---@param addr string
---@param ctx doorbell.ctx
---@return doorbell.addr
function _M.get(addr, ctx)
  assert(cache, "doorbell.ip module not initialized")

  ---@type doorbell.addr
  local data = cache:get("addr", addr)

  if data then
    ctx.country_code = data.country
    ctx.localhost_ip = data.localhost_ip
    ctx.private_ip = data.private_ip
    return data
  end

  data = new_tab(0, 3)

  local code, err = get_country(addr)
  if code then
    ctx.country_code = code
    data.country = code
  else
    ctx.geoip_error = err
  end

  ctx.localhost_ip = localhost:match(addr) and true
  data.localhost_ip = ctx.localhost_ip

  ctx.private_ip = private:match(addr) and true
  data.private_ip = ctx.private_ip

  cache:set("addr", addr, data)

  return data
end

---@param opts table
function _M.init(opts)
  geoip = opts.geoip
  cache = opts.cache
  trusted = ipmatcher.new(assert(opts.trusted, "trusted ips missing"))
end

return _M
