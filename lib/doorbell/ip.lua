local _M = {
  _VERSION = require("doorbell.constants").version,
}

local log = require "doorbell.log"
local cache = require "doorbell.cache"

local ipmatcher = require "resty.ipmatcher"

local assert = assert
local var = ngx.var
local exit = ngx.exit
local HTTP_FORBIDDEN = ngx.HTTP_FORBIDDEN

---@type resty.ipmatcher
local trusted

local geoip

---@param addr string
---@return string?
local function lookup(addr)
  if not geoip then
    return
  end

  return geoip:lookup_value(addr, "country", "iso_code")
end

_M.private = ipmatcher.new({
  "10.0.0.0/8",
  "172.16.0.0/12",
  "192.168.0.0/16",
})

_M.localhost = ipmatcher.new({
  "127.0.0.0/8",
})


---@param ctx doorbell.ctx
function _M.require_trusted(ctx)
  assert(cache, "doorbell.ip module not initialized")

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
---@return string? country
---@return string? error
function _M.get_country(addr)
  if not geoip then return nil, "geoip not enabled" end

  assert(cache, "doorbell.ip module not initialized")

  local country = cache:get("geoip", addr)

  if country then
    return country
  end

  local err
  country, err = lookup(addr)

  if err then
    return nil, err
  elseif not country then
    cache:set("addr", addr, false)

    return
  end

  cache:set("addr", addr, country)

  return country
end

---@param opts doorbell.config
function _M.init(opts)
  if opts.geoip_db then
    local mmdb = require("geoip.mmdb")
    local db, err = mmdb.load_database(opts.geoip_db)
    if not db then
      log.alertf("failed loading geoip database file (%s): %s", opts.geoip_db, err)
    end
    geoip = db
  end

  trusted = assert(ipmatcher.new(opts.trusted))
end

return _M
