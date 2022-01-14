local _M = {
  _VERSION = require("doorbell.constants").version,
}

local log = require "doorbell.log"
local cache = require "doorbell.cache"
local util = require "doorbell.util"

local ipmatcher = require "resty.ipmatcher"

local assert = assert
local var = ngx.var
local exit = ngx.exit
local HTTP_FORBIDDEN = ngx.HTTP_FORBIDDEN

---@type resty.ipmatcher
local trusted

---@type table<string, string>
local country_names

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

---@return boolean
function _M.geoip_enabled()
  return (geoip and true) or false
end

---@param code string
---@return string?
function _M.get_country_name(code)
  return code and country_names[code]
end

---@param addr string
---@return string? country_code
---@return string? country_name_or_error
function _M.get_country(addr)
  if not geoip then return nil, "geoip not enabled" end

  assert(cache, "doorbell.ip module not initialized")

  local country = cache:get("geoip", addr)

  if country == false then
    return nil, nil
  elseif country then
    return country, country_names[country]
  end

  local err
  country, err = lookup(addr)
  if country then
    cache:set("geoip", addr, country)
    return country, country_names[country]
  end

  if err == "failed to find entry" or err == nil then
    cache:set("geoip", addr, false)
    err = nil
  end

  return nil, err
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

    local fname = opts.asset_path .. "/data/country-codes-to-names.json"
    country_names, err = util.read_json_file(fname)
    if not country_names then
      log.errf("failed loading country code map from %s: %s", fname, err)
      country_names = {}
    end
  end

  trusted = assert(ipmatcher.new(opts.trusted))
end

return _M
