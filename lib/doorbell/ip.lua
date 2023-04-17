local _M = {
  _VERSION = require("doorbell.constants").version,
}

local log = require "doorbell.log"
local cache = require "doorbell.cache"

local ipmatcher = require "resty.ipmatcher"
local split = require("ngx.re").split

local assert = assert
local var = ngx.var
local exit = ngx.exit
local HTTP_FORBIDDEN = ngx.HTTP_FORBIDDEN
local EMPTY = {}

local parse_ipv4 = ipmatcher.parse_ipv4
local parse_ipv6 = ipmatcher.parse_ipv6


---@param ip string
---@return boolean
local function valid_ip(ip)
  return (parse_ipv4(ip) or parse_ipv6(ip)) and true or false
end


---@type resty.ipmatcher
local trusted

---@type table<string, string>
local country_names = require "doorbell.ip.countries"

local geoip

---@param addr string
---@return string?
local function lookup(addr)
  if not geoip then
    return
  end

  return geoip:lookup_value(addr, "country", "iso_code")
end

local function is_trusted(ip)
  local trust = cache:get("trusted", ip)

  if trust == nil then
    trust = (trusted:match(ip) and true) or false
    cache:set("trusted", ip, trust)
  end

  return trust
end


---@class doorbell.ip.info : table
---
---@field addr             string
---@field city             string|nil
---@field continent        string
---@field continent_code   string
---@field country          string
---@field country_code     string
---@field latitude         number|nil
---@field longitude        number|nil
---@field postal_code      string|nil
---@field region           string|nil
---@field region_code      string|nil
---@field time_zone        string|nil


---@return doorbell.ip.info
local function get_ip_info(addr)
  local info = cache:get("geoip-info", addr)
  if info then
    return info
  end

  local geo = geoip:lookup(addr)
  if not geo then
    cache:set("geoip-info", addr, false)
    return { addr = addr, message = "no geoip data found" }
  end

  local location     = geo.location or EMPTY
  local country      = geo.country or EMPTY
  local reg_country  = geo.registered_country or EMPTY
  local continent    = geo.continent or EMPTY
  local postal       = geo.postal or EMPTY
  local subdiv       = (geo.subdivisions or EMPTY)[1] or EMPTY
  local city         = geo.city or EMPTY

  info = {
    addr           = addr,
    country        = (country.names and country.names.en)
                     or (reg_country.names and reg_country.names.en)
                     or country.geoname_id,
    country_code   = country.iso_code or reg_country.iso_code,
    city           = (city.names or EMPTY).en or city.geoname_id,
    latitude       = location.latitude,
    longitude      = location.longitude,
    time_zone      = location.time_zone,
    postal_code    = postal.code,
    continent      = (continent.names or EMPTY).en,
    continent_code = continent.code or continent.geoname_id,
    region         = (subdiv.names or EMPTY).en or subdiv.geoname_id,
    region_code    = subdiv.iso_code or subdiv.geoname_id,
  }

  cache:set("geoip-info", addr, info)

  return info
end



_M.private_cidrs = {
  "10.0.0.0/8",
  "172.16.0.0/12",
  "192.168.0.0/16",
}

_M.private = ipmatcher.new(_M.private_cidrs)

_M.localhost_cidrs = { "127.0.0.0/8", "::1/128" }

_M.localhost = ipmatcher.new(_M.localhost_cidrs)


---@param ctx doorbell.ctx
function _M.require_trusted(ctx)
  assert(cache, "doorbell.ip module not initialized")

  local ip = assert(var.realip_remote_addr, "no $realip_remote_addr")
  local trust = cache:get("trusted", ip)
  if trust == nil then
    trust = (trusted:match(ip) and true) or false
    cache:set("trusted", ip, trust)
  end

  if not trust then
    log.warn("denying connection from untrusted IP: ", ip)
    return exit(HTTP_FORBIDDEN)
  end

  ctx.trusted_ip = trust
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


local function get_forwarded(forwarded, pos)
  pos = pos or #forwarded
  local addr = forwarded[pos]

  if not valid_ip(addr) then
    return
  end

  if pos > 1 and is_trusted(addr) then
    return get_forwarded(forwarded, pos - 1)
  end

  return addr
end

---@return string
function _M.get_forwarded_ip()
  local client_ip = var.realip_remote_addr or var.remote_addr

  if is_trusted(client_ip) then
    local header = var.http_x_forwarded_for or var.http_x_real_ip
    if header then
      local all = split(header, ", *", nil, nil, 0)
      return get_forwarded(all) or client_ip
    end
  end

  return client_ip
end



---@param addr string
---
---@return doorbell.ip.info info
function _M.get_ip_info(addr)
  if not geoip then
    return { addr = addr, message = "geoip is not enabled" }
  end

  return get_ip_info(addr)
end


_M.is_valid = valid_ip

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

  local trusted_cidrs = opts.trusted
  if trusted_cidrs then
    trusted = assert(ipmatcher.new(trusted_cidrs))
  else
    log.warnf("using default trusted IP range (%s)", table.concat(_M.localhost_cidrs, ","))
    trusted = _M.localhost
  end

end


return _M
