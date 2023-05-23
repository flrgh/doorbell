local _M = {
  _VERSION = require("doorbell.constants").version,
}

local log = require "doorbell.log"
local util = require "doorbell.util"

---@class doorbell.cache
local cache

local ipmatcher = require "resty.ipmatcher"
local split = require("ngx.re").split

local assert = assert
local var = ngx.var
local exit = ngx.exit
local HTTP_FORBIDDEN = ngx.HTTP_FORBIDDEN
local EMPTY = {}
local fmt = string.format
local encode_args = ngx.encode_args

local parse_ipv4 = ipmatcher.parse_ipv4
local parse_ipv6 = ipmatcher.parse_ipv6


---@param ip string
---@return 4|6|nil
local function valid_ip(ip)
  if parse_ipv4(ip) then
    return 4

  elseif parse_ipv6(ip) then
    return 6
  end
end


---@type resty.ipmatcher
local trusted

---@type table<string, string>
local country_names = require "doorbell.ip.countries"

local LOCATION_DB_FILE
local LOCATION_DB
local ASN_DB_FILE
local ASN_DB
local HAVE_COUNTRY_DB = false
local HAVE_CITY_DB = false
local HAVE_ASN_DB = false


---@param opts doorbell.config
local function init_geoip(opts)
  if opts.geoip_city_db then
    HAVE_CITY_DB = true
    HAVE_COUNTRY_DB = true
    LOCATION_DB_FILE = opts.geoip_city_db

  elseif opts.geoip_country_db then
    HAVE_COUNTRY_DB = true
    LOCATION_DB_FILE = opts.geoip_country_db

  elseif opts.geoip_db then -- legacy
    HAVE_COUNTRY_DB = true
    LOCATION_DB_FILE = opts.geoip_db
  end

  if opts.geoip_asn_db then
    HAVE_ASN_DB = true
    ASN_DB_FILE = opts.geoip_asn_db
  end

  if LOCATION_DB_FILE then
    local mmdb = require("geoip.mmdb")
    local db, err = mmdb.load_database(LOCATION_DB_FILE)
    if not db then
      log.alertf("failed loading GeoIP Location database file (%s): %s", LOCATION_DB_FILE, err)
    end
    LOCATION_DB = db
  end

  if ASN_DB_FILE then
    local mmdb = require("geoip.mmdb")
    local db, err = mmdb.load_database(ASN_DB_FILE)
    if not db then
      log.alertf("failed loading GeoIP ASN database file (%s): %s", ASN_DB_FILE, err)
    end

    ASN_DB = db
  end
end


---@param addr string
---@return string?
local function lookup_country_code(addr)
  if not LOCATION_DB then
    return
  end

  return LOCATION_DB:lookup_value(addr, "country", "iso_code")
end

local function is_trusted(ip)
  local trust = cache:get("trusted", ip)

  if trust == nil then
    trust = (trusted:match(ip) and true) or false
    cache:set("trusted", ip, trust)
  end

  return trust
end


---@param info doorbell.ip.info
local function add_map_links(info)
  if not info then return end

  info.search_link = nil
  info.map_link    = nil

  if info.city or info.country_code or info.region or info.postal_code then
    local query = {
      city         = info.city,
      country      = info.country or info.country_code,
      countrycodes = info.country_code,
      postalcode   = info.postal_code,
      state        = info.region,
    }

    info.search_link = "https://nominatim.openstreetmap.org/ui/search.html?"
                       .. encode_args(query)
  end


  if info.latitude and info.longitude then
    local zoom = 13

    -- Example:
    -- https://www.openstreetmap.org/?mlat=45.5760&mlon=-122.7018#map=13/45.5760/-122.7018
    info.map_link = fmt("https://www.openstreetmap.org/?mlat=%s&mlon=%s#map=%s/%s/%s",
                        info.latitude, info.longitude,
                        zoom,
                        info.latitude, info.longitude)
  end
end


---@class doorbell.ip.info : table
---
---@field addr             string
---@field asn              integer|nil
---@field city             string|nil
---@field continent        string
---@field continent_code   string
---@field country          string
---@field country_code     string
---@field latitude         number|nil
---@field longitude        number|nil
---@field map_link         string|nil
---@field org              string|nil
---@field postal_code      string|nil
---@field region           string|nil
---@field region_code      string|nil
---@field search_link      string|nil
---@field time_zone        string|nil


---@return doorbell.ip.info?
local function get_ip_info(addr)
  local info = cache:get("geoip-info", addr)
  if info ~= nil then
    return info or nil
  end

  local geo
  if LOCATION_DB then
    geo = LOCATION_DB:lookup(addr)
  end

  local asn
  if HAVE_ASN_DB then
    asn = ASN_DB:lookup(addr)
  end

  if not geo and not asn then
    cache:set("geoip-info", addr, false)
    return
  end

  asn = asn or EMPTY
  geo = geo or EMPTY


  local location     = geo.location or EMPTY
  local country      = geo.country or EMPTY
  local reg_country  = geo.registered_country or EMPTY
  local continent    = geo.continent or EMPTY
  local postal       = geo.postal or EMPTY
  local subdiv       = (geo.subdivisions or EMPTY)[1] or EMPTY
  local city         = geo.city or EMPTY

  info = {
    addr           = addr,
    asn            = asn.autonomous_system_number,
    org            = asn.autonomous_system_organization,
    country        = (country.names and country.names.en)
                     or (reg_country.names and reg_country.names.en)
                     or country.geoname_id,
    country_code   = country.iso_code or reg_country.iso_code,
    city           = (city.names or EMPTY).en or city.geoname_id,
    latitude       = location.latitude,
    longitude      = location.longitude,
    map_link       = "", -- placeholder for table size
    search_link    = "", -- placeholder for table size
    network        = geo.network or asn.network,
    time_zone      = location.time_zone,
    postal_code    = postal.code,
    continent      = (continent.names or EMPTY).en,
    continent_code = continent.code or continent.geoname_id,
    region         = (subdiv.names or EMPTY).en or subdiv.geoname_id,
    region_code    = subdiv.iso_code or subdiv.geoname_id,
  }

  add_map_links(info)

  cache:set("geoip-info", addr, info)

  return info
end


_M.private_cidrs = {
  "10.0.0.0/8",
  "172.16.0.0/12",
  "192.168.0.0/16",
}

local private_matcher = ipmatcher.new(_M.private_cidrs)

_M.private = private_matcher

_M.localhost_cidrs = { "127.0.0.0/8", "::1/128" }

local localhost_matcher = ipmatcher.new(_M.localhost_cidrs)

_M.localhost = localhost_matcher


---@param ip string
---@return boolean
local function is_private(ip)
  local private = cache:get("is-private", ip)
  if private == nil then
    private = (private_matcher:match(ip)
               or localhost_matcher:match(ip)
               and true) or false

    cache:set("is-private", ip, private)
  end

  return private
end



---@param ctx doorbell.ctx
---@param route doorbell.route
function _M.require_trusted_proxy(ctx, route)
  if route.allow_untrusted ~= true and not ctx.is_trusted_proxy then
    log.warn("denying connection from untrusted IP: ", ctx.client_addr)
    return exit(HTTP_FORBIDDEN)
  end
end


---@return boolean
function _M.geoip_enabled()
  return (LOCATION_DB and true) or false
end


---@return boolean
function _M.have_country_info()
  return HAVE_COUNTRY_DB
end

---@return boolean
function _M.have_city_info()
  return HAVE_CITY_DB
end

---@return boolean
function _M.have_asn_info()
  return HAVE_ASN_DB
end


---@param code string
---@return string?
function _M.get_country_name(code)
  return code and country_names[code]
end


---@param addr string
---@return string? country_code
---@return string? country_name_or_error
local function get_country(addr)
  if not LOCATION_DB then return nil, "geoip not enabled" end

  assert(cache, "doorbell.ip module not initialized")

  local country = cache:get("geoip", addr)

  if country == false then
    return nil, nil
  elseif country then
    return country, country_names[country]
  end

  local err
  country, err = lookup_country_code(addr)
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


---@param addr string
---
---@return integer? asn
---@return string?  org
---@return string?  error
function _M.get_net_info(addr)
  if not ASN_DB then return nil, nil, "asn not enabled" end

  assert(cache, "doorbell.ip module not initialized")

  local info = get_ip_info(addr)
  if not info then
    return nil, nil, "no IP info for " .. addr
  end

  return info.asn, info.org
end
local get_net_info = _M.get_net_info


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


local parse_forwarded
do
  local buf = {}
  local clear = require "table.clear"

  ---@param header? string
  ---@return string? addr
  function parse_forwarded(header)
    if type(header) ~= "string" then return end

    local parsed = cache:get("x-forwarded-for", header)
    if parsed ~= nil then
      return parsed or nil
    end

    clear(buf)
    split(header, ", *", "oj", nil, 0, buf)

    parsed = get_forwarded(buf)

    if parsed then
      cache:set("x-forwarded-for", header, parsed)
    else
      cache:set("x-forwarded-for", header, false)
    end

    return parsed
  end
end


---@param addr string
---
---@return doorbell.ip.info? info
---@return string? error
---@return integer? status_code
function _M.get_ip_info(addr)
  if not LOCATION_DB and not ASN_DB then
    return nil, "geoip is not enabled", 501
  end

  local info = get_ip_info(addr)
  if info then
    return info
  end

  return nil, "no ip info found", 404
end


---@param addr string
---@return table? info
---@return string? error
---@return integer? status_code
function _M.get_raw_ip_info(addr)
  if not LOCATION_DB and not ASN_DB then
    return nil, "geoip is not enabled", 501
  end

  local location, asn

  if LOCATION_DB then
    location = LOCATION_DB:lookup(addr)
  end

  if ASN_DB then
    asn = ASN_DB:lookup(addr)
  end

  if not location and not asn then
    return nil, "no ip info found", 404
  end

  local info = location or {}
  for k, v in pairs(asn or EMPTY) do
    info[k] = v
  end

  return info
end

--- Decorate the request context with IP-related fields:
---
--- - client_addr
--- - forwarded_addr
--- - is_trusted_proxy
--- - geoip_country_code
--- - geoip_net_asn
--- - geoip_net_org
---
---@param ctx doorbell.ctx
function _M.init_request_ctx(ctx)
  local client_addr = var.realip_remote_addr or var.remote_addr
  ctx.client_addr = client_addr
  ctx.is_trusted_proxy = false

  local forwarded_addr = client_addr

  if is_trusted(client_addr) then
    ctx.is_trusted_proxy = true

    local header = var.http_x_forwarded_for or var.http_x_real_ip
    if header then
      local parsed = parse_forwarded(header)

      if parsed then
        forwarded_addr = parsed
      else
        log.err("failed to parse X-Forwarded-For header: '", header, "'")
      end
    end
  end

  ctx.forwarded_addr = forwarded_addr

  if not is_private(forwarded_addr) then
    ctx.geoip_country_code = get_country(forwarded_addr)
    ctx.geoip_net_asn, ctx.geoip_net_org = get_net_info(forwarded_addr)

  else
    ctx.geoip_net_asn = 0
  end
end


---@param addr string
---@param raw? string
---@return table? info
---@return string? error
---@return integer? status_code
function _M.info_api(addr, raw)
  if not valid_ip(addr) then
    return nil, "invalid IP address", 400
  end

  if not LOCATION_DB and not ASN_DB then
    return nil, "geoip is not enabled", 501
  end

  if util.truthy(raw) then
    return _M.get_raw_ip_info(addr)

  else
    return _M.get_ip_info(addr)
  end
end


_M.is_valid = valid_ip


---@param opts doorbell.config
function _M.init(opts)
  init_geoip(opts)

  local trusted_cidrs = opts.trusted
  if trusted_cidrs then
    trusted = assert(ipmatcher.new(trusted_cidrs))
  else
    log.warnf("using default trusted IP range (%s)", table.concat(_M.localhost_cidrs, ","))
    trusted = _M.localhost
  end

  cache = require "doorbell.cache"
end


return _M
