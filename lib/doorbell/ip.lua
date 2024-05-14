local _M = {}

local log = require("doorbell.log").with_namespace("ip")
local util = require "doorbell.util"

---@class doorbell.cache
local cache

---@class doorbell.cache
local cache_basic

---@class doorbell.cache
local cache_geo

---@class resty.ipmatcher
local ipmatcher
do
  -- resty.ipmatcher logs a bunch of things at INFO level.
  --
  --- hack it to DEBUG to preserve our sanity

  local ngx_info = ngx.INFO
  ngx.INFO = ngx.DEBUG -- luacheck: ignore
  package.loaded["resty.ipmatcher"] = nil
  ipmatcher = require "resty.ipmatcher"
  ngx.INFO = ngx_info -- luacheck: ignore
end

local split = require("ngx.re").split

local assert = assert
local var = ngx.var
local EMPTY = {}
local fmt = string.format
local encode_args = ngx.encode_args
local type = type

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
local trusted_ips

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
  return (trusted_ips:match(ip) and true) or false
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



---@class doorbell.ip.info.basic : table
---
---@field asn         integer
---@field country     string
---@field net_tag     string
---@field org         string
---@field private     boolean
---@field trusted     boolean


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
  local info = cache_geo:raw_get(addr)
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
    cache_geo:raw_set(addr, false)
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

  cache_geo:raw_set(addr, info)

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
  return (private_matcher:match(ip)
          or localhost_matcher:match(ip)
          and true) or false
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
---
---@return integer? asn
---@return string?  org
---@return string?  error
function _M.get_net_info(addr)
  if not ASN_DB then return nil, nil, "asn not enabled" end

  local info = get_ip_info(addr)
  if not info then
    return nil, nil, "no IP info for " .. addr
  end

  return info.asn, info.org
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

local get_network_tag, init_network_tags
do
  local DEFAULT_NET_TAGS = {
    ["10.0.0.0/8"]     = "LAN",
    ["172.16.0.0/12"]  = "LAN",
    ["192.168.0.0/16"] = "LAN",
    ["127.0.0.0/8"]    = "localhost",
    ["default"]        = "WAN",
  }

  ---@class doorbell.ip.network.tag : table
  ---
  ---@field matcher   resty.ipmatcher
  ---@field network   string
  ---@field tag       string
  ---@field mask_bits integer

  ---@type doorbell.ip.network.tag[]
  local TAGS
  local TAGS_N = 0

  ---@type string
  local DEFAULT

  ---@param addr string
  ---@return string
  function get_network_tag(addr)
    local tag = DEFAULT or "default"

    for i = 1, TAGS_N do
      local t = TAGS[i]
      if t.matcher:match(addr) then
        tag = t.tag
        break
      end
    end

    return tag
  end


  ---@param network_tags doorbell.config.network_tags
  function init_network_tags(network_tags)
    network_tags = network_tags or DEFAULT_NET_TAGS
    ---@type doorbell.ip.network.tag[]
    local tags = {}

    for cidr, tag in pairs(network_tags) do
      ---@type doorbell.ip.network.tag
      if cidr == "default" then
        assert(DEFAULT == nil, "duplicate default network tag")

        DEFAULT = tag
        goto continue
      end

      local m = ngx.re.match(cidr, "([^/]+)(/(.+))?")
      local addr, mask = cidr, nil

      if m then
        addr = m[1]
        mask = m[3]
      end

      local typ = valid_ip(addr)
      assert(type ~= nil, "invalid CIDR: " .. cidr)

      if typ == 4 then
        mask = mask or 32

      elseif typ == 6 then
        mask = mask or 128
      end

      local network = addr .. "/" .. tostring(mask)

      mask = tonumber(mask)
      assert(mask ~= nil, "invalid CIDR: " .. cidr)


      table.insert(tags, {
        matcher   = assert(ipmatcher.new({ network })),
        network   = network,
        tag       = tag,
        mask_bits = mask,
      })

      ::continue::
    end

    table.sort(tags, function(a, b)
      if a.mask_bits ~= b.mask_bits then
        return a.mask_bits > b.mask_bits
      end

      return a.network > b.network
    end)

    TAGS = tags
    TAGS_N = #tags
  end
end


---@param addr string
---@return doorbell.ip.info.basic
local function get_basic_info(addr)
  local info = cache_basic:raw_get(addr)

  if info ~= nil then
    return info
  end

  local trusted = is_trusted(addr)
  local private = is_private(addr)

  local country

  local asn = 0
  local org

  if not private then
    country = lookup_country_code(addr)

    if ASN_DB then
      local data = ASN_DB:lookup(addr)
      if data then
        asn = data.autonomous_system_number
        org = data.autonomous_system_organization
      end
    end
  end

  local tag = get_network_tag(addr)

  info = {
    asn     = asn,
    country = country,
    net_tag = tag,
    org     = org,
    private = private,
    trusted = trusted,
  }

  cache_basic:raw_set(addr, info)

  return info
end


--- Decorate the request context with IP-related fields:
---
--- - client_addr
--- - client_network_tag
--- - forwarded_addr
--- - forwarded_network_tag
--- - is_trusted_proxy
--- - geoip_country_code
--- - geoip_net_asn
--- - geoip_net_org
---
---@param ctx doorbell.ctx
function _M.init_request_ctx(ctx)
  local client_addr = var.realip_remote_addr or var.remote_addr
  ctx.client_addr = client_addr

  local client = get_basic_info(client_addr)
  ctx.client_network_tag = client.net_tag

  local forwarded_addr = client_addr

  if client.trusted then
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

  if forwarded_addr == client_addr then
    ctx.geoip_country_code      = client.country
    ctx.geoip_net_asn           = client.asn
    ctx.geoip_net_org           = client.org
    ctx.forwarded_network_tag   = client.net_tag
    ctx.is_trusted_downstream   = ctx.is_trusted_proxy

  else
    local forwarded = get_basic_info(forwarded_addr)
    ctx.geoip_country_code      = forwarded.country
    ctx.geoip_net_asn           = forwarded.asn
    ctx.geoip_net_org           = forwarded.org
    ctx.forwarded_network_tag   = forwarded.net_tag
    ctx.is_trusted_downstream   = forwarded.trusted
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
    trusted_ips = assert(ipmatcher.new(trusted_cidrs))
  else
    log.warnf("using default trusted IP range (%s)", table.concat(_M.localhost_cidrs, ","))
    trusted_ips = _M.localhost
  end

  init_network_tags(opts.network_tags)

  cache       = require("doorbell.cache")
  cache_basic = require("doorbell.cache").new("ip-basic", 2000)
  cache_geo   = require("doorbell.cache").new("ip-geo", 2000)
end


return _M
