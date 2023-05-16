---@class doorbell.config : table
---
---@field allow            doorbell.rule[]
---@field asset_path       string
---@field base_url         string
---@field cache_size       integer
---@field deny             doorbell.rule[]
---@field geoip_asn_db     string
---@field geoip_city_db    string
---@field geoip_country_db string
---@field host             string
---@field log_path         string
---@field notify           doorbell.notify.config
---@field runtime_path     string
---@field state_path       string
---@field trusted          string[]
---@field metrics          doorbell.metrics.config
---@field ota?             doorbell.ota.config
---@field unauthorized     doorbell.unauthorized
---@field redirect_uri     string
---@field utc_offset       integer
---@field approvals        doorbell.config.approvals
local _M = {
  _VERSION = require("doorbell.constants").version,
}

local util = require "doorbell.util"
local http = require "doorbell.http"
local cjson_safe = require "cjson.safe"
local env = require "doorbell.env"
local schema = require "doorbell.schema"

local prefix = ngx.config.prefix()


---@param s string
---@return string[]
local function split_at_comma(s)
  local items = util.array()
  local _ = s:gsub("[^,]+", function(word)
    word = word:gsub("^%s+", ""):gsub("%s+$", "")
    table.insert(items, word)
  end)

  return items
end


local function unserialize(field, value)
  if not value then return end

  if field.type == "integer" or field.type == "number" then
    local parsed = tonumber(value)
    if parsed then
      return parsed
    end

    util.errorf("could not parse %s value %q as number", field.name, value)

  elseif field.type == "array" then
    return split_at_comma(value)
  end

  return value
end


local function get_user_config()
  local source, config_string

  if env.CONFIG_STRING then
    source = "env://DOORBELL_CONFIG_STRING"
    config_string = env.CONFIG_STRING

  elseif env.CONFIG then
    source = "file://" .. env.CONFIG
    local err
    config_string, err = util.read_file(env.CONFIG)

    if not config_string then
      util.errorf("failed to open user config file %s: %s",
                  source, err)
    end

  else
    local fname = util.join(prefix, "config.json")
    source = "file://" .. fname
    config_string = util.read_file(fname) or "{}"
  end

  local config, err = cjson_safe.decode(config_string)
  if err then
    util.errorf("config (%q) JSON is invalid: %s", source, err)

  elseif type(config) ~= "table" then
    util.errorf("config (%q) JSON is not a table", source)
  end

  return config
end


function _M.init()
  ---@type doorbell.config
  local config = {}

  for name, field in pairs(schema.config.fields) do
    config[name] = field.default
  end

  local user_config = get_user_config()

  for k, v in pairs(user_config) do
    config[k] = v
  end

  for name, field in pairs(schema.config.fields) do
    local value = env[name:upper()]
    if value then
      config[name] = unserialize(field, value)
    end
  end

  config.approvals = config.approvals or {}
  for name, property in pairs(schema.config.fields.approvals.properties) do
    if config.approvals[name] == nil then
      config.approvals[name] = property.default
    end
  end

  assert(schema.config.input.validate(config))

  do
    local parsed = http.parse_url(config.base_url)
    if not parsed or not parsed.host then
      util.errorf("failed to parse hostname from base_url: %s", config.base_url)
    end
    config.host = parsed.host
  end

  assert(schema.config.entity.validate(config))

  for k, v in pairs(config) do
    _M[k] = v
  end

end

return _M
