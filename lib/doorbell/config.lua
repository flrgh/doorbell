---@class doorbell.config : table
---
---@field allow            doorbell.rule[]
---@field approvals        doorbell.config.approvals
---@field asset_path       string
---@field auth             doorbell.config.auth
---@field base_url         string
---@field cache_size       integer
---@field deny             doorbell.rule[]
---@field geoip_asn_db     string
---@field geoip_city_db    string
---@field geoip_country_db string
---@field host             string
---@field log_path         string
---@field metrics          doorbell.metrics.config
---@field network_tags     doorbell.config.network_tags
---@field notify           doorbell.notify.config
---@field ota?             doorbell.ota.config
---@field redirect_uri     string
---@field runtime_path     string
---@field state_path       string
---@field trusted          string[]
---@field unauthorized     doorbell.unauthorized
---@field utc_offset       integer
---@field plugins          table<string, any>
---@field smtp             doorbell.config.smtp
---@field twilio           doorbell.verify.twilio.conf
local _M = {}

local util = require "doorbell.util"
local http = require "doorbell.http"
local cjson_safe = require "cjson.safe"
local env = require "doorbell.env"
local schema = require "doorbell.schema"

local byte = string.byte

local prefix = ngx.config.prefix()

local EMPTY = {}


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


---@param name string
---@param field doorbell.schema
---@param value any
---@return any value
local function unserialize(name, field, value)
  if not value then return end

  if not field then
    return value

  elseif field.type == "integer" or field.type == "number" then
    local parsed = tonumber(value)
    if parsed then
      return parsed
    end

    util.errorf("could not parse %s value %q as number", name, value)

  elseif field.type == "array" then
    return split_at_comma(value)
  end

  return value
end

local is_env
do
  local DOLLAR = byte("$")
  local LBRACE = byte("{")
  local RBRACE = byte("}")

  ---@param s string
  ---@return boolean
  function is_env(s)
    if type(s) ~= "string" then
      return false
    end

    local a, b = byte(s, 1, 2)
    return a == DOLLAR
       and b == LBRACE
       and byte(s, -1) == RBRACE
  end
end


---@param s string
---@param name string
---@param field doorbell.schema|nil
---@return any
local function get_env(s, name, field)
  local var = s:sub(3, -2)
               :gsub("^%s*(.-)%s*$", "%1")
               :upper()

  local value = env[var] or env.all[var]
  if field then
    value = unserialize(name, field, value)
  end

  return value
end

---@param name string|number
---@param value any
---@param field doorbell.schema
local function fill_from_env(name, value, field)
  field = field or EMPTY

  if is_env(value) then
    return get_env(value, name, field)
  end

  if type(value) == "table" then
    if field.type == "object" then
      local properties = field.properties or EMPTY

      for k, v in pairs(value) do
        value[k] = fill_from_env(k, v, properties[k])
      end

    elseif field.type == "array" then
      local items = field.items

      for i = 1, #value do
        value[i] = fill_from_env(i, value[i], items)
      end
    end
  end

  return value
end


---@return doorbell.config
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

  local fields = schema.config.fields

  for name, field in pairs(fields) do
    config[name] = field.default
  end

  local user_config = get_user_config()

  for k, v in pairs(user_config) do
    config[k] = v
  end

  for name, field in pairs(fields) do
    local value = env[name:upper()]
    if value then
      config[name] = unserialize(name, field, value)
    end
  end

  config.approvals = config.approvals or {}
  for name, property in pairs(fields.approvals.properties) do
    if config.approvals[name] == nil then
      config.approvals[name] = property.default
    end
  end

  fill_from_env("config", config, schema.config.entity)

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
