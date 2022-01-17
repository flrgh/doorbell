---@class doorbell.config : table
---
---@field allow      doorbell.rule[]
---@field asset_path string
---@field base_url   string
---@field cache_size integer
---@field deny       doorbell.rule[]
---@field geoip_db   string
---@field host       string
---@field log_path   string
---@field notify     doorbell.notify.config
---@field save_path  string
---@field trusted    string[]
---@field metrics    doorbell.metrics.config
---
local _M = {
  _VERSION = require("doorbell.constants").version,
}

local util = require "doorbell.util"
local log  = require "doorbell.log"

local prefix = ngx.config.prefix()
local getenv = os.getenv

local function require_env(name)
  local value = getenv(name)
  if value == nil then
    util.errorf("env var %q is unset", name)
  elseif value == "" then
    util.errorf("env var %q is empty", name)
  end
  return value
end

local function iter_keys(t)
  local keys = {}
  for k in pairs(t) do
    table.insert(keys, k)
  end

  local i = 0
  return function()
    i = i + 1
    return keys[i]
  end
end

local function replace_env(t)
  local typ = type(t)
  if typ == "string" then
    t = t:gsub("%${%s*([a-zA-Z0-9_]+)%s*}", require_env)
  elseif typ == "table" then
    for k in iter_keys(t) do
      t[k] = replace_env(t[k])
    end
  end

  return t
end

local REQUIRED = {}
local NOT_REQUIRED = {}

---@type doorbell.config
local defaults = {
  allow      = NOT_REQUIRED,
  asset_path = prefix .. "/assets/",
  base_url   = REQUIRED,
  cache_size = 1000,
  deny       = NOT_REQUIRED,
  geoip_db   = NOT_REQUIRED,
  host       = NOT_REQUIRED,
  log_path   = prefix .. "/logs/request.json.log",
  notify     = NOT_REQUIRED,
  save_path  = prefix .. "/rules.json",
  trusted    = REQUIRED,
  metrics    = NOT_REQUIRED
}

function _M.init()
  local fname = getenv("DOORBELL_CONFIG") or "/etc/doorbell/config.json"

  local data, err = util.read_json_file(fname)
  if not data then
    util.errorf("failed loading config (%s): %s", fname, err)
  end

  replace_env(data)

  for name in iter_keys(defaults) do
    local default = defaults[name]
    local user    = data[name]

    if user ~= nil then
      _M[name] = user
    elseif default == REQUIRED then
      util.errorf("config.%s is required", name)
    elseif default == NOT_REQUIRED then
      _M[name] = nil
    else
      _M[name] = default
    end
  end

  do
    local m = ngx.re.match(_M.base_url, "^(http(s)?://)?(?<host>[^/]+)")
    if not (m and m.host) then
      util.errorf("failed to parse hostname from base_url: %s", _M.base_url)
    end
    _M.host = m.host:lower()
  end

end

if _G._TEST then
  _M._replace_env = replace_env

  ---@param fn function
  ---@return function
  _M._set_getenv = function(fn)
    local old = getenv
    getenv = fn
    return old
  end
end

return _M
