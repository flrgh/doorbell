local _M = {
  _VERSION = require("doorbell.constants").version,
}

local prefix = ngx.config.prefix()

local REQUIRED = {}
local NOT_REQUIRED = {}

---@class doorbell.config : table
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
local config = {
  allow      = NOT_REQUIRED,
  asset_path = "/opt/doorbell/assets",
  base_url   = REQUIRED,
  cache_size = 1000,
  deny       = NOT_REQUIRED,
  geoip_db   = NOT_REQUIRED,
  host       = NOT_REQUIRED,
  log_path   = prefix .. "/request.json.log",
  notify     = REQUIRED,
  save_path  = prefix .. "/rules.json",
  trusted    = REQUIRED,
}

---@param opts doorbell.config
---@return doorbell.config
function _M.new(opts)
  assert(opts, "opts table required")

  local keys = {}
  for k in pairs(config) do table.insert(keys, k) end
  for _, name in ipairs(keys) do
    local default = config[name]
    local user    = opts[name]

    if user ~= nil then
      config[name] = user
    elseif default == REQUIRED then
      error("`opts." .. name .. "` is required")
    elseif default == NOT_REQUIRED then
      config[name] = nil
    end
  end

  do
    local m = ngx.re.match(config.base_url, "^(http(s)?://)?(?<host>[^/]+)")
    assert(m and m.host, "failed to parse hostname from base_url: " .. config.base_url)
    config.host = m.host:lower()
  end

  return config
end

return _M
