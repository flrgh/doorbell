---@class doorbell.ota : table
local _M = {
  _VERSION = require("doorbell.constants").version,
}

local http = require "resty.http"
local cjson = require "cjson.safe"
local manager = require "doorbell.rules.manager"
local const = require "doorbell.constants"
local rules = require "doorbell.rules"
local log = require "doorbell.log"
local util = require "doorbell.util"

local DEFAULT_INTERVAL = 60

---@param rule doorbell.rule
---@return boolean
local function is_ota(rule)
  return rule.source == const.sources.ota
end

---@class doorbell.ota.config : table
---
---@field url      string
---@field headers? table<string, string|string[]>
---@field interval number
local config

local state = {
  etag          = nil,
  last_modified = nil,
}

---@param payload doorbell.rule[]
---
---@return boolean? ok
local function apply(payload)
  if type(payload) ~= "table" then
    log.errf("received invalid rules object from OTA: %s", type(payload))
    return false
  end

  for i = 1, #payload do
    local rule = payload[i]
    rule.source = const.sources.ota
    local _, err = rules.new(rule)

    if err then
      log.errf("received invalid rule from OTA: %s", err)
      return false
    end
  end

  -- TODO: atomicity

  local remove = util.filter(manager.list(), is_ota)

  for _,  rule in ipairs(remove) do
    local ok, err = manager.delete(rule)
    if not ok then
      log.errf("failed to remove old OTA rule %q: %s", rule.hash, err)
      return false
    end
  end

  for _, rule in ipairs(payload) do
    local ok, err = manager.add(rule, true)
    if not ok then
      log.errf("failed to add new OTA rule %q: %s", rule.hash, err)
      return false
    end
  end

  manager.reload()

  return true
end


local function update(premature)
  if premature then return end

  local client, err = http:new()

  if not client then
    log.errf("failed to create HTTP client for OTA updates: %s", err)
    return
  end

  local headers = {}

  for k, v in pairs(config.headers) do
    headers[k] = v
  end

  if state.etag then
    headers["If-None-Match"] = state.etag

  elseif state.last_modified then
    headers["If-Modified-Since"] = state.last_modified
  end


  local res
  res, err = client:request_uri(config.url, {
    method = "GET",
    headers = headers,
  })

  if not res then
    log.errf("failed to send request to %s for OTA updates: %s", config.url, err)
    return
  end

  if res.status == 304 then
    log.debugf("no new updates available at %s", config.url)
    return

  elseif res.status ~= 200 then
    log.errf("received %d from %s for OTA updates", res.status, config.url)
    return
  end

  local body = res.body

  if not body or #body == 0 then
    log.errf("no body received from %s for OTA updates", config.url)
    return
  end

  local json
  json, err = cjson.decode(body)
  if err then
    log.errf("failed to decode JSON from %s for OTA updates: %s", config.url, err)
    return
  end

  if not apply(json) then
    log.errf("failed to apply OTA rules from %s", config.url)
    return
  end

  log.noticef("updated %s OTA rules from %s", #json, config.url)

  if res.headers.etag then
    state.etag = res.headers.etag

  elseif res.headers["last_modified"] then
    state.last_modified = res.headers["last_modified"]
  end
end


---@param conf doorbell.config
function _M.init(conf)
  config = conf.ota
  if not config then return end

  assert(type(config.url) == "string", "ota.url must be a string")
  assert(http:parse_uri(config.url), "ota.url is not a valid URL")

  assert(config.interval == nil or type(config.interval) == "number",
        "ota.interval must be a number")

  config.interval = config.interval or DEFAULT_INTERVAL

  assert(config.headers == nil or type(config.headers) == "table",
        "ota.headers must be a table")
end


function _M.init_agent()
  if not config then return end
  assert(ngx.timer.every(config.interval, update))
end



return _M
