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
local transaction = require "doorbell.rules.transaction"
local notify = require "doorbell.notify"
local fmt = string.format

local DEFAULT_INTERVAL = 60

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

  local trx, err = transaction.new()
  if not trx then
    log.errf("failed to start transaction for OTA updates: %s", err)
    return false
  end

  trx:delete_where({ source = const.sources.ota })

  local ok

  local n = #payload
  for i, rule in ipairs(payload) do
    rule.source = const.sources.ota
    rule, err = rules.new(rule)
    if not rule then
      trx:abort()
      log.errf("failed to create rule from OTA payload %s/%s: %s", i, n, err)
    end

    ok, err = trx:insert(rule)
    if not ok then
      trx:abort()
      log.errf("failed to insert new OTA rule %s/%s: %s", i, n, err)
      return false
    end
  end

  ok, err = trx:commit()
  if not ok then
    log.errf("failed to commit OTA transaction: %s", err)
    return false
  end

  manager.reload()

  return true
end


local function update()
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

  local n = #json

  log.noticef("updated %s OTA rules from %s", n, config.url)

  if res.headers["Etag"] then
    state.etag = res.headers["Etag"]

  elseif res.headers["Last-Modified"] then
    state.last_modified = res.headers["Last-Modified"]
  end

  if notify.in_notify_period() then
    notify.send({
      title = "Updated OTA rules",
      message = fmt([[Updated %s OTA rules from `%s`]], n, config.url),
      level = notify.level.info,
    })
  end
end


---@param premature? boolean
local function update_timer(premature)
  if premature then return end

  update()

  if not ngx.worker.exiting() then
    assert(ngx.timer.at(config.interval, update_timer))
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


function _M.init_worker()
  if not config then return end
  if ngx.worker.id() == 0 then
    assert(ngx.timer.at(0, update_timer))
  end
end



return _M
