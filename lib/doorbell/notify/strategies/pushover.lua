---@type doorbell.notify.strategy
local _M = {
  _VERSION = require("doorbell.constants").version,
}

local log = require "doorbell.log"
local ip = require "doorbell.ip"
local notify = require "doorbell.notify"

local pushover = require "resty.pushover"
local encode = require("cjson.safe").encode

local level_to_priority = {
  [notify.level.debug] = pushover.priority.lowest,
  [notify.level.info] = pushover.priority.normal,
  [notify.level.error] = pushover.priority.high,
  [notify.level.alert] = pushover.priority.highest,
}

local fmt = string.format
local insert = table.insert
local concat = table.concat

local EMPTY = {}

---@type resty.pushover.client.opts
local config

---@param conf resty.pushover.client.opts
function _M.init(conf)
  config = assert(conf, "pushover config required")
  assert(config.token, "pushover token required")
  assert(config.user_key, "pushover user key required")
end

---@param req doorbell.forwarded_request
---@param url string
function _M.ring(req, url)
  local po, err = pushover.new(config)
  if not po then
    return nil, "failed creating pushover client: " .. err
  end

  local message = {
    "IP Address: " .. req.addr,
  }

  local country = ip.get_country_name(req.country)
  if country then
    insert(message, "Country: " .. country)
  end

  local info = ip.get_ip_info(req.addr) or EMPTY
  if info.region then
    insert(message, "Region: " .. info.region)
  end

  if info.city then
    insert(message, "City: " .. info.city)
  end

  if info.org then
    insert(message, "Network: " .. info.org)
  end

  insert(message, "User-Agent: " .. (req.ua or "<NONE>"))

  insert(message, fmt("Request: %s %s://%s%s",
                      req.method,
                      req.scheme,
                      req.host,
                      req.uri))


  -- pushover puts the action link/url immediately below the rest of the
  -- content, so this adds a little extra padding to make it more clickable
  insert(message, "---\n")

  local sent, res
  sent, err, res = po:notify({
    title     = "Access requested for " .. req.addr,
    message   = concat(message, "\n"),
    monospace = true,
    url       = url,
    url_title = "Approve / Deny",
  })

  if res then
    log.debug("pushover notify response: ", encode(res))
  end

  return sent, err, res
end


function _M.send(msg)
  local po, err = pushover.new(config)
  if not po then
    return nil, "failed creating pushover client: " .. err
  end

  msg = {
    title     = msg.title,
    message   = msg.message,
    url       = msg.link,
    url_title = msg.link_title,
    priority = assert(level_to_priority[msg.level], "invalid notify level"),
  }

  local sent, res
  sent, res = po:notify(msg)

  if res then
    log.debug("pushover notify response: ", encode(res))
  end

  return sent, err, res
end


return _M
