local _M = {
  _VERSION = require("doorbell.constants").version,
}

local log = require "doorbell.log"
local ip = require "doorbell.ip"

local pushover = require "resty.pushover"
local encode = require("cjson.safe").encode

local fmt = string.format

---@type resty.pushover.client.opts
local config

---@param conf resty.pushover.client.opts
function _M.init(conf)
  config = assert(conf, "pushover config required")
  assert(config.token, "pushover token required")
  assert(config.user_key, "pushover user key required")
end

---@param req doorbell.request
---@param url string
function _M.send(req, url)
  local po, err = pushover.new(config)
  if not po then
    return nil, "failed creating pushover client: " .. err
  end

  local req_str = fmt(
    "%s %s://%s%s",
    req.method,
    req.scheme,
    req.host,
    req.uri
  )

  local country = ip.get_country_name(req.country) or "Unknown"

  local message = fmt(
    [[
      IP address: %s
      Origin: %s
      User-Agent: %s
      Request: %s
    ]],
    req.addr,
    country,
    req.ua or "<NONE>",
    req_str
  )

  local sent, res
  sent, err, res = po:notify({
    title     = "access requested for " .. req.addr,
    message   = message,
    monospace = true,
    url       = url,
    url_title = "approve or deny",
  })

  if res then
    log.debug("pushover notify response: ", encode(res))
  end

  return sent, err, res
end


return _M
