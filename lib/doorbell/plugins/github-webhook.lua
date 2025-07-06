local const = require "doorbell.constants"
local ring = require "doorbell.auth.ring"
local mac = require "resty.openssl.mac"
local request = require "doorbell.request"

local get_header = request.get_header
local get_raw_body = request.get_raw_body
local encode_base64 = ngx.encode_base64
local max = math.max
local byte = string.byte
local type = type

---@class doorbell.plugin.github-webhook
local _M = {
  name = "github-webhook",
}

local log = require("doorbell.log").with_namespace(_M.name)

local STATES = const.states

local HMAC

---@class doorbell.config.plugin.github-webhook
---
---@field secret string

---@param lhs string
---@param rhs string
---@return boolean
local function compare(lhs, rhs)
  local lhs_len = #lhs
  local rhs_len = #rhs
  local len = max(lhs_len, rhs_len)

  local eq = lhs_len == rhs_len

  for i = 1, len do
    if byte(lhs, i) ~= byte(rhs, i) then
      eq = false
    end
  end

  return eq
end

---@param req doorbell.forwarded_request
---@param ctx doorbell.ctx
---@param state doorbell.auth.access.state
---@return doorbell.auth.access.state|nil
local function ring_hook(req, ctx, state)
  if state == STATES.deny then
    return
  end

  if req.method ~= "POST" then
    return
  end

  local client_sig = get_header(ctx, "x-hub-signature-256")
  if type(client_sig) == "table" then
    client_sig = client_sig[1]
  end

  if not client_sig then
    return
  end

  local body = get_raw_body(ctx)
  if not body then
    log.info("received request with no body")
    return
  end

  HMAC:reset()
  local hmac, err = HMAC:final(body)
  if err then
    log.warn("failed calculating hmac digest for request body")
    return
  end

  local real_sig = "sha256=" .. encode_base64(hmac)
  if compare(real_sig, client_sig) then
    log.debugf("allow: request signature (%q) matched ours (%q)", client_sig, real_sig)
    return STATES.allow
  end

  log.infof("deny: request signature (%q) did not match ours (%q)", client_sig, real_sig)
  return STATES.deny
end


---@param conf doorbell.config.plugin.github-webhook
function _M.init(conf)
  assert(type(conf.secret) == "string", "Webhook `secret` is required")

  HMAC = assert(mac.new(conf.secret, "hmac", nil, "sha256"))

  ring.add_hook(_M.name, ring_hook)
end


return _M
