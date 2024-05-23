local _M = {}

local shm    = require "doorbell.shm"
local util = require "doorbell.util"
local mail    = require "doorbell.mail"
local config = require "doorbell.config"
local const   = require "doorbell.constants"

local SHM = shm.with_namespace("email-validate")

local TTL = 60 * 60

local EMAIL = [[<!DOCTYPE html>
<html>
<head>
    <title>Validate Your Email Address</title>
</head>
<body>
    <div style="font-family: Arial, sans-serif; color: #333; padding: 20px; text-align: center;">
        <h1>Email Verification Required</h1>
        <p>Thank you for your request. Please click the link below to verify your email address and complete the registration process.</p>
        <a href="%s" style="background-color: #4CAF50; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; font-size: 18px;">Verify Email</a>
        <p>If you did not request this, please ignore this email.</p>
    </div>
</body>
</html>]]


---@class doorbell.email.validation.init
---
---@field addr string
---@field token string


---@class doorbell.email.validation.with_email : doorbell.email.validation.init
---
---@field email string


---@class doorbell.email.validation.with_secret : doorbell.email.validation.with_email
---
---@field secret string


---@alias doorbell.email.validation
---| doorbell.email.validation.init
---| doorbell.email.validation.with_email
---| doorbell.email.validation.with_secret

---@param token string
---@return doorbell.email.validation?
local function get_by_token(token)
  return SHM:get(token)
end


---@param addr string
---@return doorbell.email.validation?
local function get_by_addr(addr)
  local t = SHM:get(addr)

  if t then
    return get_by_token(t)
  end
end

---@param v doorbell.email.validation
local function add(v)
  assert(SHM:add(v.addr, v.token, TTL))
  assert(SHM:add(v.token, v, TTL))
end


---@param v doorbell.email.validation
local function update(v)
  assert(SHM:set(v.addr, v.token, TTL))
  assert(SHM:set(v.token, v, TTL))
end


_M.update = update


---@param addr string
---@return doorbell.email.validation.init?
function _M.incoming(addr)
  local current = get_by_addr(addr)

  if current then
    return current
  end

  local v = {
    addr = addr,
    token = util.random_string(24),
  }

  add(v)

  return v
end


---@param token string
---@return doorbell.email.validation?
function _M.get(token)
  return get_by_token(token)
end


---@param secret string
---@return doorbell.email.validation.with_secret?
function _M.get_by_secret(secret)
  local token = SHM:get("secret:" .. secret)
  if token then
    return get_by_token(token)
  end
end


---@param v doorbell.email.validation
---@return boolean? ok
---@return string? error
function _M.send_email(v)
  assert(v.email)
  v.secret = util.random_string(24)
  update(v)
  assert(SHM:add("secret:" .. v.secret, v.token), TTL)

  local url = config.base_url
           .. const.endpoints.email
           .. "?"
           .. ngx.encode_args({ v = v.secret })

  return mail.send({
    subject = "Please verify your email address",
    html = EMAIL:format(url),
    to = { v.email },
    from = config.smtp.from,
  })
end


---@param v doorbell.email.validation
function _M.teardown(v)
  if v.addr then
    SHM:delete(v.addr)
  end

  if v.token then
    SHM:delete(v.token)
  end

  if v.secret then
    SHM:delete("secret:" .. v.secret)
  end
end

return _M
