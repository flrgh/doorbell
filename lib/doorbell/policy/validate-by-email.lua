---@class doorbell.policy.validate-by-email : doorbell.policy.strategy
---
---@field config doorbell.config
local _M = {}

local http   = require "doorbell.http"
local access = require "doorbell.auth.access"
local log    = require "doorbell.log"
local const  = require "doorbell.constants"
local util   = require "doorbell.util"
local shm    = require "doorbell.shm"
local random     = require "resty.random"
local str        = require "resty.string"
local buffer     = require "string.buffer"
local users = require "doorbell.users"
local mail = require "doorbell.mail"
local config = require "doorbell.config"
local rules = require "doorbell.rules.api"


local fmt = string.format
local join = util.join
local encode_args = ngx.encode_args

local ENDPOINTS = const.endpoints
local STATES    = const.states
local SHM       = shm.email_validation

---@return string
local function rand_string()
  local bytes = random.bytes(24, true)
  return str.to_hex(bytes)
end

do
  local arg_t = {
    pre_validate = nil,
  }

  ---@param token string
  ---@return string
  function _M:get_redir_location(token)
    arg_t.pre_validate = token
    return join(self.config.base_url, ENDPOINTS.email_validate) .. "?" .. encode_args(arg_t)
  end
end

---@param conf doorbell.config
function _M.new(conf)
  _M.config = conf
  return _M
end

---@param req doorbell.forwarded_request
function _M:unknown(req)
  local state, token = access.new_access_request(req)

  if state == STATES.allow then
    return http.send(201, "you may enter")

  elseif state == STATES.deny then
    return http.send(403, "go away dude")

  elseif state == STATES.error then
    return http.send(500, "uh oh")
  end

  assert(state == STATES.pending, "unexpected/invalid state: " .. state)
  assert(token ~= nil, "empty token returned")

  local pre_validate_token = rand_string()
  assert(SHM:set("pre-validate:" .. pre_validate_token, token))

  local location = self:get_redir_location(pre_validate_token)

  log.notice("redirecting client to ", location)
  return http.send(302, "there's a system in place", { location = location })
end


---@param req doorbell.forwarded_request
---@param token string
function _M:pending(req, _, token)
  if true then error("this doesn't work yet") end
  local location = self:get_redir_location(token)

  log.notice("redirecting client to ", location)
  return http.send(302, "there's a system in place", { location = location })
end


---@param req doorbell.forwarded_request
---@return boolean
function _M:pre_auth_allow(req)
  if    req.host == self.config.host
    and req.path == ENDPOINTS.email_validate
  then
    log.debugf("allowing request to %s endpoint", ENDPOINTS.email_validate)
    return true
  end

  return false
end


---@param email string
---@return boolean? ok
---@return string? error
function _M.send_validation_email(email)
  local user = users.get_by_email(email)

  if not user then
    return nil, "no such user"
  end

  local token = rand_string()

  assert(SHM:set(token, email, 60 * 60))

  local link = join(config.base_url, ENDPOINTS.email_validate) .. "?" .. encode_args({
    v = token,
  })

  local message = fmt([[<html>
  <body>
    Dear %s,
    <br>
    Please click the following link to verify your email address:
    <br>
    <a href=%q >verify me!</a>
    <br>
    NOTE: this link will expire in one hour.
  </body>
</html>
]], user.name, link)

  local subject = "please validate your email address"
  return mail.send(email, subject, message)
end

---@param ctx doorbell.ctx
---@param token string
function _M.validate(ctx, token)
  local email = SHM:get(token)
  if not email then
    return nil, "invalid token"
  end

  log.info("handling email validation for ", email)
  local addr = ctx.forwarded_addr

  local ok, err, status = rules.insert({
    addr    = addr,
    comment = fmt("email-validated rule for %s", email),
    ttl     = 60 * 60,
    action  = "allow",
  })

  if ok then
    SHM:delete(token)
    return true
  end

  return nil, err
end

return _M
