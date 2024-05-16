---@class doorbell.policy.validate-by-email : doorbell.policy.strategy
---
---@field config doorbell.config
local _M = {}

local http   = require "doorbell.http"
local log    = require "doorbell.log"
local const  = require "doorbell.constants"
local email  = require "doorbell.auth.email"

local ENDPOINT = const.endpoints.email

do
  local encode_args = ngx.encode_args
  local arg_t = {
    s = nil,
  }

  ---@param token? string
  ---@return string
  function _M:get_redir_location(token)
    arg_t.s = token
    return self.config.base_url
           .. ENDPOINT
           .. "?"
           .. encode_args(arg_t)
  end
end

local mt = { __index = _M }

---@param conf doorbell.config
function _M.new(conf)
  assert(conf.smtp, "SMTP must be configured to use email validation")
  local self = { config = conf }
  setmetatable(self, mt)
  return self
end


---@param req doorbell.forwarded_request
function _M:unknown(req)
  local v = email.incoming(req.addr)
  local location = self:get_redir_location(v.token)
  log.notice("redirecting client to ", location)
  return http.send(302, "there's a system in place", { location = location })
end


function _M:pending()
  error("unreachable!")
end


---@param req doorbell.forwarded_request
---@return boolean
function _M:pre_auth_allow(req)
  if    req.host == self.config.host
    and req.path == ENDPOINT
  then
    log.debugf("allowing request to %s endpoint", ENDPOINT)
    return true
  end

  return false
end

return _M
