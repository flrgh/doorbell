---@class doorbell.policy.verify : doorbell.policy.strategy
---
---@field config doorbell.config
local _M = {}

local http   = require "doorbell.http"
local log    = require "doorbell.log"
local const  = require "doorbell.constants"

local ENDPOINT = const.endpoints.verify

do
  local encode_args = ngx.encode_args
  local fmt = string.format

  local arg_t = {
    next = nil,
  }

  ---@param req doorbell.forwarded_request
  ---@return string
  function _M:get_redir_location(req)
    arg_t.next = fmt("%s://%s%s", req.scheme, req.host, req.uri)
    return self.config.base_url
           .. ENDPOINT
           .. "?"
           .. encode_args(arg_t)
  end
end

local mt = { __index = _M }

---@param conf doorbell.config
function _M.new(conf)
  assert(conf.smtp or conf.twilio,
         "At least one of SMTP or Twilio must be configured for user verification")
  local self = { config = conf }
  setmetatable(self, mt)
  return self
end


---@param req doorbell.forwarded_request
function _M:unknown(req)
  local location = self:get_redir_location(req)
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
