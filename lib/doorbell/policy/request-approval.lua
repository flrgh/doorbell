---@class doorbell.policy.request-approval : doorbell.policy.strategy
---
---@field config doorbell.config
local _M = {}

local http   = require "doorbell.http"
local access = require "doorbell.auth.access"
local const  = require "doorbell.constants"

local ENDPOINTS = const.endpoints
local STATES    = const.states
local log       = require("doorbell.log").with_namespace("request-approval")

local mt = { __index = _M }


---@param conf doorbell.config
function _M.new(conf)
  local self = { config = conf }
  setmetatable(self, mt)
  return self
end


---@param req doorbell.forwarded_request
function _M:unknown(req)
  log.notice("requesting access for ", req.addr)

  local state = access.new_access_request(req)

  if state == STATES.allow then
    return http.send(201, "you may enter")

  elseif state == STATES.deny then
    return http.send(403, "go away dude")

  elseif state == STATES.error then
    return http.send(500, "uh oh")
  end

  assert(state == STATES.pending, "unexpected/invalid state: " .. state)

  if access.await(req) then
    log.notice("access approved for ", req.addr)
    return http.send(201, "access approved, c'mon in")
  end

  return http.send(401, "who are you?")
end


---@param req doorbell.forwarded_request
function _M:pending(req)
  log.notice("awaiting access for ", req.addr)
  if access.request(req) and access.await(req) then
    return http.send(201, "access approved, c'mon in")
  end

  return http.send(401, "I dunno man")
end


---@param req doorbell.forwarded_request
---@return boolean
function _M:pre_auth_allow(req)
  if    req.host == self.config.host
    and req.path == ENDPOINTS.answer
  then
    log.debugf("allowing request to %s endpoint", ENDPOINTS.get_access)
    return true
  end

  return false
end

return _M
