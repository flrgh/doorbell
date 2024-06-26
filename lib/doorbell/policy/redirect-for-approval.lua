---@class doorbell.policy.redirect-for-approval : doorbell.policy.strategy
---
---@field config doorbell.config
local _M = {}

local http = require "doorbell.http"
local access  = require "doorbell.auth.access"
local log     = require "doorbell.log"
local const   = require "doorbell.constants"
local join    = require("doorbell.util").join

local ENDPOINTS       = const.endpoints
local STATES          = const.states

local fmt = string.format

local mt = { __index = _M }

do
  local encode_args = ngx.encode_args
  local arg_t = {
    addr     = nil,
    next     = nil,
    token    = nil,
    scopes   = nil,
    subjects = nil,
    max_ttl  = nil,
  }

  ---@param req doorbell.forwarded_request
  ---@param token string
  ---@return string
  function _M:get_redir_location(req, token)
    local uri

    if self.config.redirect_uri then
      uri = self.config.redirect_uri

    else
      uri = join(self.config.base_url, ENDPOINTS.get_access)
    end

    arg_t.next     = fmt("%s://%s%s", req.scheme, req.host, req.uri)
    arg_t.token    = token
    arg_t.scopes   = self.config.approvals.allowed_scopes
    arg_t.subjects = self.config.approvals.allowed_subjects
    arg_t.max_ttl  = self.config.approvals.max_ttl
    arg_t.addr     = req.addr

    return uri .. "?" .. encode_args(arg_t)
  end
end


---@param conf doorbell.config
function _M.new(conf)
  local self = { config = conf }
  setmetatable(self, mt)
  return self
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

  local location = self:get_redir_location(req, token)

  log.info("redirecting client to ", location)
  return http.send(302, "there's a system in place", { location = location })
end


---@param req doorbell.forwarded_request
---@param token string
function _M:pending(req, _, token)
  local location = self:get_redir_location(req, token)

  log.info("redirecting client to ", location)
  return http.send(302, "there's a system in place", { location = location })
end


---@param req doorbell.forwarded_request
---@return boolean
function _M:pre_auth_allow(req)
  if    req.host == self.config.host
    and req.path == ENDPOINTS.get_access
  then
    log.debug("allowing request to", ENDPOINTS.get_access, " endpoint")
    return true
  end

  return false
end

return _M
