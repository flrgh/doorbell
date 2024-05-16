local _M = {}

local http = require "doorbell.http"

function _M.new()
  return _M
end

function _M:unknown()
  return http.send(401, "who are you?")
end

function _M:pending()
  return http.send(401, "who are you?")
end

function _M:pre_auth_allow()
  return false
end

return _M
