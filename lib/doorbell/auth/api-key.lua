---@class doorbell.auth.api-key
local _M = {}

local util = require "doorbell.util"
local request = require "doorbell.request"
local const = require "doorbell.constants"
local users = require "doorbell.users"

local get_header = request.get_header
local sha256 = util.sha256
local type = type

local HEADER = const.headers.api_key


---@param ctx doorbell.ctx
function _M.identify(ctx)
  local header = get_header(ctx, HEADER)
  if not header then
    return nil, "no API key", 401

  elseif type(header) == "table" then
    return nil, "invalid API key", 400
  end

  local user = users.get_by_api_key(sha256(header))
  if user then
    ctx.user = user
    return user
  end

  return nil, "unknown API key", 403
end


return _M
