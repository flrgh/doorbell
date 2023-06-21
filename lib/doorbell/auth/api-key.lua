---@class doorbell.auth.api-key
local _M = {}

local util = require "doorbell.util"
local request = require "doorbell.request"
local const = require "doorbell.constants"

local get_header = request.get_header
local sha256 = util.sha256
local type = type

local HEADER = const.headers.api_key

---@type table<string, doorbell.config.auth.user>
local USERS_BY_API_KEY

---@param conf doorbell.config
function _M.init(conf)
  local users = conf.auth and conf.auth.users
  if users then
    for _, u in ipairs(users) do
      local user = { name = u.name }

      for _, id in ipairs(u.identifiers) do
        if id.apikey then
          USERS_BY_API_KEY = USERS_BY_API_KEY or {}
          assert(USERS_BY_API_KEY[id.apikey] == nil, "duplicate user API key")
          USERS_BY_API_KEY[id.apikey] = user
        end
      end
    end
  end
end

---@param ctx doorbell.ctx
function _M.identify(ctx)
  if not USERS_BY_API_KEY then
    return nil, "no API key", 401
  end

  local header = get_header(ctx, HEADER)
  if not header then
    return nil, "no API key", 401

  elseif type(header) == "table" then
    return nil, "invalid API key", 400
  end

  local user = USERS_BY_API_KEY[sha256(header)]
  if user then
    ctx.user = user
    return user
  end

  return nil, "unknown API key", 403
end


return _M
