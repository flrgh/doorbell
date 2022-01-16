local _M = {
  _VERSION = require("doorbell.constants").version,
}

local util = require "doorbell.util"

local byte     = string.byte
local re_match = ngx.re.match
local re_find  = ngx.re.find
local assert   = assert
local type     = type

local TILDE = string.byte("~")

local function is_regex(path)
  return byte(path, 1) == TILDE
end

---@param re string
---@return boolean ok
---@return string? err
local function validate_regex(re)
  -- strip the '~' prefix
  re = re:sub(2)
  local _, _, err = re_find(".", re, "oj")
  if err then
    return nil, err
  end
  return re
end

---@alias doorbell.route.handler fun(ctx:table, match:table)

---@class doorbell.route : table
---@field path            string
---@field description     string
---@field metrics_enabled boolean
---@field log_enabled     boolean
---@field allow_untrusted boolean
---@field content_type    string
---@field GET             doorbell.route.handler
---@field POST            doorbell.route.handler
---@field DELETE          doorbell.route.handler
---@field PUT             doorbell.route.handler
---@field PATCH           doorbell.route.handler

---@class doorbell.route_list : table
---@field [1] string
---@field [2] doorbell.route

---@type table<string, doorbell.route>
local plain = {}

---@type doorbell.route_list
local regex = { n = 0 }

---@param path string
---@param route doorbell.route
function _M.add(path, route)
  assert(type(path) == "string", "path must be a string")
  assert(type(route) == "table", "route must be a table")

  if is_regex(path) then
    local re, err = validate_regex(path)
    if not re then
      util.errorf("invalid route path regex (%q): %s", path, err)
    end

    local n = regex.n + 1
    regex[n] = { re, route }
    regex.n = n
  else
    plain[path] = route
  end
end

---@class doorbell.route_match : table

---@type doorbell.route_match
local match_t = {}

---@prarm path string
---@return doorbell.route?
---@return doorbell.route_match?
function _M.match(path)
  local r = plain[path]
  if r then return r end

  for i = 1, regex.n do
    local item = regex[i]
    local re = item[1]
    local match = re_match(path, re, "oj", nil, match_t)
    if match then
      match_t = {}
      return item[2], match
    end
  end
end

setmetatable(_M, {
  __newindex = function(_, path, route)
    _M.add(path, route)
  end,
})

return _M
