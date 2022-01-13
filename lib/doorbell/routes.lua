local _M = {
  _VERSION = require("doorbell.constants").version,
}

local byte     = string.byte
local re_match = ngx.re.match
local assert   = assert
local type     = type
local resty_re = require "resty.core.regex"

local TILDE = string.byte("~")

local function is_regex(path)
  return byte(path, 1) == TILDE
end

---@type table<string, doorbell.route>
local plain = {}

---@type doorbell.route_list
local regex = { n = 0 }

---@class doorbell.route_list : table
---@field [1] string
---@field [2] doorbell.route

---@class doorbell.route : table
---@field path            string
---@field description     string
---@field metrics_enabled boolean
---@field log_enabled     boolean
---@field allow_untrusted boolean
---@field run             fun(ctx:table)

---@class doorbell.route_match : table

---@param path string
---@param route doorbell.route
function _M.add(path, route)
  assert(type(path) == "string", "path must be a string")
  assert(type(route) == "table", "route must be a table")

  if is_regex(path) then
    local n = regex.n + 1
    regex[n] = { path, route }
    regex.n = n
  else
    plain[path] = route
  end
end

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
    local match, err = re_match(path, re, "oj", nil, match_t)
  end

end

return _M
