local _M = {
  _VERSION = require("doorbell.constants").version,
}

local util = require "doorbell.util"

local cache = require("doorbell.cache").new("routes", 1000)

local re_match = ngx.re.match
local assert   = assert
local type     = type

---@alias doorbell.route.handler fun(ctx:table, match:table)

---@class doorbell.route : table
---@field path            string
---@field description     string
---@field metrics_enabled boolean
---@field log_enabled     boolean
---@field allow_untrusted boolean
---@field need_query      boolean
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

  if util.is_regex(path) then
    local re, err = util.validate_regex(path)
    if not re then
      util.errorf("invalid route path regex (%q): %s", path, err)
    end

    local n = regex.n + 1
    regex[n] = { re, route }
    regex.n = n

    -- we only cache regex route matches, so this only needs to be flushed
    -- when adding a regex route
    cache:flush_all()

  else
    -- normalize and match both `/route` and `/route/`
    path = path:gsub("/+$", "")

    if plain[path] then
      local other = plain[path]
      util.errorf("route for %q already exists (%s)", path, other.description)
    end

    plain[path] = route
    plain[path .. "/"] = route
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

  local cached = cache:get("path", path)
  if cached then
    return cached.route, cached.match
  end

  for i = 1, regex.n do
    local item = regex[i]
    local re = item[1]
    local match = re_match(path, re, "oj", nil, match_t)
    if match then
      match_t = {}
      local route = item[2]
      cache:set("path", path, { route = route, match = match })
      return route, match
    end
  end
end

setmetatable(_M, {
  __newindex = function(_, path, route)
    _M.add(path, route)
  end,
})

return _M
