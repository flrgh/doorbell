local _M = {}

local util = require "doorbell.util"
local middleware = require "doorbell.middleware"
local auth = require "doorbell.auth"

local DEFAULT_AUTH = auth.require_all(auth.TRUSTED_IP, auth.OPENID)

local cache = require("doorbell.cache").new("routes", 1000)

local re_match = ngx.re.match
local type     = type
local set_response_header = require("doorbell.http").response.set_header

---@alias doorbell.route.handler fun(ctx:table, match:table)

---@class doorbell.route : table
---@field id              string
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
---@field middleware      table<doorbell.middleware.phase, doorbell.middleware[]>
---@field _middleware     table<doorbell.middleware.phase, doorbell.middleware>
---
---@field auth_required   boolean
---@field auth_strategy   integer

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
  if type(path) ~= "string" then
    error("path must be a string", 2)
  end

  if type(route) ~= "table" then
    error("route must be a table", 2)
  end

  if route.id ~= nil and type(route.id) ~= "string" then
    error("route.id is required", 2)
  end

  route.path = path

  route.id = route.id or path:gsub("/", "-")

  route.auth_strategy = route.auth_strategy or DEFAULT_AUTH

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

  route._middleware = {}
  for _, phase in pairs(middleware.phase) do
    local mws = route.middleware and route.middleware[phase]
    route._middleware[phase] = middleware.compile(mws)
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


function _M.on_match(_, route)
  local ct = route.content_type
  if ct then
    set_response_header("content-type", ct)
  end
end


---@param phase doorbell.middleware.phase
---@param ctx doorbell.ctx
---@param route? doorbell.route
---@param match? doorbell.route_match
function _M.exec_middleware(phase, ctx, route, match)
  route = route or ctx.route
  if route then
    match = match or ctx.route_match
    route._middleware[phase](ctx, route, match)
  end
end


setmetatable(_M, {
  __newindex = function(_, path, route)
    _M.add(path, route)
  end,
})

return _M
