local _M = {}

local log = require("doorbell.log").with_namespace("util.http")

local cjson = require "cjson"
local safe_decode = require("cjson.safe").decode
local nkeys = require "table.nkeys"
local split = require("ngx.re").split
local util = require "doorbell.util"
local shm = require "doorbell.shm"
local http_const = require "doorbell.http.constants"

local ngx                 = ngx
local print               = ngx.print
local exit                = ngx.exit
local get_body_data       = ngx.req.get_body_data
local get_body_file       = ngx.req.get_body_file
local read_body           = ngx.req.read_body
local header              = ngx.header
local get_query           = ngx.req.get_uri_args
local get_req_headers     = ngx.req.get_headers
local get_post_args       = ngx.req.get_post_args
local clear_req_header    = ngx.req.clear_header
local now                 = ngx.now

local open   = io.open
local encode = cjson.encode
local find   = string.find
local sub    = string.sub
local insert = table.insert
local concat = table.concat
local random_string = util.random_string
local type   = type
local assert = assert
local tonumber = tonumber

local CSRF = shm.with_namespace("csrf")

local MAX_QUERY_ARGS = 100
local MAX_REQUEST_HEADERS = 100
local MAX_POST_ARGS = 100
local CSRF_MAX_AGE = 60 * 15 -- 15 minutes

---@alias doorbell.http.headers table<string, string|string[]>

---@alias doorbell.http.query table<string, any>


---@return string?
local function get_request_body()
  read_body()

  local body = get_body_data()
  if body then
    return body
  end

  local fname = get_body_file()
  if not fname then
    return
  end

  log.debugf("reading request body from file (%s)", fname)

  local fh, err = open(fname, "r")
  if not fh then
    log.warnf("failed reading request body from file (%s): %s", fname, err)
    return
  end

  body, err = fh:read("*a")
  fh:close()

  if err then
    log.warnf("read() call failed for request body file (%s): %s", fname, err)
  end

  return body
end

---@param status ngx.http.status_code
---@param body string|table|nil
---@param headers? table<string, string|string[]>
local function send(status, body, headers)
  if type(body) == "table" then
    body = encode(body)
    headers = headers or {}
    headers[http_const.headers.CONTENT_TYPE] = http_const.types.JSON
  end

  if headers then
    for k, v in pairs(headers) do
      header[k] = v
    end
  end

  ngx.status = status

  if body ~= nil then
    print(body)
  end

  return exit(status)
end


_M.send = send


---@generic T
---@param check_type? `T`
---@param optional? boolean
---@return T?
local function get_json_request_body(check_type, optional)
  local body = get_request_body()

  if not optional and (body == "" or not body) then
    log.info("got request without body")
    return send(400, { error = "JSON request body required" })
  end

  local json, err = safe_decode(body)

  if err then
    log.info("got request with invalid JSON body")
    return send(400, { error = "invalid JSON request body" })
  end

  if check_type then
    local typ = type(json)
    if typ ~= check_type then
      return send(400, { error = "invalid JSON request body type" })
    end
  end

  return json
end


---@param optional? boolean
---@return table?
local function get_request_post_args(optional)
  read_body()

  local args, err = get_post_args(MAX_POST_ARGS)
  if err == "truncated" then
    log.notice("request post args exceeded the limit of ", MAX_POST_ARGS)

  elseif err then
    log.err("unexpected error parsing request post args: ", err)
  end

  if not optional and (not args or nkeys(args) == 0) then
    return send(400, { error = "request post args required" })
  end

  return args or {}
end


_M.parse_url = require("socket.url").parse


--- Extract the request path component from the URI.
---@param uri string
---@return string
function _M.extract_path(uri)
  local pos = find(uri, "?", 1, true)
  if pos then
    return sub(uri, 1, pos - 1)
  end

  return uri
end


--- HTTP Request Helper Functions
_M.request = {}

---@return doorbell.http.headers
function _M.request.get_headers()
  local headers, err = get_req_headers(MAX_REQUEST_HEADERS)
  if err then
    if err == "truncated" then
      log.notice("request headers exceeded the limit of ", MAX_REQUEST_HEADERS)
    else
      log.err("unexpected error reading headers: ", err)
    end
  end

  return headers
end


---@return doorbell.http.query
function _M.request.get_query_args()
  local query, err = get_query(MAX_QUERY_ARGS)

  if err then
    if err == "truncated" then
      log.notice("request query string args exceeded the limit of ", MAX_QUERY_ARGS)
    else
      log.err("unexpected error parsing query string args: ", err)
    end
  end

  return query
end

_M.request.get_raw_body = get_request_body
_M.request.get_json_body = get_json_request_body
_M.request.get_post_args = get_request_post_args
_M.request.clear_header = clear_req_header


_M.request.middleware = {}

---@param name string
---@return doorbell.middleware
function _M.request.middleware.clear_header(name)
  if type(name) ~= "string" then
    error("invalid header type", 2)
  end

  if log.IS_DEBUG then
    local get_headers = _M.request.get_headers
    return function()
      local headers = get_headers()

      if headers and headers[name] then
        log.debugf("clearing client request header %q", name)
      end

      clear_req_header(name)
    end

  else
    return function()
      clear_req_header(name)
    end
  end
end

---@param name string
---@param value string|string[]|nil
local function set_response_header(name, value)
  header[name] = value
end


---@param key fun(doorbell.ctx):string|nil, integer?, number?
---@return doorbell.middleware
function _M.request.middleware.rate_limit(key)
  local rl = require("doorbell.rate-limit")

  assert(type(key) == "function")

  local rl_req = rl.request

  ---@type doorbell.middleware
  return function(ctx)
    local k, limit, period = key(ctx)
    if not k then return end

    local allow, remain, reset = rl_req(k, limit, period)

    set_response_header("X-RateLimit-Limit", tostring(limit))
    set_response_header("X-RateLimit-Limit-Remaining", tostring(remain))
    set_response_header("X-RateLimit-Limit-Reset", tostring(reset))

    if not allow then
      set_response_header("Retry-After", tostring(now() + reset))
      set_response_header("Content-Type", "application/json")
      return send(429, [[{ "message": "too many requests" }]])
    end
  end
end


--- HTTP Response Helper Functions
_M.response = {}
_M.response.set_header = set_response_header

---@class doorbell.http.CORS
_M.CORS = {}


local add_cors_headers
do
  local cache = {}

  ---@param route doorbell.route
  ---@return string
  local function build_cors_methods(route)
    local methods = {}

    if route.GET then
      insert(methods, "GET")
    end

    if route.POST then
      insert(methods, "POST")
    end

    if route.PUT then
      insert(methods, "PUT")
    end

    if route.PATCH then
      insert(methods, "PATCH")
    end

    if route.DELETE then
      insert(methods, "DELETE")
    end

    insert(methods, "OPTIONS")

    local value = concat(methods, ", ")
    cache[route] = value

    return value
  end


  ---@param route doorbell.route
  function add_cors_headers(route, add_methods)
    if add_methods then
      header["Access-Control-Allow-Methods"] = cache[route]
                                            or build_cors_methods(route)
    end

    -- TODO: make this configurable
    header["Access-Control-Allow-Origin"] = "*"

    header["Access-Control-Max-Age"] = "3600"

    header["Access-Control-Expose-Headers"] = nil

    header["Access-Control-Allow-Credentials"] = "true"
    header["Access-Control-Allow-Headers"] = "Authorization, Cookie, Content-Type"
  end
end


---@param ctx doorbell.ctx
function _M.CORS.preflight(ctx)
  local route = assert(ctx.route, "CORS preflight called without a route")
  set_response_header("content-type", "text/plain")
  add_cors_headers(route, true)
  return send(200)
end


---@param ctx doorbell.ctx
---@param route doorbell.route
function _M.CORS.middleware(ctx, route)
  -- the preflight handler will take care of OPTIONS requests
  if ctx.method == "OPTIONS" then
    return
  end
  add_cors_headers(route, false)
end


do
  local byte = string.byte
  local sort = table.sort

  local WILD = byte("*")
  local MATCH_ALL = "*/*"

  local function type_match(lhs, rhs)
    if lhs == rhs or lhs == MATCH_ALL then
      return true
    end

    if byte(lhs, -1) == WILD then
      lhs = sub(lhs, 1, -2)
      return find(rhs, lhs, nil, true) == 1
    end

    return false
  end

  ---@param a doorbell.http.accept.entry
  ---@param b doorbell.http.accept.entry
  ---@return boolean
  local function weight_sort(a, b)
    if a[2] ~= b[2] then
      return a[2] > b[2]
    else
      return a[3] < b[3]
    end
  end

  --- mime type
  ---@alias doorbell.http.accept.mime_type string

  --- client-specified weight of the mime-type (e.g. q=1.0)
  ---@alias doorbell.http.accept.weight number

  --- position of the mime type in the Accept header
  ---@alias doorbell.http.accept.position integer

  ---@alias doorbell.http.accept.entry [doorbell.http.accept.mime_type, doorbell.http.accept.weight, doorbell.http.accept.position]

  ---@type doorbell.http.accept.entry[]|string[]
  local buf = {}

  ---@param accept string
  ---@param available doorbell.http.accept.mime_type[]
  ---@return string?
  local function negotiate(accept, available)
    split(accept, ", *", "jo", nil, nil, buf)

    local count = 0

    for i = 1, #buf do
      local typ = buf[i]

      if not typ then
        break
      end

      local weight = 1

      local from, to = find(typ, ";q=", nil, true)
      if from then
        weight = tonumber(sub(typ, to + 1)) or 1
        typ = sub(typ, 1, from - 1)
      end

      for j = 1, #available do
        local av = available[j]

        -- check if the type the client requested is available
        if type_match(typ, av) then
          count = count + 1
          buf[count] = { av, weight, i }
          break
        end
      end
    end

    if count > 1 then
      buf[count + 1] = nil
      sort(buf, weight_sort)
    end

    if count > 0 then
      return buf[1][1]
    end
  end


  ---@param accept string
  ---@param available_types string[]
  ---@return string
  function _M.get_mime_type(accept, available_types)
    local first = available_types[1]

    if not accept or accept == "" or type_match(accept, first) then
      return first
    end

    return negotiate(accept, available_types) or first
  end
end

---@param value string
---@return table
function _M.parse_cache_control(value)
  local cc = {}
  local list = assert(split(value, ", *", "jo"))

  for i = 1, #list do
    local item = list[i]
    local k, v = item:match("(.+)=(.+)")

    if k and v then
      v = tonumber(v) or v
    else
      k = item
      v = true
    end

    cc[k] = v
  end

  return cc
end

--- CSRF utilities
_M.csrf = {}

--- Generates and returns a CSRF token
---@return string
function _M.csrf.generate()
  local token = random_string(32)
  local ok, err = CSRF:add(token, now() + CSRF_MAX_AGE)

  if err == "exists" then
    error("randomly generated a duplicate CSRF token")

  elseif not ok then
    error("failed generating a CSRF token: " .. tostring(err))
  end

  return token
end

--- Validates a CSRF token
---
---@param token string?
---@return boolean? valid
---@return "expired"|"not found"? error
function _M.csrf.validate(token)
  local ts = CSRF:get(token)
  CSRF:delete(token)

  if not ts then
    return nil, "not found"

  elseif now() > ts then
    return nil, "expired"
  end

  return true
end

_M.headers = http_const.headers
_M.types = http_const.types

return _M
