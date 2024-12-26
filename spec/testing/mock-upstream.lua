---@class doorbell.spec.testing.mock-upstream : table
local mock = {}

local cjson = require "cjson"
local cjson_safe = require "cjson.safe"
local http  = require "doorbell.http"
local uuid  = require("resty.jit-uuid").generate_v4
local resty_http = require "resty.http"
local luassert = require "luassert"

local SHM = ngx.shared.mock
local EMPTY = {}

local BASE_URL = ("http://127.0.0.1:%s"):format(require("spec.testing.constants").MOCK_UPSTREAM_PORT)

local store = {
  get = function(key)
    local value = SHM:get(key)
    if value ~= nil then
      return cjson.decode(value)
    end
  end,

  set = function(key, value)
    return assert(SHM:set(key, cjson.encode(value)))
  end,

  push = function(key, value)
    return assert(SHM:rpush(key, cjson.encode(value)))
  end,

  pop = function(key)
    local value = SHM:lpop(key)
    if value ~= nil then
      return cjson.decode(value)
    end
  end,
}


---@param status ngx.http.status_code
---@param body string|table|nil
---@param headers table<string,string>|nil
local function respond(status, body, headers)
  headers = headers or EMPTY
  for name, value in pairs(headers) do
    ngx.header[name] = value
  end

  ngx.status = status

  if type(body) == "table" then
    body = cjson.encode(body)
    ngx.header["content-type"] = "application/json"
  end

  if body then
    ngx.print(body)
  end


  return ngx.exit(status)
end

---@class spec.testing.mock-upstream.response
---
---@field status?      ngx.http.status_code
---@field body?        string
---@field json?        table
---@field headers      table<string,string>|nil
---@field delay        number|nil

---@class spec.testing.mock-upstream.route
---
---@field once?    boolean
---@field method?  string
---@field host?    string
---@field path?    string
---@field response spec.testing.mock-upstream.response


---@param r spec.testing.mock-upstream.route
---@return boolean? ok
---@return string? err
local function validate(r)
  if type(r) ~= "table" then
    return nil, "invalid route"
  end

  if r.once ~= nil and type(r.once) ~= "boolean" then
    return nil, "invalid once"
  end

  if r.method ~= nil and type(r.method) ~= "string" then
    return nil, "invalid method"
  end

  if r.host ~= nil and type(r.host) ~= "string" then
    return nil, "invalid host"
  end

  if r.path ~= nil and type(r.path) ~= "string" then
    return nil, "invalid path"
  end

  if type(r.response) ~= "table" then
    return nil, "invalid response"
  end

  if type(r.response.status) ~= "number" then
    return nil, "invalid response status"
  end

  if r.response.body ~= nil and type(r.response.body) ~= "string" then
    return nil, "invalid response body"
  end

  if r.response.json ~= nil and type(r.response.json) ~= "table" then
    return nil, "invalid response json"
  end

  if r.response.body and r.response.json then
    return nil, "response body and json are mutually exclusive"
  end

  if r.response.headers ~= nil and type(r.response.headers) ~= "table" then
    return nil, "invalid response headers"
  end

  if r.response.delay ~= nil and type(r.response.delay) ~= "number" then
    return nil, "invalid response delay"
  end


  return true
end


---@return spec.testing.mock-upstream.request
local function get_request()
  local headers = http.request.get_headers()
  local content_type = headers["content-type"]

  local errors = {}
  local body = http.request.get_raw_body()
  local json

  if body and content_type:lower():find("application/json") then
    local err
    json, err = cjson_safe.decode(body)
    if err then
      table.insert(errors, err)
      json = ngx.null
    end
  end

  body = body or ngx.null

  ---@class spec.testing.mock-upstream.request
  local req = {
    headers = headers,
    method  = ngx.req.get_method(),
    host    = ngx.var.host:lower(),
    uri     = ngx.var.request_uri,
    path    = ngx.var.request_uri:gsub("%?.*", ""),
    query   = ngx.req.get_uri_args(1000),
    ---@type string|nil
    body    = body,
    ---@type any|nil
    json    = json,
    errors  = errors,
  }

  return req
end

---@param res spec.testing.mock-upstream.response
local function send_response(res)
  if res.delay then
    ngx.sleep(res.delay)
  end
  return respond(res.status, res.body or res.json, res.headers)
end

---@param req spec.testing.mock-upstream.request
---@param route spec.testing.mock-upstream.route
---@return boolean
local function matches(req, route)
  if route.method and route.method ~= req.method then
    return false
  end

  if route.host and route.host ~= req.host then
    return false
  end

  if route.path and route.path ~= req.path then
    return false
  end

  return true
end

function mock.serve()
  assert(SHM, "mock shm is not defined")

  local req = get_request()
  ngx.ctx.request = req
  local routes = store.get("routes") or {}

  local res

  for i, route in ipairs(routes) do
    if matches(req, route) then
      res = route.response
      ngx.ctx.route = route

      if route.once then
        table.remove(routes, i)
        store.set("routes", routes)
      end

      break
    end
  end

  if res then
    return send_response(res)
  end

  local route = store.get("default")
  if route then
    ngx.ctx.route = route
    send_response(route.response)
  end

  return respond(405, { error = "not allowed" })
end


function mock.prepare()
  assert(SHM, "mock shm is not defined")

  if ngx.req.get_method() ~= "POST" then
    return respond(405, { error = "only POST is allowed" })
  end

  local route = http.request.get_json_body("table", true)
  local ok, err = validate(route)
  if not ok then
    return respond(400, { error = err })
  end

  route.id = uuid()

  if route.once then
    local routes = store.get("routes") or {}
    table.insert(routes, route)
    store.set("routes", routes)
    return respond(200, { message = "ok" })
  end

  store.set("default", route)
end


function mock.reset()
  assert(SHM, "mock shm is not defined")

  SHM:flush_all()
  respond(200, { message = "ok" })
end


function mock.get_last()
  assert(SHM, "mock shm is not defined")

  local last = store.pop("requests")
  if last then
    return respond(200, last)
  end
  return respond(404, { error = "no request found" })
end


function mock.log()
  assert(SHM, "mock shm is not defined")

  local req = ngx.ctx.request
  if req then
    store.push("requests", req)
  end
end

local function mocker_send(path, body, params)
  local client = assert(resty_http.new())
  local req = { headers = {} }

  for k, v in pairs(params or EMPTY) do
    if k == "headers" then
      for jk, jv in pairs(v) do
        req.headers[jk] = jv
      end
    else
      req[k] = v
    end
  end

  local uri =  BASE_URL .. path

  if body then
    req.body = cjson.encode(body)
    req.headers["Content-Type"] = "application/json"
    req.method = req.method or "POST"
  end

  req.method = req.method or "GET"

  return assert(client:request_uri(uri, req))
end

mock.mock = {
  ---@param r spec.testing.mock-upstream.route
  prepare = function(r)
    assert(validate(r))
    local res = mocker_send("/_/prepare", r)
    assert(res.status == 200)
  end,

  ---@return spec.testing.mock-upstream.request|nil
  get_last = function()
    local res = mocker_send("/_/last")
    assert(res.status == 200 or res.status == 404)

    if res.status == 404 then
      return
    end

    return cjson.decode(res.body)
  end,

  reset = function()
    local res = mocker_send("/_/reset", nil, { method = "POST" })
    assert(res.status == 200)
  end,
}

mock.mock.assert_no_request_received = function()
  local req = mock.mock.get_last()
  luassert.is_nil(req, "expected no recent requests to the mock upstream")
end


---@return spec.testing.mock-upstream.request
mock.mock.assert_request_received = function()
  local req = mock.mock.get_last()
  luassert.not_nil(req, "expected the mock upstream to have received a request")
  luassert.is_table(req)
  luassert.is_table(req.headers)

  return req
end

return mock
