local _M = {}

local http = require "resty.http"
local cjson = require "cjson"
local clone = require "table.clone"

local headers_mt = {
  __index = function(self, name)
    name = name:lower():gsub("_", "-")
    return rawget(self, name)
  end,

  __newindex = function(self, name, value)
    name = name:lower():gsub("_", "-")
    return rawset(self, name, value)
  end,
}


---@param req spec.testing.client.request
local function prepare(req)
  if req.json then
    assert(req.body == nil, "request.json and request.body are " ..
                            "mutually exclusive")

    req.body = cjson.encode(req.json)
    req.json = nil

    req.headers = req.headers or {}
    req.headers["content-type"] = "application/json"
  end
end


---@param t table|nil
---@return table
function _M.headers(t)
  local new = setmetatable({}, headers_mt)
  if t then
    for k, v in pairs(t) do
      new[k] = v
    end
  end
  return new
end

---@class spec.testing.client.request : resty.http.request_params
---
---@field json table


---@class spec.testing.client : table
---
---@field httpc        resty.http.client
---@field request      spec.testing.client.request
---@field response     resty.http.response
---@field err          string
---@field host         string
---@field port         integer
---@field scheme       "http"|"https"
---@field headers      table<string,string>
---@field need_connect boolean
---@field timeout      number
local client = {}
client.__index = client

function client:close()
  return self.httpc:close()
end

function client:reset()
  self.headers = _M.headers()
  self.request = {}
  self.response = nil
  self.err = nil
end

function client:send()
  self.response = nil

  self.httpc:set_timeout(self.timeout or 5000)

  if self.need_connect then
    local ok, err = self.httpc:connect({
      host   = self.host,
      scheme = self.scheme,
      port   = self.port,
    })

    self.err = err
    if not ok then return nil, err end
    self.need_connect = false
  end

  local req = clone(self.request)
  req.headers = req.headers or _M.headers()
  prepare(req)

  for k, v in pairs(self.headers) do
    req.headers[k] = v
  end

  local res, err = self.httpc:request(req)
  self.err = err

  if not res then
    self:close()
    self.need_connect = true
    return nil, err
  end

  local body, json
  if res.has_body then
    body = res:read_body()
    local ct = res.headers["content-type"] or ""
    if ct:find("application/json", 1, true) then
      json = cjson.decode(body)
    end
  end

  local conn = res.headers.connection or ""
  if conn:find("close", 1, true) then
    self:close()
    self.need_connect = true
  end

  self.response = {
    status  = res.status,
    headers = res.headers,
    body    = body,
    json    = json,
  }

  return self.response
end

---@param uri string
---@param query_in_path? boolean
function client:parse_uri(uri, query_in_path)
  return self.httpc:parse_uri(uri, query_in_path)
end

function client:add_x_forwarded_headers(addr, meth, req)
  local headers = self.headers
  headers.x_forwarded_for = addr
  headers.x_forwarded_method = meth
  local parsed = assert(self:parse_uri(req, true))
  headers.x_forwarded_proto = parsed[1]
  headers.x_forwarded_host  = parsed[2]
  headers.x_forwarded_uri   = parsed[4]
end

for _, method in ipairs({"get", "put", "post", "delete", "patch"}) do
  ---@param self spec.testing.client
  ---@param path string
  ---@param params spec.testing.client.request
  client[method] = function(self, path, params)
    params = params or {}

    if self.need_connect then
      local ok, err = self.httpc:connect({
        host   = self.host,
        scheme = self.scheme,
        port   = self.port,
      })

      if not ok then return nil, err end
      self.need_connect = false
    end

    local req = {
      method  = method:upper(),
      headers = _M.headers(),
      path    = path,
      query   = params.query,
      body    = params.body,
      json    = params.json,
    }

    prepare(req)

    for k, v in pairs(self.headers) do
      req.headers[k] = v
    end

    if params.headers then
      for k, v in pairs(_M.headers(params.headers)) do
        req.headers[k] = v
      end
    end

    local res, err = self.httpc:request(req)

    if not res then
      self:close()
      self.need_connect = true
      return nil, err
    end

    local body, json
    if res.has_body then
      body = res:read_body()
      local ct = res.headers["content-type"] or ""
      if ct:find("application/json", 1, true) then
        json = cjson.decode(body)
      end
    end

    local conn = res.headers.connection or ""
    if conn:find("close", 1, true) then
      self:close()
      self.need_connect = true
    end

    return {
      status  = res.status,
      headers = res.headers,
      body    = body,
      json    = json,
    }
  end
end

function _M.new(url)
  url = url or "http://127.0.0.1:9876"

  local parsed = assert(http:parse_uri(url))

  local self = {
    httpc        = assert(http.new()),
    scheme       = parsed[1],
    host         = parsed[2],
    port         = parsed[3],
    headers      = _M.headers(),
    need_connect = true,
    request      = {},
  }

  return setmetatable(self, client)
end

return _M
