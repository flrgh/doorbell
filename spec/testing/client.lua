local _M = {}

local http = require "resty.http"
local cjson = require("cjson").new()
local clone = require "table.clone"
local const = require "doorbell.constants"

cjson.decode_array_with_array_mt(true)

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

local function is_conn_err(e)
  return e == "closed"
      or e == "broken pipe"
      or e == "connection reset by peer"
end

---@param req spec.testing.client.request
local function prepare(req)
  if req.json then
    assert(req.body == nil, "request.json and request.body are " ..
                            "mutually exclusive")

    assert(req.post == nil, "request.json and request.post are " ..
                            "mutually exclusive")

    req.body = cjson.encode(req.json)
    req.json = nil

    req.headers = req.headers or _M.headers()
    req.headers["content-type"] = "application/json"

  elseif req.post then
    assert(req.body == nil, "request.post and request.body are " ..
                            "mutually exclusive")

    assert(type(req.post) == "table", "request.post must be a table")

    req.body = assert(ngx.encode_args(req.post))
    req.headers = req.headers or _M.headers()
    req.headers["content-type"] = "application/x-www-form-urlencoded"
  end
end

---@param res resty.http.response
---@return spec.testing.client.response
local function new_response(res)
  local ct = res.headers["content-type"] or ""
  local body, json
  if res.has_body then
    body = assert(res:read_body())
    if ct:find("application/json", 1, true) then
      json = cjson.decode(body)
    end
  end

  return {
    status  = res.status,
    headers = _M.headers(res.headers),
    body    = body,
    json    = json,
    id      = res.headers[const.headers.request_id],
  }
end


---@param self spec.testing.client
---@param req spec.testing.client.request
---@param res spec.testing.client.response
local function check_response(self, req, res)
  local method = req.method or "GET"
  local check = self.assert_status[method]

  if check then
    local status = res.status
    local ok, msg = true, nil

    if ok and check.gt then
      ok = status > check.gt
      msg = "status code " .. status .. " is <= " .. check.gt
    end

    if ok and check.gte then
      ok = status >= check.gte
      msg = "status code " .. status .. " is < " .. check.gte
    end

    if ok and check.lt then
      ok = status < check.lt
      msg = "status code " .. status .. " is >= " .. check.lt
    end

    if ok and check.lte then
      ok = status <= check.lte
      msg = "status code " .. status .. " is > " .. check.lte
    end


    if ok and check.eq then
      ok = status == check.eq
      msg = "status code " .. status .. " != " .. check.eq
    end

    if ok and check.one_of then
      local found = false
      for _, exp in ipairs(check.one_of) do
        if exp == status then
          found = true
          break
        end
      end

      ok = found
      msg = "status code " .. status .. " was not one of "
            .. table.concat(check.one_of, ", ")
    end

    assert(ok, { msg = msg, req = req, res = self.response })
  end
end


---@alias spec.testing.client.headers table<string, string|string[]>

---@param t? spec.testing.client.headers
---@return spec.testing.client.headers
function _M.headers(t)
  local new = setmetatable({}, headers_mt)
  if t then
    for k, v in pairs(t) do
      new[k] = v
    end
  end
  return new
end

---@alias spec.testing.client.method fun(self:spec.testing.client, path:string, params?:spec.testing.client.request):spec.testing.client.response? string?


---@class spec.testing.client.request : resty.http.request_params
---
---@field json? table
---
---@field post? table


---@class spec.testing.client.response : table
---
---@field status  integer
---@field json    table|nil
---@field body    string|nil
---@field headers spec.testing.client.headers
---@field id      string|nil


---@class spec.testing.client.status.assertion : table
---
---@field gt     integer
---@field gte    integer
---@field lt     integer
---@field lte    integer
---@field eq     integer
---@field one_of integer[]


---@class spec.testing.client : table
---
---@field httpc        resty.http.client
---@field request      spec.testing.client.request
---@field response     spec.testing.client.response
---@field err          string|nil
---@field host         string
---@field port         integer
---@field scheme       "http"|"https"
---@field headers      spec.testing.client.headers
---@field need_connect boolean
---@field timeout      number
---
---@field raise_on_request_error     boolean
---@field raise_on_connect_error     boolean
---@field reopen                     boolean
---
---@field assert_status? table<ngx.http.method|string, spec.testing.client.status.assertion>
---
---@field get     spec.testing.client.method
---@field post    spec.testing.client.method
---@field put     spec.testing.client.method
---@field patch   spec.testing.client.method
---@field delete  spec.testing.client.method
---@field options spec.testing.client.method
local client = {}
client.__index = client

function client:close()
  self.need_connect = true
  return self.httpc:close()
end

function client:reset()
  self.headers = _M.headers()
  self.request = {}
  self.response = nil
  self.err = nil
end


function client:reconnect()
  self:close()
  assert(self.httpc:connect({
    host   = self.host,
    scheme = self.scheme,
    port   = self.port,
  }))
  self.need_connect = true
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

    if not ok then
      if self.raise_on_connect_error then
        error("resty.http.client:connect() failed: " .. tostring(err))
      end

      return nil, err
    end

    self.need_connect = false
  end

  ---@type spec.testing.client.request
  local req = clone(self.request)
  req.headers = req.headers or _M.headers()
  prepare(req)

  for k, v in pairs(self.headers) do
    req.headers[k] = v
  end


  self.httpc:set_timeout(self.timeout or 5000)

  local res, err = self.httpc:request(req)
  self.err = err

  if res then
    self.response = new_response(res)

    local conn = res.headers.connection or ""
    if conn:find("close", 1, true) then
      self:close()
    end

    check_response(self, req, self.response)

  else
    self:close()

    if is_conn_err(err) and self.reopen then
      self.reopen = false

      self:send()

      self.reopen = true

    elseif self.raise_on_request_error then
      error("failed to send request: " .. tostring(err))
    end

    return nil, err
  end

  do
    local method = req.method or "GET"
    local check = self.assert_status[method]

    if check then
      local status = res.status
      local ok, msg = true, nil

      if ok and check.gt then
        ok = status > check.gt
        msg = "status code " .. status .. " is <= " .. check.gt
      end

      if ok and check.gte then
        ok = status >= check.gte
        msg = "status code " .. status .. " is < " .. check.gte
      end

      if ok and check.lt then
        ok = status < check.lt
        msg = "status code " .. status .. " is >= " .. check.lt
      end

      if ok and check.lte then
        ok = status <= check.lte
        msg = "status code " .. status .. " is > " .. check.lte
      end


      if ok and check.eq then
        ok = status == check.eq
        msg = "status code " .. status .. " != " .. check.eq
      end

      if ok and check.one_of then
        local found = false
        for _, exp in ipairs(check.one_of) do
          if exp == status then
            found = true
            break
          end
        end

        ok = found
        msg = "status code " .. status .. " was not one of "
              .. table.concat(check.one_of, ", ")
      end

      assert(ok, { msg = msg, req = req, res = self.response })
    end
  end

  return self.response
end

---@param uri string
---@param query_in_path? boolean
function client:parse_uri(uri, query_in_path)
  return self.httpc:parse_uri(uri, query_in_path)
end

---@param addr   string
---@param method string
---@param url    string
function client:add_x_forwarded_headers(addr, method, url)
  local headers = self.headers
  headers.x_forwarded_for = addr
  headers.x_forwarded_method = method
  local parsed = assert(self:parse_uri(url, true))
  headers.x_forwarded_proto = parsed[1]
  headers.x_forwarded_host  = parsed[2]
  headers.x_forwarded_uri   = parsed[4]
end

for _, method in ipairs({"get", "put", "post", "delete", "patch", "options"}) do
  ---@param self spec.testing.client
  ---@param path string
  ---@param params spec.testing.client.request
  client[method] = function(self, path, params)
    params = params or {}
    self.request = {
      method  = method:upper(),
      headers = _M.headers(params.headers),
      path    = path,
      query   = params.query,
      body    = params.body,
      json    = params.json,
      post    = params.post,
    }

    return self:send()
  end
end

---@param url? string
---@return spec.testing.client
function _M.new(url)
  url = url or "http://127.0.0.1:9876"

  local parsed = assert(http:parse_uri(url))

  local self = {
    httpc                  = assert(http.new()),
    scheme                 = parsed[1],
    host                   = parsed[2],
    port                   = parsed[3],
    headers                = _M.headers(),
    need_connect           = true,
    request                = {},
    raise_on_request_error = false,
    raise_on_connect_error = true,
    assert_status          = {},
    reopen                 = false,
  }

  return setmetatable(self, client)
end

return _M
