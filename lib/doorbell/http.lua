local _M = {
  _VERSION = require("doorbell.constants").version,
}

local log = require "doorbell.log"

local cjson = require "cjson"
local safe_decode = require("cjson.safe").decode

local open          = io.open
local encode        = cjson.encode
local ngx           = ngx
local print         = ngx.print
local exit          = ngx.exit
local get_body_data = ngx.req.get_body_data
local get_body_file = ngx.req.get_body_file
local read_body     = ngx.req.read_body
local type = type

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
local function send(status, body)
  if type(body) == "table" then
    body = encode(body)
  end

  ngx.status = status

  if body ~= nil then
    print(body)
  end

  return exit(status)
end

_M.send = send

_M.get_request_body = get_request_body

---@return table? json
function _M.get_json_request_body()
  local body = get_request_body()

  if body == "" or not body then
    return send(400, { error = "json request body required" })
  end

  local json, err = safe_decode(body)

  if err then
    return send(400, { error = "invalid json" })
  end

  return json
end

return _M
