local _M = {
  _VERSION = require("doorbell.constants").version,
}

local cjson = require "cjson.safe"
local encode = cjson.encode
local decode = cjson.decode
local open = io.open
local type = type

---@param fname string
---@return string? contents
---@return string? error
local function read_file(fname)
  local fh, err = open(fname, "r")
  if not fh then
    return nil, err
  end

  local content
  content, err = fh:read("*a")
  fh:close()

  return content, err
end

_M.read_file = read_file

---@param fname string
---@return any? json
---@return string? error
function _M.read_json_file(fname)
  local data, err = read_file(fname)
  if not data then
    return nil, err
  end

  local json
  json, err = decode(data)
  if err then
    return nil, err
  end

  return json
end

---@param fname string
---@param json table
---@return boolean ok
---@return string? error
function _M.write_json_file(fname, json)
  -- there isn't really any case where we'd want to save anything but a json
  -- object or array to disk
  if type(json) ~= "table" then
    return nil, "not a table"
  end

  local encoded, err = encode(json)
  if not encoded then
    return nil, err
  end

  local fh
  fh, err = open(fname, "w+")
  if not fh then
    return nil, err
  end

  local bytes
  bytes, err = fh:write(encoded)
  fh:close()

  return bytes
end

return _M
