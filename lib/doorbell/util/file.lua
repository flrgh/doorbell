---@class doorbell.util.file
local _M = {}

local rand_bytes = require("resty.random").bytes
local to_hex = require("resty.string").to_hex

local cjson = require("cjson.safe").new()
cjson.encode_keep_buffer(true)
cjson.encode_number_precision(16)
cjson.encode_escape_forward_slash(false)


local open = io.open
local encode = cjson.encode
local decode = cjson.decode
local rename = os.rename
local remove = os.remove
local md5 = ngx.md5_bin

---@return string
local function rand_suffix()
  local bytes = rand_bytes(8, false)
  return "." .. to_hex(bytes)
end


---@param fname string
---@param data string
---@return boolean? ok
---@return string? error
local function write(fname, data)
  local fh, err = open(fname, "w+")
  if not fh then
    return nil, err
  end

  local ok
  ok, err = fh:write(data)

  fh:close()

  if not ok then
    return nil, err
  end

  return true
end


---@param fname string
---@return string? contents
---@return string? error
local function read(fname)
  local fh, err = open(fname, "r")
  if not fh then
    return nil, err
  end

  local content
  content, err = fh:read("*a")
  fh:close()

  if err or not content then
    return nil, err
  end

  return content
end

---@param fname string
---@return string?
local function md5_file(fname)
  local content = read(fname)
  if content then
    return md5(content)
  end
end


---@param fname string
---@param data string
---@return boolean? ok
---@return string? error
---@return boolean written
local function update(fname, data)
  local checksum = md5_file(fname)
  if checksum and checksum == md5(data) then
    return true, nil, false
  end

  local temp = fname .. rand_suffix()

  local ok, err

  ok, err = write(temp, data)
  if not ok then
    return nil, err, false
  end

  ok, err = rename(temp, fname)
  if not ok then
    -- we don't know if our temp file still exists, so ignore errors
    remove(temp)

    return nil, err, false
  end

  return true, nil, true
end


_M.write = write
_M.update = update
_M.read = read

---@param fname string
---@param data string
---@return boolean? ok
---@return string? error
function _M.write_json(fname, data)
  local encoded, err = encode(data)
  if err then
    return nil, err
  end

  return write(fname, encoded)
end


---@param fname string
---@param data string
---@return boolean? ok
---@return nil
---@return boolean written
function _M.update_json(fname, data)
  local encoded, err = encode(data)
  if err then
    return nil, err, false
  end

  return update(fname, encoded)
end


---@param fname string
---@return any? json
---@return string? error
function _M.read_json(fname)
  local contents, err = read(fname)
  if not contents then
    return nil, err
  end

  return decode(contents)
end


return _M
