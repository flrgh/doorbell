local _M = {}

local ffi    = require "ffi"
local cjson  = require("cjson.safe").new()
local encode = cjson.encode
local fmt    = string.format
local concat = table.concat
local insert = table.insert

cjson.encode_keep_buffer(true)
cjson.encode_number_precision(16)
cjson.encode_escape_forward_slash(false)

local BUF_SIZE = 1024 * 64
local BUF = require("string.buffer").new(BUF_SIZE)

local system_constants = require "lua_system_constants"
local O_CREAT = system_constants.O_CREAT()
local O_WRONLY = system_constants.O_WRONLY()
local O_APPEND = system_constants.O_APPEND()
local S_IRUSR = system_constants.S_IRUSR()
local S_IWUSR = system_constants.S_IWUSR()
local S_IRGRP = system_constants.S_IRGRP()
local S_IROTH = system_constants.S_IROTH()


local oflags = bit.bor(O_WRONLY, O_CREAT, O_APPEND)
local mode = ffi.new("int", bit.bor(S_IRUSR, S_IWUSR, S_IRGRP, S_IROTH))

local C = ffi.C

ffi.cdef[[
int open(const char * filename, int flags, ...);

size_t read(int fd, void *buf, size_t count);

int write(int fd, const void *ptr, int numbytes);

int close(int fd);

char *strerror(int errnum);
]]


local function flush_buffer(fd)
  repeat
    local ptr, len = BUF:ref()

    if len == 0 then break end

    local n = C.write(fd, ptr, len)

    if n < 0 then
      BUF:reset()
      return nil, ffi.string(C.strerror(ffi.errno()))
    end

    BUF:skip(n)
  until n >= len

  return true
end


---@param path string
---@param entries table[]
---
---@return boolean? ok
---@return string?  error
---@return integer? written
function _M.write(path, entries)
  assert(type(path) == "string", "path must be a string")
  assert(type(entries) == "table", "entries must be a table")

  local fd = C.open(path, oflags, mode)
  if fd < 0 then
    return nil, ffi.string(C.strerror(ffi.errno())), 0
  end

  local n = #entries
  local c = 0
  local errors = {}
  local ok, data, err

  local buffered = 0

  for i = 1, n do
    local entry = entries[i]

    data, err = encode(entry)

    if data then
      BUF:put(data)
      BUF:put("\n")
      buffered = buffered + 1

      if #BUF >= BUF_SIZE then
        ok, err = flush_buffer(fd)
        if ok then
          c = c + buffered
          buffered = 0

        else
          insert(errors, fmt("failed to flush entries %s..%s: %s", c + 1, c + 1 + buffered, err))
          buffered = 0
        end
      end

    else
      insert(errors, fmt("failed to JSON encode entry #%s: %s", i, err))
    end
  end

  ok, err = flush_buffer(fd)
  if ok then
    c = c + buffered
  else
    insert(errors, fmt("failed to flush remaining entries: %s", err))
  end

  C.close(fd)

  if #errors > 0 then
    return nil, concat(errors, "\n"), c
  end

  return true, nil, c
end


return _M
