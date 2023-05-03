local _M = {
  _VERSION = require("doorbell.constants").version,
}

local const   = require "doorbell.constants"
local log     = require "doorbell.log"
local cjson = require "cjson.safe"
local resty_lock = require "resty.lock"
local uuid = require("resty.jit-uuid").generate_v4
local clone = require "table.clone"
local clear_tab = require "table.clear"
local nkeys = require "table.nkeys"
local isarray = require "table.isarray"

local encode  = cjson.encode
local decode  = cjson.decode
local open    = io.open
local type    = type
local fmt     = string.format
local byte    = string.byte
local utctime = ngx.utctime
local error   = error
local md5     = ngx.md5
local re_find = ngx.re.find
local pairs   = pairs
local sort    = table.sort
local select  = select
local insert  = table.insert
local concat  = table.concat

local LOCK_SHM = const.shm.locks

local TILDE = string.byte("~")

---@param t table
---@return string? encoded
---@return string? error
local function encode_table(t)
  -- there isn't really any case where we'd want to save anything but a json
  -- object or array to disk
  if type(t) ~= "table" then
    return nil, "not a table"
  end
  return encode(t)
end

--- Read the contents of a file.
---@param fname string
---
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
---@param contents string
---@return boolean? ok
---@return string? error
local function write_file(fname, contents)
  local fh, err = open(fname, "w+")
  if not fh then
    return nil, err
  end

  local bytes
  bytes, err = fh:write(contents)
  fh:close()

  if not bytes then
    return nil, err
  end

  return true
end

---@param fname string
---@return string? checksum
---@return string? error
local function md5_file(fname)
  local contents, err = read_file(fname)
  if not contents then
    return nil, err
  end
  return md5(contents)
end

---@param fname string
---@param contents string
---@return boolean? ok
---@return boolean? written
---@return string? error
local function update_file(fname, contents)
  -- not checking for errors here; if we couldn't read/checksum the existing
  -- file we'll just assume that a write is needed
  local file_sum = md5_file(fname)

  if file_sum and md5(contents) == file_sum then
    -- no write needed
    return true, false
  end

  local ok, err = write_file(fname, contents)
  if ok then
    return true, true
  end

  return nil, nil, err
end

--- Read and unserialize json data from a file.
---
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

--- Serialize and write json data to a file
---
---@param fname string
---@param json table
---@return boolean? ok
---@return string? error
function _M.write_json_file(fname, json)
  local encoded, err = encode_table(json)
  if not encoded then
    return nil, err
  end

  return write_file(fname, encoded)
end

---@param fname string
---@param json table
---@return boolean? ok
---@return boolean? written
---@return string? error
function _M.update_json_file(fname, json)
  local encoded, err = encode_table(json)
  if not encoded then
    return nil, nil, err
  end

  return update_file(fname, encoded)
end

--- Returns an ISO 8601 timestamp (UTC)
---@return string
function _M.timestamp()
  --    1234567890123456789
  local yyyy_mm_dd_hh_mm_ss = utctime()
  return fmt("%sT%s+00:00", yyyy_mm_dd_hh_mm_ss:sub(1, 10), yyyy_mm_dd_hh_mm_ss:sub(12, 19))
end

--- error() but with a format string
---
---```lua
---  util.errorf("failed writing %s lines to file (%s): %s", n, fname, err)
---```
---
---@param  f     string  a format string
---@param  ...   any     arguments passed to string.format
function _M.errorf(f, ...)
  error(fmt(f, ...), 2)
end

--- Apply a function to all values in an array-like table.
---
--- The table is modified in place and returned.
---
---```lua
---  local letters = { "a", "b", "c" }
---
---  util.map(letters, string.upper)
---
---  table.concat(letters, ",") --> "A,B,C"
---```
---
---@generic T: table, V
---@param t T
---@param fn fun(v:V, ...:any):T
---@return T
function _M.map(t, fn, ...)
  for i = 1, #t do
    t[i] = fn(t[i], ...)
  end
  return t
end

---@generic T: table, V
---@param t T
---@param fn fun(v:V, ...:any):boolean
---@return T
function _M.filter(t, fn, ...)
  local n = 0
  for i = 1, #t do
    local elem = t[i]
    if fn(elem, ...) then
      n = n + 1
      t[n] = elem
    else
      t[i] = nil
    end
  end
  return t
end


---@param path string
---@return boolean
function _M.is_regex(path)
  return byte(path, 1) == TILDE
end


---@param re string
---@return string? regex
---@return string? err
function _M.validate_regex(re)
  -- strip the '~' prefix
  re = re:sub(2)
  local _, _, err = re_find(".", re, "oj")
  if err then
    return nil, err
  end
  return re
end


---@generic T
---@param t table<T, any>
---@return T[]
function _M.table_keys(t)
  local keys = {}
  local n = 0
  for k in pairs(t) do
    n = n + 1
    keys[n] = k
  end

  sort(keys)

  return keys
end


---@generic T
---@param t table<any, T>
---@param unique? boolean
---@return T[]
function _M.table_values(t, unique)
  local values = {}

  local seen

  if unique then
    seen = {}
  end

  local n = 0
  for _, value in pairs(t) do
    local add = true

    if unique and seen[value] then
      add = false
    end

    if add then
      n = n + 1
      values[n] = value

      if unique then
        seen[value] = true
      end
    end
  end

  sort(values)

  return values
end


---@class doorbell.lock : resty.lock
---@field _name string
---@field _action string
---@field unlock fun(self:doorbell.lock, ...: any):any
---@field _unlock fun(self:resty.lock)

---@param lock doorbell.lock
---@param ... any
---@return any
local function _unlock(lock, ...)
  local ok, err = lock:_unlock()
  if not ok then
    log.errf(
      "failed unlocking lock %s (action = %s): %s",
      lock._name,
      lock._action,
      err
    )
  end

  return ...
end


---@param ns string
---@param key string
---@param action string
---@param opts? resty.lock.opts
---@return doorbell.lock? lock
---@return string? err
function _M.lock(ns, key, action, opts)
  local lock, err = resty_lock:new(LOCK_SHM, opts)
  if not lock then
    log.errf("failed to create lock (action = %s): %s", action, err)
    return nil, err
  end

  local name = ns .. ":" .. key

  local elapsed
  elapsed, err = lock:lock(name)
  if not elapsed then
    log.errf("failed to acquire lock of %s (action = %s): %s", name, action, err)
    return nil, err
  end

  lock._name = name
  lock._unlock = lock.unlock
  lock.unlock = _unlock
  return lock
end


local buf = {}

---@param ... string
---@return string
function _M.join(...)
  local n = select("#", ...)
  for i = 1, n do
    local elem = select(i, ...)

    if i == 1 then
      elem = elem:gsub("^//+", "/")
    else
      elem = elem:gsub("^/+", "")
    end

    elem = elem:gsub("/+$", "")
    insert(buf, i, elem)
  end

  return concat(buf, "/", 1, n)
end

---@return string
_M.uuid = uuid


---@generic T : table
---@param t T
---@return T
local function deep_copy(t)
  local new
  if type(t) == "table" then
    new = {}

    for k, v in pairs(t) do
      new[k] = deep_copy(v)
    end

  else
    new = t
  end

  return new
end

_M.deep_copy = deep_copy


---@param value any
function _M.truthy(value)
  if type(value) == "string" then
    value = value:lower()
  end

  return value == "yes"
      or value == "1"
      or value == "true"
      or value == true
      or value == 1
end


---@generic T
---@param t? T[]
---@return T[]
function _M.array(t)
  if t == nil then
    t = {}
  end

  if type(t) == "table" then
    setmetatable(t, cjson.array_mt)
  end

  return t
end


do
  local tbuf = {
    year   = nil,
    month  = nil,
    day    = nil,
    hour   = nil,
    minute = nil,
    second = nil,
  }

  ---@class doorbell.time_t : table
  ---
  ---@field year   integer
  ---@field month  integer
  ---@field day    integer
  ---@field hour   integer
  ---@field minute integer
  ---@field second integer

  ---@alias doorbell.time_t.part "year"|"month"|"day"|"hour"|"minute"|"second"

  ---@param part doorbell.time_t.part
  ---@return integer
  ---
  ---@overload fun():doorbell.time_t
  function _M.current_time(part)
    --    1234567890123456789
    local yyyy_mm_dd_hh_mm_ss = utctime()

    tbuf.year   = tonumber(yyyy_mm_dd_hh_mm_ss:sub(1, 4))
    tbuf.month  = tonumber(yyyy_mm_dd_hh_mm_ss:sub(6, 7))
    tbuf.day    = tonumber(yyyy_mm_dd_hh_mm_ss:sub(9, 10))
    tbuf.hour   = tonumber(yyyy_mm_dd_hh_mm_ss:sub(12, 13))
    tbuf.minute = tonumber(yyyy_mm_dd_hh_mm_ss:sub(15, 16))
    tbuf.second = tonumber(yyyy_mm_dd_hh_mm_ss:sub(18, 19))

    if part then
      return assert(tbuf[part], "unknown time component: " .. tostring(part))
    end

    return clone(tbuf)
  end
end


do
  local buf = {}
  local n = 0
  local max_n = 1000
  local i_level = 0
  local i_char  = "  "

  local rep = string.rep
  local json = require("cjson").new()
  json.encode_escape_forward_slash(false)
  local encode = cjson.encode
  local NULL = json.null
  local array_mt = json.array_mt
  local empty_array_mt = json.empty_array_mt

  local function is_array(t)
    local mt = getmetatable(t)
    return mt == array_mt
        or mt == empty_array_mt
        or isarray(t)
  end

  local function reset()
    n = 0
    clear_tab(buf)
  end

  ---@return string
  local function render()
    local s = concat(buf, "", 1, n)
    reset()
    return s
  end

  local function put(s)
    n = n + 1
    buf[n] = s
    if n >= max_n then
      put(render())
    end
  end

  ---@param s string
  ---@param ... any
  local function putf(s, ...)
    put(fmt(s, ...))
  end

  ---@param l string
  local function add_line(l)
    putf("%s%s\n", rep(i_char, i_level), l)
  end

  local function put_indent()
    put(rep(i_char, i_level))
  end

  local function start_line()
    put("\n")
    put_indent()
  end

  local function indent()
    i_level = i_level + 1
  end

  local function dedent()
    i_level = i_level - 1
  end

  local function format_json(v)
    local typ = type(v)

    if typ == "table" then
      local len = nkeys(v)

      if is_array(v) then
        if len == 0 then
          put("[]")

        else
          put("[")
          indent()

          for i = 1, len -1 do
            start_line()
            format_json(v[i])
            put(",")
          end

          start_line()
          format_json(v[len])

          dedent()
          start_line()
          put("]")
        end
      else
        if len == 0 then
          put("{}")

        else
          put("{")
          indent()

          local keys = _M.table_keys(v)

          for i = 1, len - 1 do
            local key = keys[i]
            local value = v[key]
            start_line()

            format_json(key)
            put(": ")

            format_json(value)
            put(",")
          end

          start_line()
          format_json(keys[len])
          put(": ")

          format_json(v[keys[len]])

          dedent()
          start_line()
          put("}")
        end
      end

    elseif typ == "string" then
      put(encode(v))

    elseif typ == "number" then
      put(encode(v))

    elseif typ == "boolean" then
      put(encode(v))

    elseif v == "nil" then
      put(encode(NULL))

    elseif v == NULL then
      put(encode(v))

    else
      error("unknown type: " .. typ)
    end
  end

  ---@param v any
  ---@return string
  function _M.pretty_json(v)
    format_json(v)
    return render()
  end
end

return _M
