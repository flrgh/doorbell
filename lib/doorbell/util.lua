local _M = {}

local const   = require "doorbell.constants"
local log     = require("doorbell.log").with_namespace("util")
local cjson = require "cjson.safe"
local resty_lock = require "resty.lock"
local uuid = require("resty.jit-uuid").generate_v4
local clone = require "table.clone"
local file = require "doorbell.util.file"
local proc = require("doorbell.nginx").process

local type    = type
local fmt     = string.format
local byte    = string.byte
local utctime = ngx.utctime
local error   = error
local re_find = ngx.re.find
local pairs   = pairs
local sort    = table.sort
local select  = select
local concat  = table.concat
local to_hex  = require("resty.string").to_hex
local rand_bytes = require("resty.random").bytes
local run_worker_thread = ngx.run_worker_thread
local get_phase = ngx.get_phase
local exiting = ngx.worker.exiting

local THREAD_POOL = "doorbell.util.file"

local LOCK_SHM = const.shm.locks

local TILDE = byte("~")


---@return boolean
local function should_run_in_thread()
  local phase = get_phase()

  return proc.is_worker
     and not exiting()
     and (
             phase == "timer"
          or phase == "access"
          or phase == "rewrite"
          or phase == "content"
          or phase == "header_filter"
          or phase == "set"
          or phase == "body_filter"
          or phase == "log"
          or phase == "balancer"
        )
end

---@param fn string
---@param ... any
local function run_it(fn, ...)
  if should_run_in_thread() then
    local ok, a, b, c, d = run_worker_thread(THREAD_POOL, "doorbell.util.file", fn, ...)

    if ok then
      return a, b, c, d

    else
      return nil, a
    end

  else
    return file[fn](...)
  end
end


--- Read the contents of a file.
---@param fname string
---
---@return string? contents
---@return string? error
local function read_file(fname)
  return run_it("read", fname)
end

_M.read_file = read_file

---@param fname string
---@param contents string
---@return boolean? ok
---@return string? error
local function write_file(fname, contents)
  return run_it("write", fname, contents)
end

_M.write_file = write_file

---@param fname string
---@param contents string
---@return boolean? ok
---@return string? error
---@return boolean? written
local function update_file(fname, contents)
  return run_it("update", fname, contents)
end

_M.update_file = update_file

--- Read and unserialize json data from a file.
---
---@param fname string
---@return any? json
---@return string? error
function _M.read_json_file(fname)
  return run_it("read_json", fname)
end

--- Serialize and write json data to a file
---
---@param fname string
---@param json table
---@return boolean? ok
---@return string? error
function _M.write_json_file(fname, json)
  return run_it("write_json", fname, json)
end

---@param fname string
---@param json table
---@return boolean? ok
---@return string? error
---@return boolean? written
function _M.update_json_file(fname, json)
  return run_it("update_json", fname, json)
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
    if not unique or not seen[value] then
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
---@field name string
---@field action string
---@field unlock fun(self:doorbell.lock, ...: any):any
---@field inner resty.lock

---@param self doorbell.lock
---@param ... any
---@return any
local function unlock(self, ...)
  local ok, err = self.inner:unlock()
  if not ok then
    log.errf(
      "failed unlocking lock %s (action = %s): %s",
      self.name,
      self.action,
      err
    )
  end

  return ...
end

local function expire(self, ...)
  return self.inner:expire(...)
end

---@param  ns             string
---@param  key            string
---@param  action         string
---@param  opts?          resty.lock.opts
---@return doorbell.lock? lock
---@return string?        err
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

  lock = {
    inner = lock,
    name = name,
    action = action,
    unlock = unlock,
    expire = expire,
  }

  return lock
end


do
  local buf = {}

  ---@param ... string
  ---@return string
  function _M.join(...)
    local n = select("#", ...)

    for i = 1, n do
      local elem = select(i, ...)
      buf[i] = elem
    end

    local s = concat(buf, "/", 1, n)

    s = s:gsub("//+", "/")
    if s ~= "/" then
      s = s:gsub("/+$", "")
    end

    return s
  end
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
      or value == "on"
      or value == "1"
      or value == "true"
      or value == true
      or value == 1
end


---@param value any
function _M.falsy(value)
  if type(value) == "string" then
    value = value:lower()
  end

  return value == "no"
      or value == "off"
      or value == "0"
      or value == "false"
      or value == false
      or value == 0
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

---@param t table
---@param label string
function _M.error_on_missing_key(t, label)
  assert(type(t) == "table")
  assert(type(label == "string"))
  setmetatable(t, {
    __index = function(_, key)
      error(label .. ": missing key: " .. tostring(key), 2)
    end,
  })
end


---@generic V
---@param t table<any, V>
---@return table<V, true>
function _M.lookup_from_values(t)
  local lookup = {}
  for _, v in pairs(t) do
    lookup[v] = true
  end

  return lookup
end


---@param s string
---@return string[]
function _M.split_at_comma(s)
  local items = _M.array()
  local _ = s:gsub("[^,]+", function(word)
    word = word:gsub("^%s+", ""):gsub("%s+$", "")
    table.insert(items, word)
  end)

  return items
end

do
  local sha256 = require("resty.sha256"):new()

  function _M.sha256(s)
    sha256:reset()
    sha256:update(s)
    local res = sha256:final()
    sha256:reset()
    return to_hex(res)
  end
end

_M.unpack = _G.table.unpack or _G.unpack


---@param nbytes? integer
---@return string
function _M.random_string(nbytes)
  nbytes = nbytes or 24
  local bytes = rand_bytes(nbytes, true)
  return to_hex(bytes)
end


return _M
