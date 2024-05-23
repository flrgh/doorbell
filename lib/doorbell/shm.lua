local SHM = {}

local const = require "doorbell.constants"

SHM.approvals         = assert(ngx.shared.approvals,     "ngx.shared.approvals does not exist")
SHM.doorbell          = assert(ngx.shared.doorbell,      "ngx.shared.doorbell does not exist")
SHM.locks             = assert(ngx.shared.locks,         "ngx.shared.locks does not exist")
SHM.metrics           = assert(ngx.shared.metrics,       "ngx.shared.metrics does not exist")
SHM.mlcache_ipc       = assert(ngx.shared.mlcache_ipc,   "ngx.shared.cache does not exist")
SHM.mlcache_locks     = assert(ngx.shared.mlcache_locks, "ngx.shared.cache_locks does not exist")
SHM.mlcache_main      = assert(ngx.shared.mlcache_main,  "ngx.shared.cache does not exist")
SHM.mlcache_miss      = assert(ngx.shared.mlcache_miss,  "ngx.shared.cache_miss does not exist")
SHM.nginx             = assert(ngx.shared.nginx,         "ngx.shared.nginx does not exist")
SHM.pending           = assert(ngx.shared.pending,       "ngx.shared.pending does not exist")
SHM.rules             = assert(ngx.shared.rules,         "ngx.shared.rules does not exist")
SHM.stats             = assert(ngx.shared.stats,         "ngx.shared.stats does not exist")
SHM.shared            = assert(ngx.shared.shared,        "ngx.shared.shared does not exist")

for _, name in pairs(const.shm) do
  assert(SHM[name], "missing " .. name .. " defined in doorbell.constants.shm")
end

local buffer = require "string.buffer"
local encode = buffer.encode
local decode = buffer.decode
local type = type

---@param value doorbell.shm.namespace.value
---@return string|integer value
---@return integer flags
local function encode_value(value)
  local typ = type(value)

  assert(   typ == "string"
         or typ == "number"
         or typ == "boolean"
         or typ == "table",
          "invalid SHM type")

  if typ == "table" then
    return encode(value), 1

  elseif typ == "boolean" then
    return (value and 1 or 0), 2
  end

  return value, 0
end


---@param value string|integer
---@param flags integer
---@return doorbell.shm.namespace.value? decoded
local function decode_value(value, flags)
  if value == nil then
    return
  end

  -- table
  if flags == 1 then
    return decode(value)

  -- boolean
  elseif flags == 2 then
    return value == 1
  end

  return value
end


local list_buf = buffer.new()

---@param value doorbell.shm.namespace.value
---@return string value
local function encode_list_value(value)
  local typ = type(value)

  assert(   typ == "string"
         or typ == "number"
         or typ == "boolean"
         or typ == "table",
          "invalid SHM type")

  if typ == "string" then
    return list_buf:encode(0)
                   :put(value)
                   :get()
  end

  return list_buf:encode(1)
                 :encode(value)
                 :get()
end

---@param value string
---@return doorbell.shm.namespace.value|nil
local function decode_list_value(value)
  if value == nil then
    return
  end

  list_buf:put(value)

  local typ = list_buf:decode()

  -- string
  if typ == 0 then
    return list_buf:get()

  -- others
  elseif typ == 1 then
    return list_buf:decode()

  else
    error("unreachable!")
  end
end


---@type table<string, boolean>
local namespaces = {}

local shared_shm = SHM.shared

---@class doorbell.shm.namespace
---
---@field prefix string
local shm = {}
local shm_mt = { __index = shm }

---@alias doorbell.shm.namespace.key string|integer

---@alias doorbell.shm.namespace.value
---| table
---| string
---| number
---| boolean

---@alias doorbell.shm.namespace.ttl number

---@alias doorbell.shm.namespace.flags integer


---@param key    doorbell.shm.namespace.key
---@param value  doorbell.shm.namespace.value
---@param ttl?   doorbell.shm.namespace.ttl
---@return boolean? ok
---@return string? error
function shm:add(key, value, ttl)
  key = self.prefix .. key

  local flags
  value, flags = encode_value(value)

  local ok, err = shared_shm:safe_add(key, value, ttl, flags)
  return ok, err
end


---@param key    doorbell.shm.namespace.key
---@param value  doorbell.shm.namespace.value|nil
---@param ttl?   doorbell.shm.namespace.ttl
---@return boolean? ok
---@return string? error
function shm:set(key, value, ttl)
  key = self.prefix .. key

  if value == nil then
    local ok, err = shared_shm:set(key, nil)
    return ok, err
  end

  local flags
  value, flags = encode_value(value)

  local ok, err = shared_shm:safe_set(key, value, ttl, flags)
  return ok, err
end


---@param key    doorbell.shm.namespace.key
---@return doorbell.shm.namespace.value? value
---@return string? error
function shm:get(key)
  key = self.prefix .. key
  local raw, flags = shared_shm:get(key)

  if raw == nil then
    return nil, flags
  end

  return decode_value(raw, flags)
end


---@param key    doorbell.shm.namespace.key
function shm:delete(key)
  shared_shm:delete(self.prefix .. key)
end


---@param key       doorbell.shm.namespace.key
---@param value?    integer # default is 1
---@param init?     number
---@param init_ttl? doorbell.shm.namespace.ttl
---@return number? new
---@return string?  error
function shm:incr(key, value, init, init_ttl)
  key = self.prefix .. key

  assert(value == nil or type(value) == "number")

  value = value or 1

  local new, err = shared_shm:incr(key, value, init, init_ttl)
  assert(err == nil or err ~= "not a number")
  return new, err
end

---@param key    doorbell.shm.namespace.key
---@param value  doorbell.shm.namespace.value
---@return integer? len
---@return string? error
function shm:lpush(key, value)
  key = self.prefix .. key
  value = encode_list_value(value)
  local len, err = shared_shm:lpush(key, value)
  assert(err == nil or err ~= "value not a list")
  return len, err
end


---@param key    doorbell.shm.namespace.key
---@param value  doorbell.shm.namespace.value
---@return integer? len
---@return string? error
function shm:rpush(key, value)
  key = self.prefix .. key
  value = encode_list_value(value)
  local len, err = shared_shm:rpush(key, value)
  assert(err == nil or err ~= "value not a list")
  return len, err
end


---@param key    doorbell.shm.namespace.key
---@return doorbell.shm.namespace.value? value
---@return string? error
function shm:lpop(key)
  key = self.prefix .. key
  local raw, err = shared_shm:lpop(key)

  if not raw then
    assert(err == nil or err ~= "value not a list")
    return nil, err
  end

  return decode_list_value(raw)
end


---@param key    doorbell.shm.namespace.key
---@return doorbell.shm.namespace.value? value
---@return string? error
function shm:rpop(key)
  key = self.prefix .. key
  local raw, err = shared_shm:rpop(key)

  if not raw then
    assert(err == nil or err ~= "value not a list")
    return nil, err
  end

  return decode_list_value(raw)
end

---@param key    doorbell.shm.namespace.key
---@return integer
function shm:llen(key)
  key = self.prefix .. key
  local len, err = shared_shm:llen(key)
  assert(err == nil or err ~= "value not a list")
  return len or 0
end


---@param name string
---@return doorbell.shm.namespace
function SHM.with_namespace(name)
  assert(type(name) == "string" and #name > 0)

  assert(namespaces[name] == nil, "duplicate namespace")

  local ns = setmetatable({ prefix = name .. "::" },
                          shm_mt)

  namespaces[name] = true

  return ns
end


function SHM.reset_shared()
  namespaces = {}
  shared_shm:flush_all()
end

function SHM.init_worker()
  if ngx.worker.id() == 0 then
    local timer = require "doorbell.util.timer"
    local log = require("doorbell.log").with_namespace("shm")

    timer.every(60, "shared-shm-cleanup", function()
      local flushed = shared_shm:flush_expired(10) or 0
      while flushed > 0 do
        log.notice("flushed ", flushed, " items from the shared shm")
        flushed = shared_shm:flush_expired(10) or 0
        ngx.sleep(0)
      end
    end)
  end
end

setmetatable(SHM, {
  __index = function(_, name)
    error("trying to access unknown SHM dict: " .. tostring(name), 2)
  end,
})

return SHM
