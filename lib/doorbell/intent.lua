--- doorbell.intent
local _M = {}

local ngx = ngx
local now = ngx.now
local assert = assert
local cjson = require "cjson"
local encode = cjson.encode
local decode = cjson.decode
local concat = table.concat
local fmt = string.format

local EMPTY = setmetatable({}, { __newindex = function() error("NO") end })

---@type ngx.shared.DICT
local SHM

---@alias doorbell.intent.action '"allow"'|'"deny"'|'"pending"'

local actions = {
  allow = true,
  pending = true,
  deny = true,
}

---@alias doorbell.intent.map table<string, doorbell.intent.action>

---@param  addr                   string
---@param  host                   string
---@param  path                   string
---@return doorbell.intent.action action
---@return string?                error
---@return boolean                global
local function get(addr, host, path)
  local value, err = SHM:get("intent:" .. addr)
  if value == nil then
    return nil, err
  end

  if actions[value] then
    return value, nil, true
  end

  ---@type doorbell.intent.action
  local result

  ---@type doorbell.intent.map
  local intent = decode(value)

  -- host + path
  local key = host .. "::" .. path
  result = intent[key]
  if result then return result end

  -- host
  key = host .. "::*"
  result = intent[key]
  if result then return result end

  -- path
  key = "*::" .. path
  result = intent[key]
  if result then return result end

  return get("*", host, path)
end


---@param  addr    string
---@param  host?   string
---@param  path?   string
---@param  intent  doorbell.intent.action
---@param  ttl     number
---@return boolean ok
---@return string? error
local function upsert(addr, host, path, intent, ttl)
  local key = "intent:" .. addr

  local idx = (host or "*") .. "::" .. (path or "*")

  if idx == "*::*" then
    return SHM:safe_set(key, intent, ttl)
  end

  ---@type doorbell.intent.map
  local current, err = SHM:get(key)
  if current == nil and err ~= nil then
    return nil, err
  end

  if current == nil or actions[current] then
    current = {}
  else
    current = decode(current)
  end

  current[idx] = intent

  return SHM:safe_set(key, encode(current), ttl)
end

---@param  addr    string
---@param  host?   string
---@param  path?    string
---@param  ttl?    number
---@return boolean ok
---@return string? error
function _M.allow(addr, host, path, ttl)
  assert(SHM, "doorbell.intent not initialized!")
  return upsert(addr, host, path, "allow", ttl)
end

---@param  addr    string
---@param  host?   string
---@param  path?    string
---@param  ttl?    number
---@return boolean ok
---@return string? error
function _M.deny(addr, host, path, ttl)
  assert(SHM, "doorbell.intent not initialized!")
  return upsert(addr, host, path, "deny", ttl)
end

---@param  addr    string
---@param  ttl?    number
---@return boolean ok
---@return string? error
function _M.pending(addr, ttl)
  assert(SHM, "doorbell.intent not initialized!")
  return upsert(addr, "*", "*", "pending", ttl)
end

---@param  addr                   string
---@param  host                   string
---@param  path                   string
---@return doorbell.intent.action action
---@return string?                error
---@return boolean                global
function _M.get(addr, host, path)
  assert(SHM, "doorbell.intent not initialized!")
  return get(addr, host, path)
end

---@param shm_name string
function _M.init(shm_name)
  SHM = assert(ngx.shared[shm_name])
end

return _M
