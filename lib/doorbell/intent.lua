--- doorbell.intent
local _M = {}

local ngx = ngx
local now = ngx.now
local assert = assert
local cjson = require "cjson"
local encode = cjson.encode
local decode = cjson.decode
local fmt = string.format
local assert = assert
local type = type
local tonumber = tonumber
local sub = string.sub

---@type ngx.shared.DICT
local SHM

---@alias doorbell.intent.action '"allow"'|'"deny"'|'"pending"'

local actions = {
  a = "allow",
  allow = "a",

  d = "deny",
  deny = "d",

  p = "pending",
  pending = "p",
}

local function serialize(action, ttl)
  local exp = now() + ttl
  return actions[action] .. exp
end

local function unserialize(value)
  local i = sub(value, 1, 1)
  local action = assert(actions[i])
  local exp = tonumber(sub(value, 2))
  return action, nil, nil, exp - now()
end


---@alias doorbell.intent.map table<string, doorbell.intent.action>

---@param  addr                   string
---@param  host                   string
---@param  path                   string
---@return doorbell.intent.action action
---@return string?                error
---@return boolean                global
---@return number?                ttl
local function get(addr, host, path)
  local key = "intent:" .. addr
  local value, err = SHM:get(key)
  if value == nil then
    return nil, err
  end

  local ttl
  if actions[value] then
    -- for plain/global states, the ttl is the shm ttl
    ttl = SHM:ttl(key)
    return value, nil, true, ttl
  end

  ---@type doorbell.intent.action
  local result

  ---@type doorbell.intent.map
  local intent = decode(value)

  -- host + path
  key = host .. "::" .. path
  result = intent[key]
  if result then return unserialize(result) end

  -- host
  key = host .. "::*"
  result = intent[key]
  if result then return unserialize(result) end

  -- path
  key = "*::" .. path
  result = intent[key]
  if result then return unserialize(result) end

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

  current[idx] = serialize(intent, ttl)

  return SHM:safe_set(key, encode(current), 0)
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
---@return number?                ttl
function _M.get(addr, host, path)
  assert(SHM, "doorbell.intent not initialized!")
  return get(addr, host, path)
end

---@param shm_name string
function _M.init(shm_name)
  SHM = assert(ngx.shared[shm_name])
end

return _M
