local _M = {
  _VERSION = require("doorbell.constants").version,
}

local const   = require "doorbell.constants"
local log     = require "doorbell.log"
local stats   = require "doorbell.rules.stats"
local util    = require "doorbell.util"
local rules   = require "doorbell.rules"
local matcher = require "doorbell.rules.matcher"
local shm = require "doorbell.rules.shm"

local cjson      = require "cjson"
local uuid       = require("resty.jit-uuid").generate_v4

local ngx         = ngx
local now         = ngx.now
local timer_at    = ngx.timer.at
local sleep       = ngx.sleep
local exiting     = ngx.worker.exiting
local get_phase   = ngx.get_phase

local assert       = assert
local encode       = cjson.encode
local min          = math.min
local ceil         = math.ceil
local fmt          = string.format
local insert       = table.insert
local pairs        = pairs
local ipairs       = ipairs
local type         = type



local function get_lock(action)
  return util.lock("rules", "trx", action)
end



---@class doorbell.rules.transaction : table
---
---@field version integer
---
---@field rules doorbell.rule[]
---
---@field actions table
local trx = {}
trx.__index = trx


local function delete(rule)
  rule.__delete = true
end

local function deleted(rule)
  return rule.__delete == true
end

local function delete_all(list)
  for i = 1, #list do
    delete(list[i])
  end

  return true
end

local function matches(fields, rule)
  for k, v in pairs(fields) do
    if rule[k] ~= v then
      return false
    end
  end
  return true
end

local function delete_where(fields)
  return function(candidates)
    for _, rule in ipairs(candidates) do
      if matches(fields, rule) then
        delete(rule)
      end
    end

    return true
  end
end

local function insert_rule(rule)
  return function(candidates)
    for _, current in ipairs(candidates) do
      if current:is_same(rule) and not deleted(current) then
        return nil, "exists"
      end
    end

    insert(candidates, rule)
    return true
  end
end

local function update_rule(hash_or_id, params)
  return function(candidates)
    local found = false
    for _, current in ipairs(candidates) do
      if current.hash == hash_or_id or current.id == hash_or_id then
        found = true
        for k, v in pairs(params) do
          current[k] = v
        end

        local ok, err = rules.new(current)
        if not ok then
          return nil, err
        end

        current:update_hash()
      end
    end

    if not found then
      return nil, "rule not found"
    end

    return true
  end
end

local function upsert_rule(rule)
  return function(candidates)
    local found = false
    for _, current in ipairs(candidates) do
      if current:is_same(rule) then
        found = true
        for k, v in pairs(rule) do
          current[k] = v
        end
        current:update_hash()
      end
    end

    if not found then
      insert(candidates, rule)
    end

    return true
  end
end


---@return boolean? success
---@return string? error
function trx:commit()
  local lock, err = get_lock("transaction:commit")
  if not lock then
    return nil, err
  end

  local list = self.rules
  for i = 1, #list do
    list[i] = rules.hydrate(list[i])
  end

  for _, action in ipairs(self.actions) do
    local ok
    ok, err = action(list)
    if not ok then
      self:abort()
      return lock:unlock(nil, err)
    end
  end


  local new = {}
  for _, rule in ipairs(list) do
    if not deleted(rule) then
      insert(new, rule)
    end
  end

  shm.set(new, self.version)

  return lock:unlock(true)
end

---@return boolean? success
function trx:delete_where(fields)
  insert(self.actions, delete_where(fields))
  return true
end

---@return boolean success
function trx:delete_all()
  insert(self.actions, delete_all)
  return true
end

---@param rule doorbell.rule
---@return boolean? success
---@return string? error
function trx:insert(rule)
  insert(self.actions, insert_rule(rule))
  return true
end

---@param hash_or_id string
---@param rule doorbell.rule
---@return boolean success
function trx:update(hash_or_id, rule)
  insert(self.actions, update_rule(hash_or_id, rule))
  return true
end

---@return boolean success
function trx:abort()
  shm.cancel_pending_version(self.version)
  return true
end

---@param rule doorbell.rule
---@return boolean? success
---@return string? error
function trx:upsert(rule)
  insert(self.actions, upsert_rule(rule))
  return true
end

---@return doorbell.rules.transaction? trx
---@return string?                     error
function _M.new()
  local lock, err = get_lock("transaction:create")
  if not lock then
    return nil, err
  end

  local self = setmetatable({
    lock = lock,
    version = shm.allocate_new_version(),
    actions = {},
    rules = shm.get(),
  }, trx)

  return lock:unlock(self)
end


return _M
