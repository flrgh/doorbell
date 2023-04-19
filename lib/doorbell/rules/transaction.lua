local _M = {
  _VERSION = require("doorbell.constants").version,
}

local util  = require "doorbell.util"
local rules = require "doorbell.rules"
local shm   = require "doorbell.rules.shm"
local nkeys = require "table.nkeys"

local insert = table.insert
local pairs  = pairs
local ipairs = ipairs

local LOCK_OPTS = {
  timeout = 5,
  exptime = 5,
}


local function get_lock()
  return util.lock("rules", "trx", "write", LOCK_OPTS)
end

local UPDATE       = "update"
local INSERT       = "insert"
local UPSERT       = "upsert"
local COMMIT       = "commit"
local DELETE       = "delete"
local DELETE_ALL   = "delete_all"
local DELETE_WHERE = "delete_where"

_M.UPDATE       = UPDATE
_M.INSERT       = INSERT
_M.UPSERT       = UPSERT
_M.COMMIT       = COMMIT
_M.DELETE       = DELETE
_M.DELETE_ALL   = DELETE_ALL
_M.DELETE_WHERE = DELETE_WHERE


---@class doorbell.transaction.action
---
---@field id "delete_all"|"delete_where"|"insert"|"update"|"upsert"|"commit"
---
---@field index integer
---
---@field params table


---@class doorbell.rules.transaction : table
---
---@field version integer
---
---@field rules doorbell.rule[]
---
---@field actions table
---
---@field lock doorbell.lock
local trx = {}
trx.__index = trx


local function delete(rule)
  rule.__delete = true
end

local function deleted(rule)
  return rule.__delete == true
end

local function delete_all()
  return {
    id = DELETE_ALL,
    handler = function(list)
      for i = 1, #list do
        delete(list[i])
      end

      return true
    end
  }
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
  return {
    id = DELETE_WHERE,
    params = fields,
    handler = function(candidates)
      for _, rule in ipairs(candidates) do
        if matches(fields, rule) then
          delete(rule)
        end
      end

      return true
    end
  }
end

local function insert_rule(rule)
  local action = {
    id = INSERT,
    params = rule,
  }

  ---@param candidates doorbell.rule[]
  action.handler = function(candidates)
    for _, current in ipairs(candidates) do
      if not deleted(current) then
        if rule.id == current.id or current:is_same(rule) then
          return nil, "exists", INSERT, { new = rule, current = current }
        end
      end
    end

    insert(candidates, rule)
    return true
  end

  return action
end

local function update_rule(hash_or_id, params)
  local action = {
    id = UPDATE,
    params = {
      id = nil,
      hash = nil,
      updates = params,
    },
  }

  if rules.is_hash(hash_or_id) then
    action.params.hash = hash_or_id
  else
    action.params.id = hash_or_id
  end

  ---@param candidates doorbell.rule[]
  action.handler = function(candidates)
    local found = false
    for _, current in ipairs(candidates) do
      if current.hash == hash_or_id or current.id == hash_or_id and not deleted(current) then
        found = true
        for k, v in pairs(params) do
          current[k] = v
        end

        local ok, err = rules.validate_entity(current)
        if not ok then
          return nil, err
        end

        current:update_generated_fields()
      end
    end

    if not found then
      return nil, "rule not found", UPDATE
    end

    return true
  end

  return action
end


local function upsert_rule(rule)
  ---@param candidates doorbell.rule[]
  return {
    id = UPSERT,
    params = rule,
    handler = function(candidates)
      local found = false
      for _, current in ipairs(candidates) do
        if current:is_same(rule) then
          found = true
          for k, v in pairs(rule) do
            current[k] = v
          end

          current:update_generated_fields()
        end
      end

      if not found then
        insert(candidates, rule)
      end

      return true
    end
  }
end


local function add_action(self, action)
  local i = self.actions.n + 1
  self.actions.n = i
  action.index = i
  self.actions[i] = action
end


---@return boolean? success
---@return string? error
---@return any? action
function trx:commit()
  local commit = {
    id = COMMIT,
    params = {
      num_actions = #self.actions,
    },
  }

  if not self.lock:expire() then
    return nil, "unlocked", commit
  end

  local list = self.rules
  for i = 1, #list do
    list[i] = rules.hydrate(list[i])
  end

  for _, action in ipairs(self.actions) do
    local ok, err = action.handler(list)
    if not ok then
      self:abort()
      return self.lock:unlock(nil, err, action)
    end
  end

  local new = {}
  for _, rule in ipairs(list) do
    if not deleted(rule) then
      insert(new, rule)
    end
  end

  if shm.get_latest_version() ~= self.version then
    self:abort()
    return nil, "stale", commit
  end

  shm.set(new, self.version)

  return self.lock:unlock(true)
end

---@return boolean? success
function trx:delete_where(fields)
  assert(type(fields) == "table")
  assert(nkeys(fields) > 0)

  add_action(self, delete_where(fields))
  return true
end

---@return boolean success
function trx:delete_all()
  add_action(self, delete_all())
  return true
end

---@param rule doorbell.rule
---@return boolean? success
---@return string? error
function trx:insert(rule)
  add_action(self, insert_rule(rule))
  return true
end

---@param hash_or_id string
---@param rule doorbell.rule
---@return boolean success
function trx:update(hash_or_id, rule)
  add_action(self, update_rule(hash_or_id, rule))
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
  add_action(self, upsert_rule(rule))
  return true
end

---@return doorbell.rules.transaction? trx
---@return string?                     error
function _M.new()
  local lock, err = get_lock()
  if not lock then
    return nil, err
  end

  shm.update_current_version()
  local version = shm.allocate_new_version()

  local self = setmetatable({
    lock = lock,
    version = version,
    actions = { n = 0 },
    rules = shm.get(),
  }, trx)

  return self
end


return _M
