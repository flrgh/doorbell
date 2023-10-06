local _M = {}

local util  = require "doorbell.util"
local rules = require "doorbell.rules"
local shm   = require "doorbell.rules.shm"
local nkeys = require "table.nkeys"
local new_tab = require "table.new"

local type   = type
local pairs  = pairs
local is_rule = rules.is_rule

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


---@alias doorbell.transaction.updates doorbell.rule|doorbell.rule.dehydrated|table

---@class doorbell.transaction.rule : doorbell.rule
---
---@field __delete boolean


---@class doorbell.transaction.action
---
---@field id "delete_all"|"delete_where"|"insert"|"update"|"upsert"|"commit"
---
---@field index integer
---
---@field params table
---
---@field error string|nil
---
---@field conflict doorbell.rule|table|nil


---@class doorbell.rules.transaction : table
---
---@field version integer
---
---@field rules doorbell.rule[]|doorbell.transaction.rule[]
---
---@field by_id table<string, doorbell.rule|doorbell.transaction.rule>
---
---@field by_hash table<string, doorbell.rule|doorbell.transaction.rule>
---
---@field actions table
---
---@field lock doorbell.lock
---
---@field len integer
local trx = {}
trx.__index = trx


---@param tx doorbell.rules.transaction
---@param pos integer
---@return doorbell.transaction.rule?
local function delete_at(tx, pos)
  local old = tx.rules[pos]

  if old then
    tx.by_id[old.id] = nil
    tx.by_hash[old.hash] = nil

    old.__delete = true
  end

  return old
end


---@param rule doorbell.transaction.rule
---@return boolean
local function deleted(rule)
  return rule.__delete == true
end


---@param tx doorbell.rules.transaction
---@param pos integer
---@param rule doorbell.rule
---@return boolean? ok
---@return string? error
---@return doorbell.rule? current
local function insert_at(tx, pos, rule)
  local by_id = tx.by_id
  local id = rule.id

  local current = by_id[id]
  if current then
    return nil, "duplicate rule id: " .. id, current
  end

  local by_hash = tx.by_hash
  local hash = rule.hash
  current = by_hash[hash]
  if current then
    return nil, "duplicate rule hash: " .. hash, current
  end

  local list = tx.rules
  current = list[pos]
  if current and not deleted(current) then
    return nil, "rule already exists at position " .. tostring(pos), current
  end

  by_id[id] = rule
  by_hash[hash] = rule
  list[pos] = rule

  if pos > tx.len then
    tx.len = pos
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


---@param rule doorbell.rule|doorbell.transaction.rule
---@param params { id:string|nil, hash:string|nil }
---@return boolean
local function same(rule, params)
  return (params.id ~= nil and rule.id == params.id)
      or (params.hash ~= nil and rule.hash == params.hash)
end


local ACTIONS = {
  ---@param tx doorbell.rules.transaction
  [DELETE_ALL] = function(tx)
    for i = 1, tx.len do
      delete_at(tx, i)
    end

    return true
  end,

  ---@param tx doorbell.rules.transaction
  ---@param params doorbell.rule|table
  [DELETE_WHERE] = function(tx, params)
    local list = tx.rules

    for i = 1, tx.len do
      if matches(params, list[i]) then
        delete_at(tx, i)
      end
    end

    return true
  end,

  ---@param tx doorbell.rules.transaction
  ---@param rule doorbell.rule
  ---@param act doorbell.transaction.action
  [INSERT] = function(tx, rule, act)
    local ok, err, current = insert_at(tx, tx.len + 1, rule)
    if not ok then
      act.error = err
      act.conflict = current
      return false
    end

    return true
  end,

  ---@param tx doorbell.rules.transaction
  ---@param params { id:string|nil, hash:string|nil, updates:table }
  ---@param act doorbell.transaction.action
  [UPDATE] = function(tx, params, act)
    local current
    if params.hash then
      current = tx.by_hash[params.hash]

    else
      current = tx.by_id[params.id]
    end

    if not current then
      act.error = "rule not found"
      return false
    end

    local old_hash = current.hash

    for k, v in pairs(params.updates) do
      current[k] = v
    end

    local ok, err = rules.validate_entity(current)

    if not ok then
      act.error = err
      return false
    end

    current:update_generated_fields()

    if current.hash ~= old_hash then
      tx.by_hash[old_hash] = nil
      tx.by_hash[current.hash] = current
    end

    return true
  end,

  ---@param tx doorbell.rules.transaction
  ---@param rule doorbell.rule
  ---@param act doorbell.transaction.action
  [UPSERT] = function(tx, rule, act)
    local list = tx.rules
    local pos = tx.len + 1

    for i = 1, tx.len do
      local current = list[i]

      if same(current, rule) then
        pos = i

        -- preserve the existing ID
        if not deleted(current) then
          rule.id = current.id
        end

        delete_at(tx, pos)
        break
      end
    end

    local ok, err, current = insert_at(tx, pos, rule)
    if not ok then
      act.error = err
      act.conflict = current
      return false
    end

    return true
  end,
}


---@param tx doorbell.rules.transaction
---@param id string
---@param params? any
local function add_action(tx, id, params)
  assert(ACTIONS[id], "unknown action: " .. id)

  local i = tx.actions.n + 1
  tx.actions.n = i
  tx.actions[i] = {
    id      = id,
    index   = i,
    params  = params,
  }
end


---@return boolean? success
---@return string? error
---@return doorbell.transaction.action? action
function trx:commit()
  local commit = {
    id = COMMIT,
    params = {
      num_actions = self.actions.n,
    },
    index = self.actions.n + 1,
  }

  if not self.lock:expire() then
    return nil, "unlocked", commit
  end

  for i = 1, self.actions.n do
    local act = self.actions[i]
    local handler = ACTIONS[act.id]

    if not handler(self, act.params, act) then
      self:abort()
      return self.lock:unlock(nil, act.error, act)
    end
  end

  local list = self.rules
  local last = 0

  for i = 1, self.len do
    local rule = list[i]

    if not deleted(rule) then
      last = last + 1
      list[last] = rule
    end
  end

  for i = last + 1, self.len do
    list[i] = nil
  end

  self.len = last

  if shm.get_latest_version() ~= self.version then
    self:abort()
    return nil, "stale", commit
  end

  shm.set(list, self.version)

  return self.lock:unlock(true)
end


---@param fields table
---@return boolean? success
function trx:delete_where(fields)
  assert(type(fields) == "table")
  assert(nkeys(fields) > 0)

  add_action(self, DELETE_WHERE, fields)
  return true
end


---@return boolean success
function trx:delete_all()
  add_action(self, DELETE_ALL)
  return true
end


---@param rule doorbell.rule
---@return boolean? success
---@return string? error
function trx:insert(rule)
  assert(is_rule(rule), "insert() arg must be a rule")

  add_action(self, INSERT, rule)
  return true
end


---@param hash_or_id string
---@param updates doorbell.transaction.updates
---@return boolean success
function trx:update(hash_or_id, updates)
  assert(type(hash_or_id) == "string")
  assert(type(updates) == "table")
  assert(updates.id == nil, "cannot change a rule's ID")
  assert(updates.hash == nil, "unexpected update.hash")

  local id, hash
  if rules.is_hash(hash_or_id) then
    hash = hash_or_id

  else
    id = hash_or_id
  end

  add_action(self, UPDATE, {
    hash = hash,
    id = id,
    updates = updates,
  })

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
  assert(is_rule(rule), "upsert() arg must be a rule")

  add_action(self, UPSERT, rule)
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

  local list = shm.get()
  local len = #list
  local by_hash = new_tab(0, len)
  local by_id = new_tab(0, len)

  for i = 1, len do
    local rule = list[i]
    by_id[rule.id] = rule
    by_hash[rule.hash] = rule
  end

  local self = setmetatable({
    actions = { n = 0 },
    by_hash = by_hash,
    by_id   = by_id,
    len     = len,
    lock    = lock,
    rules   = list,
    version = version,
  }, trx)

  return self
end


return _M
