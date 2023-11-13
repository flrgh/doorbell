local _M = {}

local const       = require "doorbell.constants"
local log         = require "doorbell.log"
local metrics     = require "doorbell.metrics"
local stats       = require "doorbell.rules.stats"
local util        = require "doorbell.util"
local storage     = require "doorbell.rules.storage"
local rules       = require "doorbell.rules"
local matcher     = require "doorbell.rules.matcher"
local shm         = require "doorbell.rules.shm"
local transaction = require "doorbell.rules.transaction"
local forwarded   = require "doorbell.auth.forwarded-request"
local timer       = require "doorbell.util.timer"

local ngx         = ngx
local now         = ngx.now
local sleep       = ngx.sleep
local get_phase   = ngx.get_phase
local null        = ngx.null
local start_time  = ngx.req.start_time

local assert       = assert
local min          = math.min
local ceil         = math.ceil
local insert       = table.insert
local pairs        = pairs
local ipairs       = ipairs
local type         = type

local req_cache_key = forwarded.cache_key
local reset_req_cache = forwarded.reset_cache

local META = require("doorbell.shm").doorbell
local SAVE_PATH

local errorf = util.errorf

---@type PrometheusCounter
local rule_actions
---@type PrometheusGauge
local rules_total

local cache = require("doorbell.cache").new("rules", 1000)

local RULES_VERSION = 0
---@type doorbell.rule[]
local RULES = {}
---@type table<string, doorbell.rule>
local RULES_BY_ID = {}
---@type table<string, doorbell.rule>
local RULES_BY_HASH = {}

local NEG_CACHE_TTL = 60

local function update_local_rules()
  local version = shm.update_current_version()
  if version == RULES_VERSION then
    return
  end

  local list = shm.get(version)
  local by_id = {}
  local by_hash = {}

  for i = 1, #list do
    local rule = list[i]
    by_id[rule.id] = rule
    by_hash[rule.hash] = rule
  end

  RULES = list
  RULES_BY_ID = by_id
  RULES_BY_HASH = by_hash
  RULES_VERSION = version
end


local function need_save(x)
  local key = "rules:need-save"

  if type(x) == "number" then
    return META:incr(key, x, 1, 0) or 0
  end
  return META:get(key) or 0
end

local function last_saved(x)
  local key = "rules:last-saved"

  if type(x) == "number" then
    local ok, err = META:safe_set(key, x)
    if not ok then
      log.alertf("failed setting %s: %s", key, err)
      return 0
    end
    return x
  end
  return META:get(key) or 0
end

local function inc_version()
  return shm.update_current_version()
end

local function noop(...)
  return ...
end

---@nodiscard
local function lock_storage(action, locked)
  if locked then
    return noop
  end

  local lock, err = util.lock("rules", "storage", action)

  if not lock then
    errorf("failed creating storage lock (action = %s): %s", action, err or "unknown")
  end

  return function(...)
    return lock:unlock(...)
  end
end


---@param hash_or_id string
local function get(hash_or_id)
  update_local_rules()

  local rule
  if rules.is_id(hash_or_id) then
    rule = RULES_BY_ID[hash_or_id]

  elseif rules.is_hash(hash_or_id) then
    rule = RULES_BY_HASH[hash_or_id]
  end

  return rule
end


---@param rule string|doorbell.rule
---@return boolean? ok
---@return string? error
---@return integer? status_code
local function delete_rule(rule)
  update_local_rules()

  if rules.is_hash(rule) then
    rule = RULES_BY_HASH[rule]

  elseif rules.is_id(rule) then
    rule = RULES_BY_ID[rule]

  elseif type(rule) == "table" then
    rule = RULES_BY_HASH[rule.hash]
  end

  if not rule then
    return nil, "not found", 404
  end

  local trx, err = transaction.new()
  if not trx then
    return nil, err, 500
  end

  local ok
  ok, err = trx:delete_where({ id = rule.id })
  if not ok then
    trx:abort()
    return nil, err, 500
  end

  ok, err = trx:commit()
  if not ok then
    return nil, err, 500
  end

  inc_version()
  need_save(1)

  return true
end

---@return doorbell.rule[]
local function get_all_rules()
  return shm.get()
end


local check_match

local function rebuild_matcher()
  update_local_rules()
  local match = matcher.new(RULES)
  cache:flush_all()
  reset_req_cache()
  check_match = match
end


--- flush any expired rules from shared memory
local function flush_expired(locked)
  local unlock, err = lock_storage("flush-expired", locked)
  if not unlock then
    log.err("failed locking storage for expired rule cleanup: ", err)
    return
  end

  shm.flush_expired()
  stats.flush_expired()

  local deleted = 0
  local updated = 0

  local t = now()
  local min_ttl = const.periods.hour
  local tx
  for _, rule in ipairs(get_all_rules()) do
    if rule:can_renew() then
      local last_matched = stats.get_last_match(rule)
      if last_matched and rule:in_renew_period(last_matched) then
        local new_expires = rule.expires + rule.renew_period
        log.debugf("renewing rule %s, expires %s => %s",
                   rule.id, rule.expires, new_expires)

        tx = tx or assert(transaction.new())
        tx:update(rule.id, { expires = new_expires })
        updated = updated + 1
      end
    end

    local expired, ttl = rule:expired(t)
    if expired then
      tx = tx or assert(transaction.new())
      tx:delete_where({ id = rule.id })
      deleted = deleted + 1
    else
      min_ttl = min(min_ttl, ttl)
    end
  end

  if tx then
    local ok
    ok, err = tx:commit()
    if ok then
      log.debugf("renewed %s rules, deleted %s expired rules", updated, deleted)
    else
      log.errf("failed to update/delete expired rules: %s", err)
    end

    inc_version()
    need_save(1)
  else
    log.debug("no expired rules to delete")
  end

  unlock()
end


---@return number
local function get_version()
  return shm.get_current_version()
end


local function reload()
  local start = now()
  rebuild_matcher()
  local duration = now() - start
  duration = ceil(duration * 1000) / 1000

  log.debugf("reloaded match rules for version %s in %ss", RULES_VERSION, duration)
end

--- save rules from shared memory to disk
---@param fname string
---@return integer? version
local function save(fname)
  local unlock, err = lock_storage("save")
  if not unlock then
    log.err("failed locking storage: ", err)
    return
  end

  local version = get_version()
  local list = get_all_rules()

  local ok, werr, written = util.update_json_file(fname, storage.serialize(list))
  if ok then
    if written then
      log.noticef("saved %s rules to %s", #list, fname)

    else
      log.debug("rule filesystem state was unchanged")
    end
  else
    log.errf("failed saving rules to %s: %s", fname, werr)
    return unlock()
  end

  last_saved(now())

  return unlock(version)
end

local saver
do
  local last = now()

  function saver()
    local c = need_save()
    if c > 0 then
      save(SAVE_PATH)
      need_save(-c)
      last = now()

    elseif (now() - last) > 60 then
      save(SAVE_PATH)
      last = now()
    end
  end
end


---@param  rule           doorbell.rule
---@param  nobuild        boolean
---@param  overwrite      boolean
---@return doorbell.rule? rule
---@return string?        error
---@return integer?       status_code
---@return doorbell.rule? conflict
local function create(rule, nobuild, overwrite)
  assert(rules.is_rule(rule), "passed an uninitialized rule to the manager")

  local trx, err = transaction.new()
  if not trx then
    return nil, err, 500
  end

  local ok
  if overwrite then
    ok, err = trx:upsert(rule)
  else
    ok, err = trx:insert(rule)
  end

  if not ok then
    errorf("failed adding/updating rule: %s", err)
  end

  local act
  ok, err, act = trx:commit()
  if not ok then
    if act.conflict then
      return nil, err, 400, act.conflict
    end
    errorf("failed to commit transaction: %s", err)
  end

  need_save(1)

  local inc
  inc, err = inc_version()
  if not inc then
    errorf("failed incrementing version: %s", err)
  end

  if not nobuild then reload() end

  return rule
end


---@param id_or_hash string
---@return doorbell.rule?
---@return string? error
function _M.get(id_or_hash)
  if type(id_or_hash) ~= "string" then
    return nil, "input must be a string"
  end
  return get(id_or_hash)
end

--- add a rule
---@param  rule    doorbell.rule
---@return doorbell.rule? rule
---@return string? error
---@return integer? status_code
---@return doorbell.rule? conflict
function _M.add(rule, nobuild)
  return create(rule, nobuild, false)
end

--- create or update a rule
---@param  rule doorbell.rule
---@return doorbell.rule? rule
---@return string? error
function _M.upsert(rule, nobuild)
  return create(rule, nobuild, true)
end

--- get a matching rule for a request
---@param  req            doorbell.forwarded_request
---@return doorbell.rule? rule
---@return boolean?       cache_hit
function _M.match(req)
  local version = get_version()
  if not check_match or version ~= RULES_VERSION then
    reload()
  end

  local cached = true
  local key = req_cache_key(req)

  ---@type doorbell.rule
  local rule = cache:get("req", key)

  -- negative cache
  if rule == false then
    return nil, true

  elseif not rule then
    cached = false
    rule = check_match(req)
  end

  if rule then
    local time = now()
    if rule:expired(time) then
      return
    end

    if not cached then
      cache:set("req", key, rule, rule:remaining_ttl(time))
    end

  else
    cache:set("req", key, false, NEG_CACHE_TTL)
  end

  return rule, cached
end

---@param rule string|doorbell.rule
---@return boolean? ok
---@return string? error
---@return integer? status_code
function _M.delete(rule)
  local ok, err, status = delete_rule(rule)
  if not ok then
    return nil, err, status
  end

  return true
end

---@param  id_or_hash     string
---@param  updates        doorbell.rule
---@return doorbell.rule? patched
---@return string?        error
---@return integer?       status_code
function _M.patch(id_or_hash, updates)
  assert(type(updates) == "table")

  local rule = get(id_or_hash)

  if not rule then
    return nil, "rule not found", 404
  end

  for k, v in pairs(updates) do
    if v == null then
      v = nil
    end

    rule[k] = v
  end


  local ok, err = rules.validate_entity(rule)
  if not ok then
    return nil, err, 400
  end


  return create(rule, true, true)
end

--- retrieve a list of all current rules
---@return doorbell.rule[]
function _M.list()
  return util.array(get_all_rules())
end

function _M.reset()
  shm.reset()
  return reload()
end

--- reload the rule matching function from shared memory
function _M.reload()
  shm.flush_expired()
  return reload()
end


---@param timeout? number
---@return boolean? ok
---@return string? error
function _M.save(timeout)
  local before = last_saved()
  local time = now()

  local _, err = need_save(1)
  if err then
    return nil, err
  end

  local waited = 0
  timeout = timeout or 10
  while waited < timeout do
    local stamp = last_saved()
    if stamp >= before and stamp >= time then
      return true
    end

    sleep(0.01)
    waited = waited + 0.01
  end

  return nil, "timeout"
end

--- reload rules from disk
---@param dir string
---@return boolean? ok
---@return string? error
function _M.load(dir)
  local fname = util.join(dir, "rules.json")

  -- don't attempt to acquire a lock if we're in init
  local locked = get_phase() == "init"

  local unlock, err = lock_storage("load-from-disk", locked)
  if not unlock then
    return nil, err
  end

  local data
  data, err = util.read_json_file(fname)
  if not data then
    return unlock(nil, err)
  end

  local list = storage.unserialize(data)

  local trx = assert(transaction.new())
  assert(trx:delete_all())

  local time = now()

  local count = 0
  for _, rule in ipairs(list) do
    if rule.source == const.sources.config then
      log.debugf("skipping restore of config rule %s", rule.id)

    elseif rule:expired(time) then
      log.debugf("skipping restore of expired rule %s", rule.id)

    else
      assert(trx:insert(rule))
      count = count + 1
    end
  end

  assert(trx:commit())

  inc_version()

  log.noticef("restored %s rules from disk", count)
  return unlock(true)
end

--- get the current data store version
---@return integer
function _M.version()
  return get_version()
end

function _M.init_worker()
  if ngx.worker.id() == 0 then
    timer.every(1, "flush-expired-rules", flush_expired)
    timer.every(1, "save-rules", saver, { run_on_premature = true })
  end

  stats.init_worker()

  if metrics.enabled() and ngx.worker.id() == 0 then

    rules_total = metrics.registry.rules_total
    rule_actions = metrics.registry.rule_actions

    metrics.add_hook(function()
      -- rule counts
      do
        local counts = {}
        for _, action in pairs(const.actions) do
          counts[action] = {}
          for _, source in pairs(const.sources) do
            counts[action][source] = 0
          end
        end

        for _, rule in ipairs(get_all_rules()) do
          counts[rule.action][rule.source] = counts[rule.action][rule.source] + 1
        end

        for action, sources in pairs(counts) do
          for source, num in pairs(sources) do
            rules_total:set(num, {action, source})
          end
        end
      end
    end)
  end
end


---@param ctx doorbell.ctx
function _M.stats_middleware(ctx)
  ---@type doorbell.rule
  local rule = ctx.rule
  if not rule then
    return
  end

  local time = now()
  local start = start_time()

  stats.inc_match_count(rule, 1, time)
  stats.set_last_match(rule, start, time)

  if rule_actions then
    rule_actions:inc(1, { rule.action })
  end
end

---@param conf doorbell.config
function _M.init(conf)
  SAVE_PATH = util.join(conf.runtime_path, "rules.json")
  stats.init(conf)

  local ok, err = _M.load(conf.runtime_path)
  if not ok then
    log.warn("failed loading rules from disk: ", err)
  end

  for _, rule in ipairs(conf.allow or {}) do
    rule.action = const.actions.allow
    rule.source = const.sources.config
    rule = assert(rules.new(rule))
    assert(_M.upsert(rule, true))
  end

  for _, rule in ipairs(conf.deny or {}) do
    rule.action = const.actions.deny
    rule.source = const.sources.config
    rule = assert(rules.new(rule))
    assert(_M.upsert(rule, true))
  end

  update_local_rules()
  stats.load(RULES)
end

function _M.update()
  inc_version()
  update_local_rules()
end

return _M
