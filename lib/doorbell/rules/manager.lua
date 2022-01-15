local _M = {
  _VERSION = require("doorbell.constants").version,
}

local const   = require "doorbell.constants"
local log     = require "doorbell.log"
local metrics = require "doorbell.metrics"
local ip      = require "doorbell.ip"
local stats   = require "doorbell.rules.stats"
local util    = require "doorbell.util"
local storage = require "doorbell.rules.storage"
local rules   = require "doorbell.rules"
local matcher = require "doorbell.rules.matcher"

local cjson      = require "cjson"
local resty_lock = require "resty.lock"
local uuid       = require("resty.jit-uuid").generate_v4

local ngx         = ngx
local now         = ngx.now
local timer_at    = ngx.timer.at
local sleep       = ngx.sleep
local exiting     = ngx.worker.exiting

local assert       = assert
local encode       = cjson.encode
local min          = math.min
local ceil         = math.ceil
local fmt          = string.format
local insert       = table.insert
local pairs        = pairs
local ipairs       = ipairs
local type         = type


local SHM_NAME  = const.shm.rules
local SHM       = assert(ngx.shared[SHM_NAME], "rules SHM missing")
local META_NAME = const.shm.doorbell
local META      = assert(ngx.shared[META_NAME], "main SHM missing")
local SAVE_PATH
local HASH  = assert(ngx.shared[const.shm.rule_hash])


---@type prometheus.counter
local rule_actions
---@type prometheus.gauge
local rules_total

local EMPTY = {}

local cache = require("doorbell.cache").new("rules", 1000)

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
  return META:incr("rules:version", 1, 0)
end

local function errorf(...)
  error(fmt(...))
end

local LOCK_OPTS = {
  exptime = 30,
  timeout = 5,
}


local function noop() end

---@nodiscard
local function lock_storage(action, locked)
  if locked then
    return noop
  end

  local lock, err = resty_lock:new(META_NAME, LOCK_OPTS)
  if not lock then
    errorf("failed creating storage lock (action = %s): %s", action, err or "unknown")
  end
  local elapsed
  elapsed, err = lock:lock("lock:rules")
  if not elapsed then
    errorf("failed locking storage (action = %s): %s", action, err)
  end

  return function()
    local unlocked, uerr = lock:unlock()
    if not unlocked then
      log.errf("failed unlocking storage (action = %s): %s", action, uerr)
    end
  end
end

local cache_key
do
  local have_geoip = ip.geoip_enabled()
  --- generate a cache key for a request object
  ---@param  req doorbell.request
  ---@return string
  function cache_key(req)
    local country = (have_geoip and req.country) or "_"
    return fmt(
      "%s||%s||%s||%s||%s||%s",
      req.addr,
      country,
      req.method,
      req.host,
      req.path,
      req.ua
    )
  end
end

local VERSION = 0

---@param rule doorbell.rule
---@param overwrite boolean
---@return boolean ok
---@return string? error
local function save_rule(rule, overwrite, stamp)
  local exp, ttl = rule:expired(stamp)
  if exp then
    return nil, "expired"
  end

  local ok, err
  if overwrite then
    ok, err = HASH:safe_set(rule.id, rule.hash, ttl)
  else
    ok, err = HASH:safe_add(rule.id, rule.hash, ttl)
  end

  if not ok then
    return nil, err
  end

  if overwrite then
    ok, err = SHM:safe_set(rule.hash, encode(rule), ttl)
  else
    ok, err = SHM:safe_add(rule.hash, encode(rule), ttl)
  end

  -- delete the lookup reference if we failed on creating a new rule
  if err and not overwrite then
    HASH:set(rule.id, nil)
  end

  return ok, err
end

---@param id string
---@return string?
local function get_hash_by_id(id)
  return HASH:get(id)
end

---@param hash_or_id string
---@param include_stats boolean
local function get(hash_or_id, include_stats)
  local hash

  if rules.is_id(hash_or_id) then
    hash = get_hash_by_id(hash_or_id)

  elseif rules.is_hash(hash_or_id) then
    hash = hash_or_id
  end

  if not hash then
    return
  end

  local rule = SHM:get(hash)
  if rule then
    return rules.hydrate(rule, include_stats)
  end
end


---@param rule doorbell.rule
---@param locked boolean
---@return boolean ok
---@return string? error
local function delete_rule(rule, locked)
  if type(rule) == "string" then
    return delete_rule(get(rule), locked)

  elseif type(rule) == "table" then
    rule = get(rule.hash)
  end

  if not rule then
    return nil, "not found"
  end

  local unlock = lock_storage("delete-rule", locked)

  -- don't really care if this fails
  stats.delete(rule)

  local ok, err = SHM:set(rule.hash, nil)
  if not ok then
    unlock()
    return nil, err
  end

  ok, err = HASH:set(rule.id, nil)
  inc_version()
  unlock()

  return ok, err
end


---@param include_stats boolean
---@return doorbell.rule[]
local function get_all_rules(include_stats)
  local list = {}
  local n = 0

  local keys = SHM:get_keys(0)
  for i = 1, #keys do
    local key = keys[i]
    local value = SHM:get(key)
    local rule = value and rules.hydrate(value, include_stats)
    if rule then
      n = n + 1
      list[n] = rule
    end
  end

  return list
end

local check_match

local function rebuild_matcher()
  local match = matcher.new(get_all_rules())
  cache:flush_all()
  check_match = match
end

--- flush any expired rules from shared memory
local function flush_expired(premature, schedule, locked)
  if premature or exiting() then
    return
  end

  local unlock = lock_storage("flush-expired", locked)

  SHM:flush_expired()
  stats.flush_expired()

  ---@type doorbell.rule[]
  local delete = {}
  local t = now()
  local min_ttl = const.periods.hour
  for _, rule in ipairs(get_all_rules()) do
    local expired, ttl = rule:expired(t)
    if expired then
      insert(delete, rule)
    else
      min_ttl = min(min_ttl, ttl)
    end
  end

  if #delete == 0 then
    log.debug("no expired rules to delete")
    unlock()
    return
  end

  local count = #delete

  for _, rule in ipairs(delete) do
    local ok, err = delete_rule(rule)
    if not ok then
      count = count - 1
      log.errf("failed deleting rule %s: %s", rule.hash, err)
    end
  end

  need_save(1)
  unlock()
  log.debugf("removed %s expired rules", count)

  if schedule then
    assert(timer_at(min_ttl, flush_expired, schedule))
  end
end


---@return number
local function get_version()
  return META:get("rules:version") or 0
end

local function reload()
  local version = get_version()
  local start = now()
  rebuild_matcher()
  VERSION = version
  local duration = now() - start
  duration = ceil(duration * 1000) / 1000
  log.debugf("reloaded match rules for version %s in %ss", version, duration)
end

--- save rules from shared memory to disk
---@param fname string
---@return integer? version
local function save(fname)
  local unlock = lock_storage("save")
  local version = get_version()
  local list = get_all_rules()

  local ok, written, err = util.update_json_file(fname, storage.serialize(list))
  if not ok then
    unlock()
    log.errf("failed saving rules to %s: %s", fname, err)
    return nil
  end

  if written then
    log.noticef("saved %s rules to disk", #rules)
  end

  last_saved(now())

  unlock()
  return version
end

local function saver(premature)
  if premature then
    return
  end

  local last = now()

  for _ = 1, 1000 do
    if exiting() then
      return
    end

    local c = need_save()
    if c > 0 then
      save(SAVE_PATH)
      need_save(-c)
      last = now()
    elseif (now() - last) > 60 then
      save(SAVE_PATH)
      last = now()
    else
      sleep(1)
    end
  end

  assert(timer_at(0, saver))
end


---@param  opts    table
---@param nobuild boolean
---@param overwrite boolean
---@return doorbell.rule? rule
---@return string? error
local function create(opts, nobuild, overwrite, locked)
  local rule, err = rules.new(opts)
  if not rule then
    return nil, err
  end

  local act = overwrite and "set-rule" or "add-rule"
  local unlock = lock_storage(act, locked)
  local saved
  saved, err = save_rule(rule, overwrite)
  if not saved then
    unlock()
    if err == "exists" then
      return nil, err
    end
    errorf("failed adding/updating rule: %s", err)
  end

  need_save(1)

  local inc
  inc, err = inc_version()
  if not inc then
    unlock()
    errorf("failed incrementing version: %s", err)
  end

  if not nobuild then reload() end
  unlock()
  return rule
end


---@param id_or_hash string
---@param include_stats boolean
---@return doorbell.rule?
function _M.get(id_or_hash, include_stats)
  if type(id_or_hash) ~= "string" then
    return nil, "input must be a string"
  end
  return get(id_or_hash, include_stats)
end

--- add a rule
---@param  opts    table
---@return doorbell.rule? rule
---@return string? error
function _M.add(opts, nobuild, locked)
  return create(opts, nobuild, false, locked)
end

--- create or update a rule
---@param  opts    table
---@return doorbell.rule? rule
---@return string? error
function _M.upsert(opts, nobuild, locked)
  return create(opts, nobuild, true, locked)
end

--- get a matching rule for a request
---@param  req            doorbell.request
---@return doorbell.rule? rule
---@return boolean        cache_hit
function _M.match(req)
  local version = get_version()
  if not check_match or version ~= VERSION then
    reload()
  end

  local cached = true
  local key = cache_key(req)

  ---@type doorbell.rule
  local rule = cache:get("req", key)

  if not rule then
    cached = false
    rule = check_match(req)
  end

  if rule then
    local time = now()
    if rule:expired(time) then
      return
    end

    if not cached then
      cache:set("req", key, rule, rule:ttl(time))
    end
  end

  return rule, cached
end

_M.delete = delete_rule

--- retrieve a list of all current rules
---@param include_stats boolean
---@return doorbell.rule[]
function _M.list(include_stats)
  return get_all_rules(include_stats)
end

function _M.reset()
  SHM:flush_all()
  assert(SHM:flush_expired(0))
  return reload()
end

--- reload the rule matching function from shared memory
function _M.reload()
  SHM:flush_expired(0)
  return reload()
end


function _M.init_agent()
  assert(timer_at(0, flush_expired, true))
  assert(timer_at(0, saver))
  stats.init_agent()
end

---@param timeout? number
---@return boolean ok
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
---@param fname string
---@return boolean ok
---@return string? error
function _M.load(fname, set_stats)
  -- no lock: this should only run during init
  local data, err = util.read_json_file(fname)
  if not data then
    return nil, err
  end

  data = storage.migrate(data)

  ---@type doorbell.rule[]
  local list = {}
  for i, rule in ipairs(data.rules) do
    list[i] = rules.hydrate(rule)
    list[i].id = list[i].id or uuid()
  end

  if set_stats then
    stats.load(list)
  end

  local count = 0

  local ok
  ok, err = SHM:flush_expired()
  if not ok then
    log.alert("failed calling shm:flush_expired(), zombie rules may exist: ", err)
  end

  local time = now()

  for _, rule in ipairs(list) do
    -- Rules that are created from the doorbell config are only saved to disk
    -- so that we can persist their stats (last match timestamp, match count, etc)
    -- to disk.
    --
    -- We don't restore their contents because that could mean creating an
    -- orphaned rule (if it no longer exists in the config).
    local restore = not (rule:expired(time) or rule.source == const.sources.config)
    if restore then
      count = count + 1
      ok, err = save_rule(rule, nil, time)
      if not ok then
        log.alertf("failed restoring rule %s to shm: %s", rule.hash, err)
      end
    end
  end
  inc_version()

  log.noticef("restored %s rules from disk", count)

  return true
end

--- get the current data store version
---@return integer
function _M.version()
  return get_version()
end

function _M.init_worker()
  if metrics.enabled() then
    rules_total = metrics.prometheus:gauge(
      "rules_total",
      "number of rules",
      { "action", "source" }
    )

    rule_actions = metrics.prometheus:counter(
      "rule_actions",
      "actions taken by rules",
      { "action" }
    )


    if ngx.worker.id() ~= 0 then
      return
    end

    metrics.add_hook(function()
      -- rule counts
      do
        local counts = {
          allow = {
            config = 0,
            user   = 0,
          },
          deny = {
            config = 0,
            user =  0,
          }
        }

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
---@param start_time number
function _M.log(ctx, start_time)
  ---@type doorbell.rule
  local rule = ctx.rule
  if not rule then
    return
  end

  local time = now()
  stats.inc_match_count(rule, 1, time)
  stats.set_last_match(rule, start_time, time)
  rule_actions:inc(1, { rule.action })
end

---@param conf doorbell.config
function _M.init(conf)
  SAVE_PATH = conf.save_path
  stats.init(conf)

  local ok, err = _M.load(SAVE_PATH, true)
  if not ok then
    log.alert("failed loading rules from disk: ", err)
  end

  for _, rule in ipairs(conf.allow or {}) do
    rule.action = "allow"
    rule.source = "config"
    assert(_M.upsert(rule, true))
  end

  for _, rule in ipairs(conf.deny or {}) do
    rule.action = "deny"
    rule.source = "config"
    assert(_M.upsert(rule, true))
  end
end

return _M
