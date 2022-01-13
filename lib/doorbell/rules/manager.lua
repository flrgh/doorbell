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

local cjson      = require "cjson"
local ipmatcher  = require "resty.ipmatcher"
local resty_lock = require "resty.lock"
local uuid       = require("resty.jit-uuid").generate_v4

local ngx         = ngx
local re_find     = ngx.re.find
local now         = ngx.now
local update_time = ngx.update_time
local timer_at    = ngx.timer.at
local sleep       = ngx.sleep
local exiting     = ngx.worker.exiting

local assert       = assert
local encode       = cjson.encode
local max          = math.max
local min          = math.min
local ceil         = math.ceil
local fmt          = string.format
local insert       = table.insert
local sort         = table.sort
local pairs        = pairs
local ipairs       = ipairs
local type         = type


local SHM_NAME  = const.shm.rules
local SHM       = assert(ngx.shared[SHM_NAME], "rules SHM missing")
local META_NAME = const.shm.doorbell
local META      = assert(ngx.shared[META_NAME], "main SHM missing")
local SAVE_PATH
local HASH  = assert(ngx.shared[const.shm.rule_hash])


local cache = require("doorbell.cache").new("rules", 1000)

local new_match, release_match
do
  local tb = require "tablepool"
  local fetch = tb.fetch
  local release = tb.release
  local pool = "doorbell.rule.match"

  local size = 5
  local narr, nrec = size, size + 3

  function new_match()
    local m = fetch(pool, narr, nrec)
    m.conditions = 0
    m.n = 0
    m.terminate = false
    return m
  end

  function release_match(m)
    release(pool, m)
  end
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


local function errorf(...)
  error(fmt(...))
end

local LOCK_OPTS = {
  exptime = 30,
  timeout = 5,
}

---@nodiscard
local function lock_storage(action)
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
---@param inplace boolean
---@return boolean ok
---@return string? error
local function save_rule(rule, inplace, stamp)
  local exp, ttl = rule:expired(stamp)
  if exp then
    return nil, "expired"
  end

  local ok, err
  if inplace then
    ok, err = HASH:safe_set(rule.id, rule.hash, ttl)
  else
    ok, err = HASH:safe_add(rule.id, rule.hash, ttl)
  end

  if not ok then
    return nil, err
  end

  if inplace then
    ok, err = SHM:safe_set(rule.hash, encode(rule), ttl)
  else
    ok, err = SHM:safe_add(rule.hash, encode(rule), ttl)
  end

  -- delete the lookup reference if we failed on creating a new rule
  if err and not inplace then
    HASH:set(rule.id, nil)
  end

  return ok, err
end

---@param id string
---@return string?
local function get_hash_by_id(id)
  return HASH:get(id)
end

local function get(hash_or_id)
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
    return rules.hydrate(rule, true)
  end
end


---@param rule doorbell.rule
---@return boolean ok
---@return string? error
local function delete_rule(rule)
  if type(rule) == "string" then
    rule = get(rule)
    if not rule then
      return nil, "not found"
    end
  end

  -- don't really care if this fails
  stats.delete(rule)

  local ok, err = SHM:set(rule.hash, nil)
  if not ok then
    return nil, err
  end

  return HASH:set(rule.id, nil)
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
    if value then
      n = n + 1
      list[n] = rules.hydrate(value, include_stats)
    end
  end

  return list
end

local function inc_version()
  return META:incr("rules:version", 1, 0)
end

--- flush any expired rules from shared memory
local function flush_expired(premature, schedule, locked)
  if premature or exiting() then
    return
  end

  local unlock = locked or lock_storage("flush-expired")

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
    if not locked then unlock() end
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
  if not locked then unlock() end
  log.debugf("removed %s expired rules", count)

  if schedule then
    assert(timer_at(min_ttl, flush_expired, schedule))
  end
end


---@alias doorbell.rule.criteria
---| '"addr"'
---| '"cidr"'
---| '"path(plain)"'
---| '"path(regex)"'
---| '"host"'
---| '"ua(plain)"'
---| '"ua(regex)"'
---| '"method"'
---| '"country"'

local CRITERIA = {
  addr       = "addr",
  cidr       = "cidr",
  path_plain = "path(plain)",
  path_regex = "path(regex)",
  host       = "host",
  ua_plain   = "ua(plain)",
  ua_regex   = "ua(regex)",
  method     = "method",
  country    = "country",
}

local cmp_rule = rules.compare

local check_match

local function rebuild_matcher()
  local criteria = {}

  local max_possible_conditions = 0

  do
    flush_expired(false, false, true)

    local list = get_all_rules()

    update_time()
    local time = now()

    ---@param rule doorbell.rule
    ---@param match doorbell.rule.criteria
    ---@param value string
    local function add_criteria(rule, match, value)
      if rule:expired(time) then
        log.warn("skipping expired rule: ", rule.hash)
        return
      end

      max_possible_conditions = max(max_possible_conditions, rule.conditions)

      criteria[match] = criteria[match] or {}
      criteria[match][value] = criteria[match][value] or { n = 0 }

      insert(criteria[match][value], rule)
      criteria[match][value].n = criteria[match][value].n + 1
    end

    for i = 1, #list do
      ---@type doorbell.rule
      local r = rules[i]

      if r.addr then
        add_criteria(r, CRITERIA.addr, r.addr)
      end

      if r.method then
        add_criteria(r, CRITERIA.method, r.method)
      end

      if r.path then
        if rules.is_regex(r.path) then
          add_criteria(r, CRITERIA.path_regex, rules.regex(r.path))
        else
          add_criteria(r, CRITERIA.path_plain, r.path)
        end
      end

      if r.host then
        add_criteria(r, CRITERIA.host, r.host)
      end

      if r.cidr then
        add_criteria(r, CRITERIA.cidr, r.cidr)
      end

      if r.ua then
        if rules.is_regex(r.ua) then
          add_criteria(r, CRITERIA.ua_regex, rules.regex(r.ua))
        else
          add_criteria(r, CRITERIA.ua_plain, r.ua)
        end
      end

      if r.country then
        add_criteria(r, CRITERIA.country, r.country)
      end
    end
  end

  local empty = {}

  local paths_plain = criteria[CRITERIA.path_plain] or empty
  local paths_regex = { n = 0 }

  for re, rs in pairs(criteria[CRITERIA.path_regex] or {}) do
    insert(paths_regex, {re, rs})
    paths_regex.n = (paths_regex.n or 0) + 1
  end

  local hosts   = criteria[CRITERIA.host]  or empty
  local methods = criteria[CRITERIA.method] or empty
  local countries = criteria[CRITERIA.country] or empty


  local addrs = criteria[CRITERIA.addr]  or empty
  local cidrs = assert(ipmatcher.new_with_value(criteria[CRITERIA.cidr] or {}))


  local uas_plain = criteria[CRITERIA.ua_plain] or empty
  local uas_regex = { n = 0 }

  for re, rs in pairs(criteria[CRITERIA.ua_regex] or {}) do
    insert(uas_regex, {re, rs})
    uas_regex.n = (uas_regex.n or 0) + 1
  end


  ---@param t table
  ---@param value string
  local function regex_match(t, value)
    for i = 1, t.n do
      local item = t[i]
      local re = item[1]
      if re_find(value, re, "oj") then
        return item[2]
      end
    end
  end

  ---@param match doorbell.rule[]
  ---@param matched doorbell.rule[]
  local function update_match(match, matched)
    if match.terminate then return end
    if not matched then return end

    for i = 1, matched.n do
      if match.terminate then return end

      local rule = matched[i]
      local conditions = rule.conditions
      local terminate = rule.terminate

      if terminate or conditions >= match.conditions then
        local hash = rule.hash
        local count = (match[hash] or 0) + 1
        match[hash] = count

        -- if all of the match conditions for this rule have been met, add it to
        -- the array-like part of the match table
        if count == conditions then
          local n = match.n

          if terminate then
            match.terminate = true
          end

          -- if our rule has met more conditions than any other, we can clear out
          -- prior matches
          if terminate or count > match.conditions then
            match.conditions = count
            match[1] = rule
            for j = 2, n do
              match[j] = nil
            end
            match.n = 1

          -- otherwise, just append the rule to the match table
          elseif count == match.conditions then
            n = n + 1
            match[n] = rule
            match.n = n
          end
        end
      end
    end
  end

  cache:flush_all()

  ---@param req doorbell.request
  ---@return doorbell.rule?
  check_match = function(req)
    local addr   = assert(req.addr, "missing request addr")
    local path   = assert(req.path, "missing request path")
    local host   = assert(req.host, "missing request host")
    local method = assert(req.method, "missing request method")
    local ua     = req.ua or ""
    local country = req.country

    ---@type doorbell.rule[]
    local match = new_match()

    update_match(match, addrs[addr])
    update_match(match, paths_plain[path])
    update_match(match, methods[method])
    update_match(match, hosts[host])
    update_match(match, uas_plain[ua])

    if country then
      update_match(match, countries[country])
    end

    if not match.terminate then
      -- plain/exact matches trump regex or cidr lookups
      --
      -- loop through each match whose conditions are met and check to see if
      -- we've matched the path, ua, or addr already
      --
      -- first, see if we have a match with the maximal number of conditions met
      if match.conditions < max_possible_conditions then
        update_match(match, cidrs:match(addr))
        if not match.terminate then
          update_match(match, regex_match(paths_regex, path))
        end
        if not match.terminate then
          update_match(match, regex_match(uas_regex, ua))
        end
      end
    end

    if match.n > 1 then
      sort(match, cmp_rule)
    end

    local res = match[1]
    release_match(match)
    return res
  end

  return check_match
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
local function create(opts, nobuild, overwrite)
  local rule, err = rules.new(opts)
  if not rule then
    return nil, err
  end

  local act = overwrite and "set-rule" or "add-rule"
  local unlock = lock_storage(act)
  local ok, shm_err = save_rule(rule, overwrite)
  if not ok then
    unlock()
    if err == "exists" then
      return nil, err
    end
    errorf("failed adding/updating rule: %s", shm_err)
  end

  need_save(1)

  ok, err = inc_version()
  if not ok then
    unlock()
    errorf("failed incrementing version: %s", err)
  end

  if not nobuild then reload() end
  unlock()
  return rule
end


---@return doorbell.rule?
function _M.get(id_or_hash)
  if type(id_or_hash) ~= "string" then
    return nil, "input must be a string"
  end
  return get(id_or_hash)
end

--- add a rule
---@param  opts    table
---@return doorbell.rule? rule
---@return string? error
function _M.add(opts, nobuild)
  return create(opts, nobuild, false)
end

--- create or update a rule
---@param  opts    table
---@return doorbell.rule? rule
---@return string? error
function _M.upsert(opts, nobuild)
  return create(opts, nobuild, true)
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
---@return doorbell.rule[]
function _M.list()
  return get_all_rules(true)
end

function _M.reset()
  SHM:flush_all()
  assert(SHM:flush_expired(0))
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
          metrics.rules:set(num, {action, source})
        end
      end
    end
  end)
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
  metrics.actions:inc(1, { rule.action })
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

---@diagnostic disable-next-line
if _G._TEST then
  _M._rebuild_matcher = rebuild_matcher
end

return _M
