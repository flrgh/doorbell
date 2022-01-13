local _M = {
  _VERSION = require("doorbell.constants").version,
}

local const   = require "doorbell.constants"
local log     = require "doorbell.log"
local metrics = require "doorbell.metrics"
local ip      = require "doorbell.ip"
local stats   = require "doorbell.rules.stats"
local util    = require "doorbell.util"

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

local assert       = assert
local encode       = cjson.encode
local decode       = cjson.decode
local max          = math.max
local min          = math.min
local ceil         = math.ceil
local fmt          = string.format
local insert       = table.insert
local sort         = table.sort
local concat       = table.concat
local pairs        = pairs
local ipairs       = ipairs
local type         = type
local setmetatable = setmetatable
local exiting      = ngx.worker.exiting

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


---@param exp number
---@return number ttl
local function ttl_from_expires(exp, t)
  if exp == 0 or not exp then
    return 0
  end

  t = t or now()

  local ttl = exp - t
  if ttl >= 0 and ttl < 1 then
    ttl = -1
  end

  return ttl
end


local rule_mt
do
  ---@class doorbell.rule : table
  ---@field id         string
  ---@field action     doorbell.action
  ---@field source     doorbell.source
  ---@field hash       string
  ---@field created    number
  ---@field expires    number
  ---@field addr       string
  ---@field cidr       string
  ---@field ua         string
  ---@field host       string
  ---@field path       string
  ---@field method     string
  ---@field country    string
  ---@field conditions number
  ---@field terminate  boolean
  ---@field key        string
  ---@field deny_action doorbell.deny_action
  ---@field match_count integer
  ---@field last_match number
  ---@field comment    string
  local rule = {}

  ---@param at? number
  ---@return boolean expired
  ---@return number  ttl
  function rule:expired(at)
    local ttl = ttl_from_expires(self.expires, at)
    return ttl < 0, ttl
  end

  ---@param at? number
  ---@return number
  function rule:ttl(at)
    return ttl_from_expires(self.expires, at)
  end

  rule_mt = {
    __index = rule,
    __tostring = function(self)
      return "rule(" .. self.hash .. ")"
    end
  }
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

local DENY  = const.actions.deny
local VERSION = 0

---@param json string
---@param pull_stats boolean
---@return doorbell.rule
local function hydrate_rule(json, pull_stats)
  ---@type doorbell.rule
  local rule = json
  if type(json) == "string" then
    rule = decode(json)
  end

  setmetatable(rule, rule_mt)

  if pull_stats then
    stats.update_from_shm(rule)
  end

  return rule
end

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

  return SHM:safe_set(rule.hash, encode(rule), ttl)
end

---@param id string
---@return doorbell.rule?
local function get_by_id(id)
  local hash = HASH:get(id)
  if not id then return end
  return SHM:get(hash)
end

local function get(hash_or_id)
  if #hash_or_id == 36 then
    return get_by_id(hash_or_id)
  end

  return SHM:get(hash_or_id)
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
  local rules = {}
  local n = 0

  local keys = SHM:get_keys(0)
  for i = 1, #keys do
    local key = keys[i]
    local value = SHM:get(key)
    if value then
      n = n + 1
      rules[n] = hydrate_rule(value, include_stats)
    end
  end

  return rules
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


---@param s string
---@return boolean
local function is_regex(s)
  return s:sub(1, 1) == "~"
end

---@param a doorbell.rule
---@param b doorbell.rule
---@return boolean
local function cmp_rule(a, b)
  -- termintation rules have the highest priority
  if a.terminate ~= b.terminate then
    return a.terminate == true
  end

  -- more conditions, mo better
  if a.conditions ~= b.conditions then
    return a.conditions > b.conditions
  end

  -- deny actions have priority over allow
  if a.action ~= b.action then
    return a.action == DENY
  end

  -- else, the newest rule wins
  return a.created > b.created
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

local check_match

local function rebuild_matcher()
  local criteria = {}

  local max_possible_conditions = 0

  do
    flush_expired(false, false, true)

    local rules = get_all_rules()

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

    for i = 1, #rules do
      ---@type doorbell.rule
      local r = rules[i]

      if r.addr then
        add_criteria(r, CRITERIA.addr, r.addr)
      end

      if r.method then
        add_criteria(r, CRITERIA.method, r.method)
      end

      if r.path then
        if is_regex(r.path) then
          add_criteria(r, CRITERIA.path_regex, r.path:sub(2))
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
        if is_regex(r.ua) then
          add_criteria(r, CRITERIA.ua_regex, r.ua:sub(2))
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

local CONDITIONS = {
  "addr",
  "cidr",
  "ua",
  "host",
  "path",
  "method",
  "country",
}

local hash_rule
do
  local buf = {}
  local md5 = ngx.md5

  ---@param rule doorbell.rule
  ---@return string
  function hash_rule(rule)
    buf[1] = rule.addr   or ""
    buf[2] = rule.cidr   or ""
    buf[3] = rule.method or ""
    buf[4] = rule.host   or ""
    buf[5] = rule.path   or ""
    buf[6] = rule.ua     or ""
    buf[7] = rule.country or ""
    local s = concat(buf, "||", 1, 7)
    return md5(s)
  end
end

local new_rule
do
  local function tpl(s)
    return function(...) return s:format(...) end
  end

  local e_required = tpl("`%s` is required and cannot be empty")
  local e_type     = tpl("invalid `%s` (expected %s, got: %s)")
  local e_empty    = tpl("`%s` cannot be empty")
  local e_enum     = tpl("invalid `%s` (expected: %s, got: %q)")

  local function is_type(t, v)
    return type(v) == t
  end
  local function tkeys(t)
    local keys = {}
    for k in pairs(t) do
      insert(keys, fmt("%q", k))
    end
    sort(keys)
    return concat(keys, "|")
  end

  local errors = {}
  local function err(v) insert(errors, v) end

  local fields = {
    action    = {"string", true, const.actions},
    source    = {"string", true, const.sources},
    expires   = {"number"},
    ttl       = {"number"},
    addr      = {"string"},
    cidr      = {"string"},
    path      = {"string"},
    host      = {"string"},
    method    = {"string"},
    ua        = {"string"},
    created   = {"number"},
    terminate = {"boolean"},
    country   = {"string"},
    deny_action = {"string", false, const.deny_actions},
    comment   = {"string"},
  }

  ---@param opts table
  local function validate(opts)
    errors = {}
    for name, spec in pairs(fields) do
      local typ = spec[1]
      local req = spec[2]
      local lookup = spec[3]

      local value = opts[name]

      local ok = true

      if req and value == nil then
        err(e_required(name))
        ok = false
      end

      if ok and value ~= nil and not is_type(typ, value) then
        err(e_type(name, typ, type(value)))
        ok = false
      end

      if ok and req and typ == "string" and value == "" then
        err(e_empty(name))
        ok = false
      end

      if ok and value ~= nil and lookup then
        if not lookup[value] then
          err(e_enum(name, tkeys(lookup), value))
        end
      end
    end
  end

  ---@param  opts    table
  ---@return doorbell.rule? rule
  ---@return string? error
  function new_rule(opts)
    validate(opts)

    local expires = opts.expires or 0

    update_time()
    local time = now()

    if opts.ttl then
      if opts.expires then
        err("only one of `ttl` and `expires` allowed")
      elseif opts.ttl < 0 then
        err("`ttl` must be > 0")
      elseif opts.ttl > 0 then
        expires = time + opts.ttl
      end
    elseif expires > 0 then
      if ttl_from_expires(expires, time) <= 0 then
        err("rule is already expired")
      end
    end

    if opts.expires and opts.expires < 0 then
      err("`expires` must be >= 0")
    end

    if not (opts.addr or opts.cidr or opts.ua or opts.method or opts.host or opts.path or opts.country) then
      err("at least one of `addr`|`cidr`|`ua`|`method`|`host`|`path`|`country` required")
    end

    if opts.action == const.actions.allow and opts.deny_action then
      err("`deny_action` cannot be used when `action` is '" .. const.actions.allow .. "'")
    end

    local conditions = 0
    local key
    for _, cond in ipairs(CONDITIONS) do
      if opts[cond] then
        conditions = conditions + 1
        if cond == "cidr" then
          key = "addr"
        else
          key = cond
        end
      end
    end

    if opts.terminate and conditions > 1 then
      err("can only have one match condition with `terminate`")
    end

    if #errors > 0 then
      return nil, concat(errors, "\n")
    end

    local deny_action
    if opts.action == const.actions.deny then
      deny_action = opts.deny_action or "exit"
    end

    ---@type doorbell.rule
    local rule = {
      id          = uuid(),
      action      = opts.action,
      addr        = opts.addr,
      cidr        = opts.cidr,
      conditions  = conditions,
      created     = opts.created or time,
      deny_action = deny_action,
      expires     = expires,
      hash        = "",
      host        = opts.host,
      key         = key,
      method      = opts.method,
      path        = opts.path,
      source      = opts.source,
      terminate   = opts.terminate,
      ua          = opts.ua,
      comment     = opts.comment,
    }
    rule.hash = hash_rule(rule)

    return hydrate_rule(rule)
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

--- add a rule
---@param  opts    table
---@return doorbell.rule? rule
---@return string? error
function _M.add(opts, nobuild)
  local rule, err = new_rule(opts)
  if not rule then
    return nil, err
  end
  local unlock = lock_storage("add-rule")
  local ok, shm_err = save_rule(rule, false)
  if not ok then
    unlock()
    if err == "exists" then
      return nil, err
    end
    errorf("failed adding rule: %s", shm_err)
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

  local len = #id_or_hash

  if len == 32 then
    return SHM:get(id_or_hash)
  elseif len == 36 then
    return get_by_id(id_or_hash)
  end

  return nil, "bad rule id or hash"
end

--- create or update a rule
---@param  opts    table
---@return doorbell.rule? rule
---@return string? error
function _M.upsert(opts, nobuild)
  local rule, err = new_rule(opts)
  if not rule then
    return nil, err
  end

  local unlock = lock_storage("update-rule")
  local ok, shm_err = save_rule(rule, true)
  if not ok then
    unlock()
    errorf("failed adding rule: %s", shm_err)
  end
  ok, err = inc_version()
  need_save(1)
  if not ok then
    unlock()
    errorf("failed incrementing version: %s", err)
  end

  if not nobuild then reload() end
  unlock()
  return rule
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

--- retrieve a list of all current rules
function _M.list()
  return get_all_rules(true)
end

--- save rules from shared memory to disk
---@param fname string
---@return integer? version
function _M.save(fname)
  local unlock = lock_storage("save")
  local version = get_version()
  local rules = get_all_rules(true)

  local ok, err = util.write_json_file(fname, rules)
  if not ok then
    unlock()
    log.errf("failed saving rules to %s: %s", fname, err)
    return nil
  end

  log.noticef("saved %s rules to disk", #rules)

  last_saved(now())

  unlock()
  return version
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
      _M.save(SAVE_PATH)
      need_save(-c)
      last = now()
    elseif (now() - last) > 60 then
      _M.save(SAVE_PATH)
      last = now()
    else
      sleep(1)
    end
  end

  assert(timer_at(0, saver))
end


function _M.init_agent()
  assert(timer_at(0, flush_expired, true))
  assert(timer_at(0, saver))
  stats.init_agent()
end

function _M.request_save()
  local before = last_saved()
  local time = now()

  local _, err = need_save(1)
  if err then
    return nil, err
  end

  local waited = 0
  while waited < 10 do
    local stamp = last_saved()
    if stamp >= before and stamp >= time then
      return true
    end
  end

  sleep(0.01)
  waited = waited + 0.01

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

  ---@type doorbell.rule[]
  local rules = {}
  for i, rule in ipairs(data) do
    rules[i] = hydrate_rule(rule)
    rules[i].id = rules[i].id or uuid()
  end

  if set_stats then
    stats.load(rules)
  end

  local count = 0

  local ok
  ok, err = SHM:flush_expired()
  if not ok then
    log.alert("failed calling shm:flush_expired(), zombie rules may exist: ", err)
  end

  local time = now()

  for _, rule in ipairs(rules) do
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
  _M._new_rule = new_rule
  _M._ttl_from_expires = ttl_from_expires
  _M._cmp_rule = cmp_rule
  _M._rebuild_matcher = rebuild_matcher
end

return _M
