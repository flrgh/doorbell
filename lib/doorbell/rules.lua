local _M = {}

local cjson = require "cjson"
local ipmatcher  = require "resty.ipmatcher"
local resty_lock = require "resty.lock"
local const = require "doorbell.constants"
local log = require "doorbell.log"
local metrics = require "doorbell.metrics"


local ngx     = ngx
local re_find = ngx.re.find
local now     = ngx.now

local assert  = assert
local encode = cjson.encode
local decode = cjson.decode
local max    = math.max
local ceil   = math.ceil
local fmt    = string.format
local insert = table.insert
local sort   = table.sort
local concat = table.concat
local pairs  = pairs
local ipairs = ipairs
local type   = type
local tostring = tostring

local SHM_NAME = const.shm.rules
local SHM = assert(ngx.shared[SHM_NAME], "rules SHM missing")
local META_NAME = const.shm.doorbell
local META = assert(ngx.shared[META_NAME], "main SHM missing")

local cache
do
  local lru = require "resty.lrucache"
  cache = assert(lru.new(1000))
end

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


local function show(t)
  log.notice(require("inspect")(t))
end

local function errorf(...)
  error(fmt(...))
end

---@nodiscard
local function lock_storage(action)
  local lock, err = resty_lock:new(META_NAME)
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

--- generate a cache key for a request object
---@param  req doorbell.request
---@return string
local function cache_key(req)
  return fmt(
    "req||%s||%s||%s||%s||%s",
    req.addr,
    req.method,
    req.host,
    req.path,
    req.ua
  )
end

---@param term string
---@param req doorbell.request
local function term_key(term, req)
  local val = req[term]
  if not val then return end
  return "term||" .. tostring(req[term])
end

local DENY  = const.actions.deny
local VERSION = 0

---@return doorbell.rule[]
local function get_all_rules()
  local rules = {}
  local n = 0

  local keys = SHM:get_keys(0)
  for i = 1, #keys do
    local key = keys[i]
    local value = SHM:get(key)
    if value then
      n = n + 1
      rules[n] = decode(value)
    end
  end

  return rules
end

---@param s string
---@return boolean
local function is_regex(s)
  return s:sub(1, 1) == "~"
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

local CRITERIA = {
  addr       = "addr",
  cidr       = "cidr",
  path_plain = "path(plain)",
  path_regex = "path(regex)",
  host       = "host",
  ua_plain   = "ua(plain)",
  ua_regex   = "ua(regex)",
  method     = "method",
}

---@param rule doorbell.rule
---@param t? number
---@return boolean
local function expired(rule, t)
  local exp = rule.expires
  if exp == 0 or not exp then return false end
  t = t or now()
  return exp <= t
end

local check_match

---@type string[]
local cache_terms = {}
local cache_terms_n = 0

local function rebuild_matcher()
  local criteria = {}

  local max_conditions = 0

  local term_fields = {}


  do
    local rules = get_all_rules()

    local time = now()

    ---@param rule doorbell.rule
    ---@param match doorbell.rule.criteria
    ---@param value string
    local function add_criteria(rule, match, value)
      if expired(rule, time) then
        log.warn("skipping expired rule: ", rule.hash)
        return
      end

      max_conditions = max(max_conditions, rule.conditions)

      criteria[match] = criteria[match] or {}
      criteria[match][value] = criteria[match][value] or { n = 0 }

      insert(criteria[match][value], rule)
      criteria[match][value].n = criteria[match][value].n + 1
    end

    for i = 1, #rules do
      ---@type doorbell.rule
      local r = rules[i]

      if r.terminate and r.key then
        term_fields[r.key] = true
      end

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
      local matched = item[2]
      if re_find(value, re, "oj") then
        return matched
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

          -- if our rule has met more conditions than any other, so can clear out
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

  ---@param a doorbell.rule
  ---@param b doorbell.rule
  ---@return boolean
  local function cmp_rule(a, b)
    -- termintation rules have the highest priority
    if a.terminate ~= b.terminate then
      return a.terminate == true
    end

    -- deny actions have priority over allow
    if a.action ~= b.action then
      return a.action == DENY
    end

    -- this probably shouldn't happen
    if a.conditions ~= b.conditions then
      return a.conditions > b.conditions
    end

    -- else, the newest rule wins
    return a.created > b.created
  end

  cache:flush_all()

  do
    local terms = {}
    local n = 0
    for field in pairs(term_fields) do
      n = n + 1
      terms[n] = field
    end
    cache_terms = terms
    cache_terms_n = n
  end

  ---@param req doorbell.request
  ---@return doorbell.rule?
  check_match = function(req)
    local addr   = assert(req.addr, "missing request addr")
    local path   = assert(req.path, "missing request path")
    local host   = assert(req.host, "missing request host")
    local method = assert(req.method, "missing request method")
    local ua     = req.ua or ""

    ---@type doorbell.rule[]
    local match = new_match()

    update_match(match, addrs[addr])
    update_match(match, paths_plain[path])
    update_match(match, methods[method])
    update_match(match, hosts[host])
    update_match(match, uas_plain[ua])

    if not match.terminate then
      -- plain/exact matches trump regex or cidr lookups
      --
      -- loop through each match whose conditions are met and check to see if
      -- we've matched the path, ua, or addr already
      --
      -- first, see if we have a match with the maximal number of conditions met
      if match.conditions < max_conditions then
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
end

---@class doorbell.rule : table
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
---@field conditions number
---@field terminate  boolean
---@field key        string

local CONDITIONS = {
  "addr",
  "cidr",
  "ua",
  "host",
  "path",
  "method",
}

local hash_rule
do
  local buf = {}
  local md5 = ngx.md5

  ---@param rule doorbell.rule
  ---@return string
  function hash_rule(rule)
    buf[1] = rule.action
    buf[2] = rule.addr   or ""
    buf[3] = rule.cidr   or ""
    buf[4] = rule.method or ""
    buf[5] = rule.host   or ""
    buf[6] = rule.path   or ""
    buf[7] = rule.ua     or ""
    local s = concat(buf, "||")
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

      if ok and lookup then
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
    local ttl = opts.ttl

    if opts.ttl then
      if opts.expires then
        err("only one of `ttl` and `expires` allowed")
      elseif opts.ttl < 0 then
        err("`ttl` must be > 0")
      elseif opts.ttl > 0 then
        expires = now() + opts.ttl
      end
    elseif expires > 0 then
      ttl = expires - now()
      if ttl <= 0 then
        err("rule is already expired")
      end
    end

    if opts.expires and opts.expires < 0 then
      err("`expires` must be >= 0")
    end

    if #errors == 0 and not (opts.addr or opts.cidr or opts.ua or opts.method or opts.host or opts.path) then
      err("at least one of `addr`|`cidr`|`ua`|`method`|`host`|`path` required")
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

    local rule = {
      action  = opts.action,
      source  = opts.source,
      created = opts.created or now(),
      expires = expires,
      addr    = opts.addr,
      cidr    = opts.cidr,
      ua      = opts.ua,
      host    = opts.host,
      path    = opts.path,
      method  = opts.method,
      hash    = "",
      conditions = conditions,
      terminate = opts.terminate,
      key = key,
    }
    rule.hash = hash_rule(rule)

    return rule, nil, ttl
  end
end

---@return number
local function get_version()
  return META:get("rules:version") or 0
end

local function inc_version()
  assert(META:incr("rules:version", 1, 0))
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
  local rule, err, ttl = new_rule(opts)
  if not rule then
    return nil, err
  end
  local unlock = lock_storage("add-rule")
  assert(SHM:safe_set(rule.hash, encode(rule), ttl))
  inc_version()
  if not nobuild then reload() end
  unlock()
  return rule
end

--- create or update a rule
---@param  opts    table
---@return doorbell.rule? rule
---@return string? error
function _M.upsert(opts, nobuild)
  local rule, err, ttl = new_rule(opts)
  if not rule then
    return nil, err
  end

  local unlock = lock_storage("update-rule")
  assert(SHM:safe_set(rule.hash, encode(rule), ttl))
  inc_version()
  if not nobuild then reload() end
  unlock()
  return rule
end

--- get a matching rule for a request
---@param  req            doorbell.request
---@return doorbell.rule? rule
---@return string?        error
function _M.match(req)
  local version = get_version()
  if not check_match or version ~= VERSION then
    reload()
  end

  local cached = true
  local key
  ---@type doorbell.rule
  local rule
  if cache_terms_n > 0 then
    for i = 1, cache_terms_n do
      local tk = term_key(cache_terms[i], req)
      rule = cache:get(tk)
      if rule then
        key = tk
        break
      end
    end
  end

  if not rule then
    key = cache_key(req)
    rule = cache:get(key)
  end

  if not rule then
    cached = false
    rule = check_match(req)
  end

  if rule then
    log.debugf(
      "cache %s for %q => %s",
      (cached and "HIT" or "MISS"),
      key,
      rule.action
    )
    local ttl
    if rule.expires and rule.expires > 0 then
      ttl = rule.expires - now()
    end

    if ttl and ttl < 0 then
      return
    end

    if not cached then
      if rule.terminate then
        cache:set(term_key(rule.key, req), rule, ttl)
      else
        cache:set(key, rule, ttl)
      end
    end
  end

  return rule, cached
end

--- retrieve a list of all current rules
function _M.list()
  return get_all_rules()
end

--- save rules from shared memory to disk
---@param fname string
---@return integer? version
function _M.save(fname)
  local unlock = lock_storage("save")
  local version = get_version()
  local rules = get_all_rules()
  local fh, err = io.open(fname, "w+")
  if not fh then
    unlock()
    log.errf("failed opening save path (%s) for writing: %s", fname, err)
    return version
  end

  local ok
  ok, err = fh:write(encode(rules))
  if not ok then
    log.err("failed writing rules to disk: ", err)
  end
  ok, err = fh:close()
  if not ok then
    log.err("failed closing file handle: ", err)
  end
  log.noticef("saved %s rules to disk", #rules)

  unlock()
  return version
end

--- reload the rule matching function from shared memory
function _M.reload()
  SHM:flush_expired()
  return reload()
end

--- flush any expired rules from shared memory
function _M.flush_expired()
  local unlock = lock_storage("flush-expired")

  SHM:flush_expired()

  ---@type doorbell.rule[]
  local delete = {}
  local t = now()
  for _, rule in ipairs(get_all_rules()) do
    if expired(rule, t) then
      insert(delete, rule)
    end
  end

  if #delete == 0 then
    log.debug("no expired rules to delete")
    unlock()
    return
  end

  local count = #delete

  for _, rule in ipairs(delete) do
    local ok, err = SHM:delete(rule.hash)
    if not ok then
      count = count - 1
      log.errf("failed deleting rule %s: %s", rule.hash, err)
    end
  end

  inc_version()
  unlock()
  log.debugf("removed %s expired rules", count)
end

--- reload rules from disk
---@param fname string
---@return boolean ok
---@return string? error
function _M.load(fname)
  -- no lock: this should only run during init
  local fh, err = io.open(fname, "r")
  if not fh then
    return nil, err
  end

  local data
  data, err = fh:read("*a")
  fh:close()
  if not data then
    return nil, err
  end

  local rules = decode(data)
  local count = 0

  local ok
  ok, err = SHM:flush_all()
  if not ok then
    log.alert("failed calling shm:flush_all(), zombie rules may exist: ", err)
  end
  ok, err = SHM:flush_expired()
  if not ok then
    log.alert("failed calling shm:flush_expired(), zombie rules may exist: ", err)
  end

  local time = now()

  for _, rule in ipairs(rules) do
    local ttl = 0
    if rule.expires > 0 then
      ttl = rule.expires - time
      if ttl <= 0.1 then
        ttl = -1
      end
    end
    if ttl >= 0 then
      count = count + 1
      ok, err = SHM:safe_set(rule.hash, encode(rule), ttl)
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

    -- cache size

  end)
end

return _M
