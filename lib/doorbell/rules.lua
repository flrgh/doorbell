local _M = {}

local cjson = require "cjson"
local ipmatcher  = require "resty.ipmatcher"
local resty_lock = require "resty.lock"
local const = require "doorbell.constants"


local assert  = assert
local ngx     = ngx
local re_find = ngx.re.find
local now     = ngx.now
local log     = ngx.log
local DEBUG   = ngx.DEBUG
local ERR     = ngx.ERR
local NOTICE  = ngx.NOTICE
local encode  = cjson.encode
local decode  = cjson.decode
local max     = math.max
local ceil    = math.ceil
local fmt     = string.format
local insert  = table.insert
local sort    = table.sort
local concat  = table.concat

local SHM_NAME = const.shm.rules
local SHM = assert(ngx.shared[SHM_NAME], "rules SHM missing")

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
  local narr, nrec = size, size + 2

  function new_match()
    local m = fetch(pool, narr, nrec)
    m.conditions = 0
    m.n = 0
    return m
  end

  function release_match(m)
    release(pool, m)
  end
end


local function show(t)
  ngx.log(ngx.NOTICE, require("inspect")(t))
end

local function errorf(...)
  error(fmt(...))
end

local function lock_storage(action)
  local lock, err = resty_lock:new(SHM_NAME)
  if not lock then
    errorf("failed creating storage lock (action = %s): %s", action, err or "unknown")
  end
  local elapsed
  elapsed, err = lock:lock("meta:lock")
  if not elapsed then
    errorf("failed locking storage (action = %s): %s", action, err)
  end

  return function()
    local unlocked, uerr = lock:unlock()
    if not unlocked then
      log(ERR, "failed unlocking storage (action = ", action, "): ", uerr)
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


local DENY  = const.actions.deny
local VERSION = 0

---@return doorbell.rule[]
local function get_all_rules()
  local rules = {}
  local n = 0

  local keys = SHM:get_keys(0)
  for i = 1, #keys do
    local key = keys[i]
    if not key:find("^meta:") then
      local value = SHM:get(key)
      if value then
        n = n + 1
        rules[n] = decode(value)
      end
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

local function rebuild_matcher()
  local criteria = {}

  local max_conditions = 0

  do
    local rules = get_all_rules()

    local time = now()

    ---@param rule doorbell.rule
    ---@param match doorbell.rule.criteria
    ---@param value string
    local function add_criteria(rule, match, value)
      if expired(rule, time) then
        log(DEBUG, "skipping expired rule: ", rule.hash)
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
    if not matched then return end

    for i = 1, matched.n do
      local rule = matched[i]
      local conditions = rule.conditions

      if conditions >= match.conditions then
        local hash = rule.hash
        local count = (match[hash] or 0) + 1
        match[hash] = count

        -- if all of the match conditions for this rule have been met, add it to
        -- the array-like part of the match table
        if count == conditions then
          local n = match.n

          -- if our rule has met more conditions than any other, so can clear out
          -- prior matches
          if count > match.conditions then
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
    -- deny actions have priority over allow
    if a.action ~= b.action then
      return a.action == DENY
    end

    -- else, the newest rule wins
    return a.created > b.created
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

    ---@type doorbell.rule[]
    local match = new_match()
    match.n = 0
    match.conditions = 0

    update_match(match, addrs[addr])
    update_match(match, paths_plain[path])
    update_match(match, methods[method])
    update_match(match, hosts[host])
    update_match(match, uas_plain[ua])

    -- plain/exact matches trump regex or cidr lookups
    --
    -- loop through each match whose conditions are met and check to see if
    -- we've matched the path, ua, or addr already
    --
    -- first, see if we have a match with the maximal number of conditions met
    if match.conditions < max_conditions then
      update_match(match, cidrs:match(addr))
      update_match(match, regex_match(paths_regex, path))
      update_match(match, regex_match(uas_regex, ua))
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
    action  = {"string", true, const.actions},
    source  = {"string", true, const.sources},
    expires = {"number"},
    ttl     = {"number"},
    addr    = {"string"},
    cidr    = {"string"},
    path    = {"string"},
    host    = {"string"},
    method  = {"string"},
    ua      = {"string"},
    created = {"number"},
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

      if ok and not is_type(typ, value) then
        err(e_type(name, typ, type(value)))
        ok = false
      end

      if ok and req and typ == "string" then
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

    if opts.ttl then
      if opts.expires then
        err("only one of `ttl` and `expires` allowed")
      elseif opts.ttl < 0 then
        err("`ttl` must be > 0")
      elseif opts.ttl > 0 then
        expires = now() + opts.ttl
      end
    end

    if opts.expires and opts.expires < 0 then
      err("`expires` must be >= 0")
    end

    if #errors == 0 and not (opts.addr or opts.cidr or opts.ua or opts.method or opts.host or opts.path) then
      err("at least one of `addr`|`cidr`|`ua`|`method`|`host`|`path` required")
    end

    if #err > 0 then
      return nil, concat(err, "\n")
    end

    local rule = {
      action  = opts.action,
      source  = opts.source,
      created = opts.created or now(),
      expires = expires or 0,
      addr    = opts.addr,
      cidr    = opts.cidr,
      ua      = opts.ua,
      host    = opts.host,
      path    = opts.path,
      method  = opts.method,
      hash    = "",
      conditions = 0,
    }
    rule.hash = hash_rule(rule)
    for _, cond in ipairs(CONDITIONS) do
      if rule[cond] then
        rule.conditions = rule.conditions + 1
      end
    end

    return rule
  end
end

---@return number
local function get_version()
  return SHM:get("meta:version") or 0
end

local function inc_version()
  assert(SHM:incr("meta:version", 1, 0))
end

local function reload()
  local version = get_version()
  local start = now()
  match = rebuild_matcher()
  VERSION = version
  local duration = now() - start
  duration = ceil(duration * 1000) / 1000
  log(DEBUG, "reloaded match rules for version ", version, " in ", duration, "s")
end

---@param  opts    table
---@return doorbell.rule? rule
---@return string? error
function _M.add(opts, nobuild)
  local rule, err = new_rule(opts)
  if not rule then
    return nil, err
  end
  local unlock = lock_storage("add-rule")
  assert(SHM:safe_set(rule.hash, encode(rule)))
  inc_version()
  if not nobuild then reload() end
  unlock()
  return rule
end

---@param  opts    table
---@return doorbell.rule? rule
---@return string? error
function _M.upsert(opts, nobuild)
  local rule, err = new_rule(opts)
  if not rule then
    return nil, err
  end

  local unlock = lock_storage("update-rule")
  assert(SHM:safe_set(rule.hash, encode(rule)))
  inc_version()
  if not nobuild then reload() end
  unlock()
  return rule
end

---@param  req            doorbell.request
---@return doorbell.rule? rule
---@return string?        error
function _M.match(req)
  local version = get_version()
  if not check_match or version ~= VERSION then
    reload()
  end

  local key = cache_key(req)
  local cached = true
  local m = cache:get(key)
  if not m then
    cached = false
    m = check_match(req)
  end

  if m then
    log(DEBUG, "cache ", (cached and "HIT" or "MISS"), " for ", req.addr, " => ", m.action)
    local ttl
    if m.expires and m.expires > 0 then
      ttl = m.expires - now()
    end

    if ttl and ttl < 0 then
      return
    end

    if not cached then
      cache:set(key, m, ttl)
    end
  end

  return m
end

function _M.list()
  return get_all_rules()
end

function _M.save(fname)
  local unlock = lock_storage("save")
  local version = get_version()
  local rules = get_all_rules()
  local fh, err = io.open(fname, "w+")
  if not fh then
    unlock()
    return nil, err
  end

  local ok
  ok, err = fh:write(encode(rules))
  if not ok then
    log(ERR, "failed writing rules to disk: ", err)
  end
  ok, err = fh:close()
  if not ok then
    log(ERR, "failed closing file handle: ", err)
  end
  log(NOTICE, "saved ", #rules, " rules to disk")

  unlock()
  return version
end

function _M.reload()
  return reload()
end

function _M.flush_expired()
  local unlock = lock_storage("flush-expired")
  ---@type doorbell.rule[]
  local delete = {}
  local t = now()
  for _, rule in ipairs(get_all_rules()) do
    if expired(rule, t) then
      insert(delete, rule)
    end
  end

  if #delete == 0 then
    log(DEBUG, "no expired rules to delete")
    unlock()
    return
  end

  local count = #delete

  for _, rule in ipairs(delete) do
    local ok, err = SHM:delete(rule.hash)
    if not ok then
      count = count - 1
      log(ERR, "failed deleting rule ", rule.hash, ": ", err)
    end
  end

  unlock()
  log(DEBUG, "removed ", count, " expired rules")
end


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
  for _, rule in ipairs(rules) do
    assert(SHM:safe_set(rule.hash, encode(rule)))
  end
  inc_version()

  log(NOTICE, "restored ", #rules, " rules from disk")

  return true
end

function _M.version()
  return get_version()
end

return _M
