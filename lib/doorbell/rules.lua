local _M = {
  _VERSION = require("doorbell.constants").version,
}

local const = require "doorbell.constants"
local stats = require "doorbell.rules.stats"
local ip    = require "doorbell.ip"
local util  = require "doorbell.util"

local cjson = require "cjson"

local uuid         = require("resty.jit-uuid").generate_v4
local valid_uuid   = require("resty.jit-uuid").is_valid
local concat       = table.concat
local insert       = table.insert
local sort         = table.sort
local fmt          = string.format
local decode       = cjson.decode
local setmetatable = setmetatable
local now          = ngx.now
local update_time  = ngx.update_time
local byte         = string.byte
local deep_copy    = util.deep_copy

local CONDITIONS = {
  "addr",
  "cidr",
  "ua",
  "host",
  "path",
  "method",
  "country",
}

local DENY  = const.actions.deny

local TILDE = byte("~")

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

---@param a doorbell.rule
---@param b doorbell.rule
---@return boolean
local function compare(a, b)
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

_M.compare = compare

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
  function rule:remaining_ttl(at)
    return ttl_from_expires(self.expires, at)
  end

  ---@param other doorbell.rule
  ---@return boolean
  function rule:is_same(other)
    return self.hash == other.hash
  end

  function rule:update_hash()
    self.hash = hash_rule(self)
  end

  rule_mt = {
    __index = rule,
    __tostring = function(self)
      return "rule(" .. self.hash .. ")"
    end
  }
end


---@param json string|table|doorbell.rule
---@param pull_stats? boolean
---@return doorbell.rule
local function hydrate(json, pull_stats)
  ---@type doorbell.rule
  local rule = json
  if type(json) == "string" then
    rule = decode(json)
  end

  assert(type(rule) == "table")

  setmetatable(rule, rule_mt)

  if pull_stats then
    stats.update_from_shm(rule)
  end

  return rule
end

_M.hydrate = hydrate

---@param rule doorbell.rule
---@return doorbell.rule
local function dehydrate(rule)
  rule.last_match = nil
  rule.match_count = nil
  return rule
end

_M.dehydrate = dehydrate


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
  id        = {"string"},
}

---@param opts table
local function validate(opts)
  local errors = {}

  for name, spec in pairs(fields) do
    local typ = spec[1]
    local req = spec[2]
    local lookup = spec[3]

    local value = opts[name]

    local ok = true

    if req and value == nil then
      insert(errors, e_required(name))
      ok = false
    end

    if ok and value ~= nil and not is_type(typ, value) then
      insert(errors, e_type(name, typ, type(value)))
      ok = false
    end

    if ok and req and typ == "string" and value == "" then
      insert(errors, e_empty(name))
      ok = false
    end

    if ok and value ~= nil and lookup then
      if not lookup[value] then
        insert(errors, e_enum(name, tkeys(lookup), value))
      end
    end
  end

  update_time()
  local time = now()

  if opts.ttl then
    if opts.expires then
      insert(errors, "only one of `ttl` and `expires` allowed")
    elseif opts.ttl < 0 then
      insert(errors, "`ttl` must be > 0")
    elseif opts.ttl > 0 then
      opts.expires = time + opts.ttl
      opts.ttl = nil
    end
  elseif (opts.expires or 0) > 0 then
    if ttl_from_expires(opts.expires, time) <= 0 then
      insert(errors, "rule is already expired")
    end

  elseif not opts.expires then
    opts.expires = 0
  end

  if opts.expires and opts.expires < 0 then
    insert(errors, "`expires` must be >= 0")
  end

  if not (opts.addr or opts.cidr or opts.ua or opts.method or opts.host or opts.path or opts.country) then
    insert(errors, "at least one of `addr`|`cidr`|`ua`|`method`|`host`|`path`|`country` required")
  end

  if opts.action == const.actions.allow and opts.deny_action then
    insert(errors, "`deny_action` cannot be used when `action` is '" .. const.actions.allow .. "'")
  end

  if opts.country and type(opts.country) == "string" then
    if not ip.get_country_name(opts.country) then
      insert(errors, "`country` must be a valid, two letter country code")
    end
  end

  local conditions = 0
  for _, cond in ipairs(CONDITIONS) do
    if opts[cond] then
      conditions = conditions + 1
    end
  end
  opts.conditions = conditions

  if opts.terminate and conditions > 1 then
    insert(errors, "can only have one match condition with `terminate`")
  end

  if opts.id and not valid_uuid(opts.id) then
    insert(errors, "`id` must be a valid uuid")
  end


  return errors
end

---@param  opts    doorbell.rule
---@return doorbell.rule? rule
---@return string? error
function _M.new(opts)
  opts = deep_copy(opts)
  local errors = validate(opts)

  if #errors > 0 then
    return nil, concat(errors, "\n")
  end

  local deny_action
  if opts.action == const.actions.deny then
    deny_action = opts.deny_action or "exit"
  end

  ---@type doorbell.rule
  local rule = {
    id          = opts.id or uuid(),
    action      = opts.action,
    addr        = opts.addr,
    cidr        = opts.cidr,
    conditions  = opts.conditions,
    created     = opts.created or now(),
    deny_action = deny_action,
    expires     = opts.expires,
    hash        = hash_rule(opts),
    host        = opts.host,
    method      = opts.method,
    path        = opts.path,
    source      = opts.source,
    terminate   = opts.terminate,
    ua          = opts.ua,
    comment     = opts.comment,
    country     = opts.country,
  }

  return hydrate(rule)
end


---@param  rule    doorbell.rule
---@return boolean? ok
---@return string? error
function _M.validate(rule)
  local errors = validate(rule)
  if #errors > 0 then
    return nil, concat(errors, "\n")
  end

  return true
end


---@param s string
---@return boolean
function _M.is_regex(s)
  return byte(s, 1) == TILDE
end

---@param val string
---@return string
function _M.regex(val)
  return val:sub(2)
end

---@param s string
---@return boolean
function _M.is_id(s)
  return type(s) == "string" and #s == 36
end

---@param s string
---@return boolean
function _M.is_hash(s)
  return type(s) == "string" and #s == 32
end

---@diagnostic disable-next-line
if _G._TEST then
  _M._ttl_from_expires = ttl_from_expires
end



return _M
