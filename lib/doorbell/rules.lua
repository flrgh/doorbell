local _M = {
  _VERSION = require("doorbell.constants").version,
}

local const = require "doorbell.constants"
local util  = require "doorbell.util"
local schema = require "doorbell.schema"

local cjson = require "cjson"

local uuid         = require("resty.jit-uuid").generate_v4
local concat       = table.concat
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
  "asn",
  "org",
}

_M.CONDITIONS = CONDITIONS

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
    buf[1] = rule.addr    or ""
    buf[2] = rule.cidr    or ""
    buf[3] = rule.method  or ""
    buf[4] = rule.host    or ""
    buf[5] = rule.path    or ""
    buf[6] = rule.ua      or ""
    buf[7] = rule.country or ""
    buf[8] = rule.asn     or ""
    buf[9] = rule.org     or ""
    local s = concat(buf, "||", 1, 9)
    return md5(s)
  end
end

---@param rule doorbell.rule.new.opts|doorbell.rule
---@return integer
local function count_conditions(rule)
  local c = 0
  for _, cond in ipairs(CONDITIONS) do
    if rule[cond] ~= nil then
      c = c + 1
    end
  end

  return c
end

_M.count_conditions = count_conditions

local SERIALIZED_FIELDS = {
  "action",
  "addr",
  "asn",
  "cidr",
  "comment",
  "country",
  "created",
  "deny_action",
  "expires",
  "host",
  "id",
  "method",
  "org",
  "path",
  "source",
  "terminate",
  "ua",
}

_M.SERIALIZED_FIELDS = SERIALIZED_FIELDS

--- IP Address to match
---@alias doorbell.rule.fields.addr string

--- Subnet/IP to match (CIDR notation)
---@alias doorbell.rule.fields.cidr string

--- Two-letter country code
---@alias doorbell.rule.fields.country string

--- HTTP Host request header
---@alias doorbell.rule.fields.host string

--- HTTP request method
---@alias doorbell.rule.fields.method string

--- HTTP request path
---@alias doorbell.rule.fields.path string

--- HTTP User-Agent request header
---@alias doorbell.rule.fields.ua string

--- Network ASN
---@alias doorbell.rule.fields.asn integer

--- Network Organization
---@alias doorbell.rule.fields.org string


---@class doorbell.rule.dehydrated: table
---
---@field addr        doorbell.rule.fields.addr
---@field asn         doorbell.rule.fields.asn
---@field cidr        doorbell.rule.fields.cidr
---@field country     doorbell.rule.fields.country
---@field host        doorbell.rule.fields.host
---@field method      doorbell.rule.fields.method
---@field org         doorbell.rule.fields.org
---@field path        doorbell.rule.fields.path
---@field ua          doorbell.rule.fields.ua
---
---@field action      doorbell.action
---@field terminate   boolean
---@field deny_action doorbell.deny_action
---
---@field expires     number
---
---@field id      string
---@field comment string
---@field source  doorbell.source
---@field created number


---@class doorbell.rule.shorthand_fields : table
---
---@field ttl integer


---@class doorbell.rule.new.opts : doorbell.rule.dehydrated : doorbell.rule.shorthand_fields


---@class doorbell.rule.update.opts : doorbell.rule.shorthand_fields
---
---@field action      doorbell.action
---@field addr        string
---@field asn         doorbell.rule.fields.asn
---@field cidr        string
---@field comment     string
---@field country     string
---@field deny_action doorbell.deny_action
---@field expires     number
---@field host        string
---@field method      string
---@field path        string
---@field terminate   boolean
---@field org         doorbell.rule.fields.org
---@field ua          string


local rule_mt
do
  ---@class doorbell.rule : doorbell.rule.dehydrated
  ---
  ---@field conditions integer # number of match conditions this rule has
  ---
  ---@field hash string        # hash of the rule match conditions
  ---
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

  function rule:update_generated_fields()
    self:update_hash()
    self.conditions = count_conditions(self)
  end

  rule_mt = {
    __index = rule,
    __tostring = function(self)
      return "rule(" .. self.hash .. ")"
    end
  }
end


---@param  json          string|table|doorbell.rule|doorbell.rule.dehydrated
---@return doorbell.rule rule
local function hydrate(json)
  if type(json) == "string" then
    json = decode(json)
  end

  assert(type(json) == "table")

  ---@type doorbell.rule
  local rule = {}

  for _, field in ipairs(SERIALIZED_FIELDS) do
    rule[field] = json[field]
  end

  setmetatable(rule, rule_mt)

  rule:update_generated_fields()

  return rule
end

_M.hydrate = hydrate

---@param  rule doorbell.rule
---@return doorbell.rule.dehydrated
local function dehydrate(rule)
  local t = {}

  for _, field in ipairs(SERIALIZED_FIELDS) do
    t[field] = rule[field]
  end

  return t
end

_M.dehydrate = dehydrate


---@param opts doorbell.rule.new.opts
local function populate(opts)
  if not opts.id then
    opts.id = uuid()
  end

  if opts.action == const.actions.deny and not opts.deny_action then
    opts.deny_action = const.deny_actions.exit
  end

  update_time()
  local t = now()

  if opts.ttl then
    opts.expires = t + opts.ttl
    opts.ttl = nil
  end

  if not opts.expires then
    opts.expires = 0
  end

  if not opts.created then
    opts.created = t
  end
end

_M.populate = populate

---@param  opts           doorbell.rule.new.opts
---@return doorbell.rule? rule
---@return string?        error
function _M.new(opts)
  opts = deep_copy(opts)
  local valid, err = schema.rule.create.validate(opts)

  if not valid then
    return nil, err
  end

  populate(opts)

  ---@type doorbell.rule
  local rule = {
    id          = opts.id,
    action      = opts.action,
    addr        = opts.addr,
    asn         = opts.asn,
    cidr        = opts.cidr,
    created     = opts.created,
    deny_action = opts.deny_action,
    expires     = opts.expires,
    host        = opts.host,
    method      = opts.method,
    path        = opts.path,
    source      = opts.source,
    terminate   = opts.terminate,
    ua          = opts.ua,
    org         = opts.org,
    comment     = opts.comment,
    country     = opts.country,
  }

  setmetatable(rule, rule_mt)
  rule:update_generated_fields()

  return rule
end

---@param rule doorbell.rule
---@return boolean? ok
---@return string? error
function _M.validate_entity(rule)
  return schema.rule.entity.validate(rule)
end

---@param opts doorbell.rule.new.opts
---@return boolean? ok
---@return string? error
function _M.validate_create(opts)
  return schema.rule.create.validate(opts)
end

---@param opts doorbell.rule.update.opts
---@return boolean? ok
---@return string? error
function _M.validate_update(opts)
  return schema.rule.patch.validate(opts)
end


_M.validate = _M.validate_entity

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

---@param t table|doorbell.rule
---@return boolean
function _M.is_rule(t)
  return type(t) == "table" and getmetatable(t) == rule_mt
end


return _M
