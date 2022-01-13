local _M = {
  _VERSION = require("doorbell.constants").version,
}

local const = require "doorbell.constants"
local log = require "doorbell.log"
local util = require "doorbell.util"

local ipairs   = ipairs
local type     = type
local now      = ngx.now
local timer_at = ngx.timer.at
local exiting  = ngx.worker.exiting
local sleep    = ngx.sleep

local SHM = assert(ngx.shared[const.shm.stats], "stats SHM missing")
local SAVE_PATH

local function need_save(x)
  if type(x) == "number" then
    return SHM:incr("need-save", x, 1, 0) or 0
  end
  return SHM:get("need-save") or 0
end

local function tpl(f)
  ---@param rule string|doorbell.rule
  return function(rule)
    local hash
    if type(rule) == "table" then
      hash = rule.hash
    else
      hash = rule
    end
    return f:format(hash)
  end
end

local match_count = tpl("%s:match_count")
local match_last  = tpl("%s:last_match")

---@return table<string, doorbell.rule.stat>
local function get_all()
  local stats = {}

  local keys, err = SHM:get_keys(0)
  if not keys then
    log.err("failed getting keys from stats shm: ", err)
    return stats
  end

  for _, key in ipairs(keys) do
    local hash, stat = key:match("([^:]+):(.+)")
    if hash and stat then
      local value = SHM:get(key)
      if value then
        stats[hash] = stats[hash] or {}
        stats[hash][stat] = value
      end
    end
  end

  return stats
end

---@class doorbell.rule.stat : table
---@field match_count number
---@field last_match number

local function get_or_set(key, value, ttl)
  if value then
    if ttl and ttl < 0 then
      return nil, "expired"
    end
    local ok, err = SHM:safe_set(key, value, ttl)
    if ok then
      need_save(1)
    end
    return ok, err
  end

  return SHM:get(key)
end

---@param rule doorbell.rule
---@param stamp? number
---@param ttl? number
---@return number?
---@return string? error
local function _last_matched(rule, stamp, ttl)
  local key = match_last(rule)
  return get_or_set(key, stamp, ttl)
end

---@param rule doorbell.rule
---@param count? number
---@param ttl? number
---@return number?
---@return string? error
local function _match_count(rule, count, ttl)
  local key = match_count(rule)
  return get_or_set(key, count, ttl)
end


---@param rule doorbell.rule
---@param value? number
---@param ts? number
function _M.inc_match_count(rule, value, ts)
  local expired, ttl = rule:expired(ts)
  if expired then
    return
  end

  local new, err = SHM:incr(match_count(rule), value or 1, 0, ttl)
  if new then
    need_save(1)
    rule.match_count = new
  else
    log.errf("failed incrementing match count for rule %s: %s", rule.hash, err)
  end
end

---@param rule doorbell.rule
---@param last_match number
---@param ts? number
function _M.set_last_match(rule, last_match, ts)
  local ok, err = _last_matched(rule, last_match, rule:ttl(ts))

  if ok then
    need_save(1)
  else
    log.errf("failed setting last match timestamp for rule %s: %s", rule.hash, err)
  end

  rule.last_match = last_match
end

---@param rule doorbell.rule
function _M.update_from_shm(rule)
  rule.last_match = _last_matched(rule) or rule.last_match
  rule.match_count = _match_count(rule) or rule.match_count or 0
end

---@param rule doorbell.rule
function _M.delete(rule)
  local ok, err = SHM:set(match_last(rule), nil)
  local bok, berr = SHM:set(match_count(rule), nil)

  return ok and bok, err or berr
end

function _M.flush_expired()
  SHM:flush_expired()
end

function _M.save()
  log.infof("saving stats data to %s", SAVE_PATH)
  local ok, err = util.write_json_file(SAVE_PATH, get_all())
  if not ok then
    log.err("failed writing stats to disk: ", err)
  end
end

---@param rules doorbell.rule[]
function _M.load(rules)
  ---@type table<string, doorbell.rule.stat>
  local stats, err = util.read_json_file(SAVE_PATH)

  if not stats then
    log.errf("failed loading stats from %s: %s", SAVE_PATH, err)
    return
  end

  local time = now()
  local empty = {}
  for _, rule in ipairs(rules) do
    local st = stats[rule.hash] or empty
    _last_matched(rule, st.last_match or rule.last_match or nil, rule:ttl(time))
    _match_count(rule, st.match_count or rule.match_count or nil, rule:ttl(time))
  end
end

---@param conf doorbell.config
function _M.init(conf)
  SAVE_PATH = (conf.save_path:gsub("[^/]+%.json$", "")) .. "stats.json"
end

local function saver(premature, interval)
  if premature or exiting() then
    log.notice("NGINX is exiting. One. Last. Save...")
    _M.save()
    return
  end

  for _ = 1, 1000 do
    if exiting() then
      return saver(true)
    end

    local count = need_save()
    if count > 0 then
      _M.save()
      need_save(-count)
    end

    sleep(interval)
  end

  assert(timer_at(interval, saver, interval))
end

function _M.init_agent()
  assert(timer_at(0, saver, 30))
end

return _M
