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
local uuid       = require("resty.jit-uuid").generate_v4

local ngx         = ngx
local now         = ngx.now
local timer_at    = ngx.timer.at
local sleep       = ngx.sleep
local exiting     = ngx.worker.exiting
local get_phase   = ngx.get_phase

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


local function get_version()
  return META:get("rules:version") or 0
end

local function get_lock()
  return util.lock("rules", "trx", "new-transaction")
end

---@return doorbell.rule[]
local function get_all_rules()
  local list = {}
  local n = 0

  local keys = SHM:get_keys(0)
  for i = 1, #keys do
    local key = keys[i]
    local value = SHM:get(key)
    local rule = value and rules.hydrate(value)
    if rule then
      n = n + 1
      list[n] = rule
    end
  end

  return list
end


---@class doorbell.rules.transaction : table
---
---@field version integer
---
---@field rules doorbell.rule[]
---
---@field lock doorbell.lock
local trx = {}
trx.__index = trx

function trx:get(rule)
end



function _M.new()
  local lock, err = get_lock()
  if not lock then
    return nil, err
  end

  return setmetatable({
    lock = lock,
    version = get_version() + 1,
    rules = get_all_rules(),
  }, trx)
end


return _M
