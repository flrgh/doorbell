local _M = {}

local proc = require "ngx.process"

local ngx = ngx
local exiting = ngx.worker.exiting
local tostring = tostring
local max = math.max
local bit = require "bit"
local lshift = bit.lshift


local SHM = require("doorbell.shm").nginx
local log = require "doorbell.log"
local metrics = require "doorbell.metrics"

local PG_ID = 0

local WORKER_COUNT = 0

local HEARTBEAT_INTERVAL = 1
local UNHEALTHY_THRESHOLD = HEARTBEAT_INTERVAL * 0.5


---@type string
local HEARTBEAT_KEY

---@type string
local LATENCY_KEY

local B_NAMESPACE_BITS   = 2
local B_NAMESPACE_OFFSET = 0
local B_NAMESPACE_GLOBAL = lshift(0, B_NAMESPACE_OFFSET)
local B_NAMESPACE_GROUP  = lshift(1, B_NAMESPACE_OFFSET)
local B_NAMESPACE_PROC   = lshift(2, B_NAMESPACE_OFFSET)

-- 8 bits for key type
local B_KEY_BITS    = 8
local B_KEY_OFFSET  = B_NAMESPACE_OFFSET + B_NAMESPACE_BITS
local B_PID         = lshift(1, B_KEY_OFFSET)
local B_STARTED_AT  = lshift(2, B_KEY_OFFSET)
local B_START_COUNT = lshift(3, B_KEY_OFFSET)
local B_HEARTBEAT   = lshift(4, B_KEY_OFFSET)
local B_LATENCY     = lshift(5, B_KEY_OFFSET)
local B_MAX_GROUP   = lshift(6, B_KEY_OFFSET)

local BKEYS = {
  B_PID,
  B_STARTED_AT,
  B_START_COUNT,
  B_HEARTBEAT,
  B_LATENCY,
}

-- 8 bits for worker id
local B_PROC_BITS = 8
local B_PROC_OFFSET = B_KEY_OFFSET + B_KEY_BITS
local B_PROC_ID = 0

-- remainder for group id
local B_GROUP_OFFSET = B_PROC_OFFSET + B_PROC_BITS
local B_GROUP_ID  = 0

-- group ID + worker ID for the current worker
local B_GLOBAL_ID = 0


local function time()
  ngx.update_time()
  return ngx.now()
end

---@param f fun(integer, boolean)
local function each_process(f)
  f(-1, true) -- agent

  for i = 0, WORKER_COUNT - 1 do
    f(i, false)
  end
end


---@param key integer
---@return integer
local function make_proc_key(key)
  return B_GLOBAL_ID + B_NAMESPACE_PROC + key
end

---@param key integer
---@return integer
local function make_group_key(key)
  return B_GROUP_ID + B_NAMESPACE_GROUP + key
end

---@param key integer
---@return integer
local function make_global_key(key)
  return B_NAMESPACE_GLOBAL + key
end

---@param pg integer
---@param key integer
---@return any
local function pg_get(pg, key)
  local shm_key = lshift(pg, B_GROUP_OFFSET) + B_NAMESPACE_GROUP + key
  return SHM:get(shm_key)
end

local function get_current_pg()
  return SHM:get(make_global_key(B_MAX_GROUP)) or 0
end


local function b_make_proc_key(pg, id, key)
  if id == -1 then
    id = 0xFF
  end

  return lshift(pg, B_GROUP_OFFSET)
       + lshift(id, B_PROC_OFFSET)
       + key
       + B_NAMESPACE_PROC
end

---@class doorbell.nginx.process.info : table
---
---@field id            integer
---@field pid           integer
---@field started       number
---@field respawn_count integer
---@field last_seen     number
---@field healthy       boolean

---@param pg integer
---@param id integer
---@param t? number
---@return doorbell.nginx.process.info
local function get_proc_info(pg, id, t)
  local pid       = SHM:get(b_make_proc_key(pg, id, B_PID))
  local started   = SHM:get(b_make_proc_key(pg, id, B_STARTED_AT))
  local starts    = SHM:get(b_make_proc_key(pg, id, B_START_COUNT))
  local last_seen = SHM:get(b_make_proc_key(pg, id, B_HEARTBEAT))
  local latency   = SHM:get(b_make_proc_key(pg, id, B_LATENCY))

  local healthy = (pid and last_seen and latency and started) and true

  t = t or time()

  if healthy then
    if latency and latency > UNHEALTHY_THRESHOLD then
      healthy = false
    end
  end

  local respawn_count = (starts and starts - 1) or 0

  if respawn_count > 0 then
    local uptime = (started and (t - started)) or 0

    if uptime < 60 then
      healthy = false
    end
  end

  return {
    id            = id,
    pid           = pid,
    started       = started,
    respawn_count = respawn_count,
    last_seen     = last_seen,
    healthy       = healthy,
    latency       = latency,
  }
end

---@class doorbell.nginx.process
local PROC = {
  ---@type string
  type      = nil,
  ---@type integer
  group     = nil,
  ---@type integer
  id        = nil,
  ---@type string
  label     = nil,
  ---@type integer
  pid       = nil,
  ---@type boolean
  is_agent  = false,
  ---@type boolean
  is_worker = false,

  ---@type boolean
  is_respawn = false,

  is_clean_start = false,
  is_reload = false,
}

_M.process = PROC


local function report_process_metrics()
  if PROC.is_respawn then
    metrics.inc("nginx_worker_respawns", 1, { PROC.type } )
  else
    metrics.inc("nginx_worker_respawns", 0, { PROC.type } )
  end
end


local function heartbeat(premature)
  if premature or exiting() then
    for i = 1, #BKEYS do
      SHM:expire(make_proc_key(BKEYS[i]), 30)
    end
    return
  end

  local t = time()
  local last = SHM:get(HEARTBEAT_KEY)

  if last then
    local latency = t - last - HEARTBEAT_INTERVAL

    if latency > UNHEALTHY_THRESHOLD then
      log.warn(PROC.label, " heartbeat delayed by more than 50%")
    end

    latency = max(0, latency)
    assert(SHM:safe_set(LATENCY_KEY, latency, 0))

  else
    log.warn(PROC.label, " is missing previous heartbeat data")
  end

  assert(SHM:safe_set(HEARTBEAT_KEY, t, 0))
end


local function heartbeat_init()
  assert(SHM:safe_set(LATENCY_KEY, 0, 0))
  assert(SHM:safe_set(HEARTBEAT_KEY, time(), 0))
  heartbeat()
  assert(ngx.timer.every(HEARTBEAT_INTERVAL, heartbeat))
end


local function cleanup(premature)
  if premature or exiting() then
    return
  end

  SHM:flush_expired()
end


function _M.init()
  assert(proc.enable_privileged_agent(1024))

  PG_ID = assert(SHM:incr(make_global_key(B_MAX_GROUP), 1, 0))

  if PG_ID == 1 then
    PROC.is_clean_start = true
  else
    PROC.is_reload = true
  end

  B_GROUP_ID = lshift(PG_ID, B_GROUP_OFFSET)

  assert(SHM:set(make_group_key(B_STARTED_AT), time(), 0))

  WORKER_COUNT = ngx.worker.count()
end


function _M.init_worker()
  PROC.pid = ngx.worker.pid()

  local t = require("ngx.process").type()

  if t == "privileged agent" then
    PROC.is_agent = true
    PROC.id = -1
    PROC.label = "agent"
    PROC.type = "agent"
    B_PROC_ID = lshift(0xFF, B_PROC_OFFSET)

  elseif t == "worker" then
    PROC.is_worker = true
    PROC.id = ngx.worker.id()
    PROC.label = "worker #" .. tostring(PROC.id)
    PROC.type = "worker"
    B_PROC_ID = lshift(PROC.id, B_PROC_OFFSET)

  else
    error("unreachable?")
  end

  B_GLOBAL_ID = B_GROUP_ID + B_PROC_ID

  do
    assert(SHM:safe_set(make_proc_key(B_PID), PROC.pid, 0))
  end

  do
    assert(SHM:set(make_proc_key(B_STARTED_AT), time(), 0))

    local c = assert(SHM:incr(make_proc_key(B_START_COUNT), 1, 0, 0))
    if c > 1 then
      log.debug(PROC.label, " respawned, start count: ", c)
      PROC.is_respawn = true
    end
  end

  do
    HEARTBEAT_KEY = make_proc_key(B_HEARTBEAT)
    LATENCY_KEY = make_proc_key(B_LATENCY)
    assert(ngx.timer.at(0, heartbeat_init))
  end

  if metrics.enabled() then
    assert(ngx.timer.at(0, report_process_metrics))
  end

  if PROC.is_agent then
    assert(ngx.timer.every(30, cleanup))

  elseif PROC.id == 0 then
    if metrics.enabled() then
      local pending = ngx.timer.pending_count
      local running = ngx.timer.running_count
      local pending_labels = { "pending" }
      local running_labels = { "running" }

      metrics.add_hook(function()
        metrics.set("nginx_timers", pending(), pending_labels)
        metrics.set("nginx_timers", running(), running_labels)
      end)
    end
  end
end

---@class doorbell.nginx.info : table
---
---@field agent          doorbell.nginx.process.info|nil
---@field group          integer
---@field is_clean_start boolean
---@field is_reload      boolean
---@field started        number
---@field uptime         number
---@field worker_count   integer
---@field workers        doorbell.nginx.process.info[]

---@return doorbell.nginx.info
function _M.info()
  local pg = get_current_pg()
  local started = pg_get(pg, B_STARTED_AT)

  local t = time()

  local info = {
    agent            = nil,
    group            = pg,
    is_clean_start   = PROC.is_clean_start,
    is_reload        = PROC.is_reload,
    started          = started,
    uptime           = (started and t - started),
    worker_count     = WORKER_COUNT,
    workers          = {},
  }

  each_process(function(id, is_agent)
    local p = get_proc_info(pg, id, t)

    if is_agent then
      info.agent = p
    else
      table.insert(info.workers, p)
    end
  end)

  return info
end

return _M
