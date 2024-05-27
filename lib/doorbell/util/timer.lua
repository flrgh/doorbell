local _M = {}

local log = require("doorbell.log").with_namespace("timer")

local exiting = ngx.worker.exiting
local timer_at = ngx.timer.at
local pcall = pcall
local sleep = ngx.sleep
local now = ngx.now
local update_time = ngx.update_time
local min = math.min
local max = math.max

local MAX_SLEEP = 1
local MIN_SLEEP = 0.001
local ROUNDS = 1000
local EMPTY = {}
local NOOP = function() end

---@class doorbell.util.timer.opts : table
---
---@field stop_on_error?    boolean
---@field run_on_premature? boolean


local function updated_time()
  update_time()
  return now()
end


---@param name string
---@param f function
---@return function
local function wrapped(name, f)
  local running = "running task: " .. name

  return function()
    log.debug(running)

    local ok, err = pcall(f)
    if not ok then
      log.err("task ", name, " threw an error: ", err)
    end

    return ok, err
  end
end


---@param premature boolean
---@param time fun():number
---@param name string
---@param period number
---@param fn function
---@param opts doorbell.util.timer.opts
local function run_every(premature, time, name, period, fn, opts)
  local stop_on_error = opts.stop_on_error
  local on_premature = opts.run_on_premature and fn or NOOP

  if premature then
    on_premature()
    return
  end

  local next_run = time()

  for _ = 1, ROUNDS do
    local t = time()
    while (next_run - t) > MIN_SLEEP and not exiting() do
      sleep(min(MAX_SLEEP, max(next_run - t, MIN_SLEEP)))
      t = time()
    end

    if exiting() then
      on_premature()
      return
    end

    local start = time()

    if fn() then
      if stop_on_error then
        return
      end
    end

    if exiting() then return end

    local elapsed = time() - start

    next_run = start + period

    if elapsed >= period then
      log.warnf("task %s took longer than its period (%s) to execute: %s",
                name, elapsed, period)

      sleep(MIN_SLEEP)
    end
  end

  if not exiting() then
    assert(timer_at(0, run_every, time, name, period, fn, opts))
  end
end


---@param period number
---@param name string
---@param fn function
---@param opts? doorbell.util.timer.opts
---@return true
function _M.every(period, name, fn, opts)
  fn = wrapped(name, fn)

  local time = now
  if period < 1 then
    time = updated_time
  end

  opts = opts or EMPTY
  assert(timer_at(0, run_every, time, name, period, fn, opts))

  return true
end


---@param timeout number
---@param name string
---@param fn function
---@param opts? doorbell.util.timer.opts
---@return true
function _M.at(timeout, name, fn, opts)
  fn = wrapped(name, fn)
  opts = opts or EMPTY

  if opts.run_on_premature then
    assert(timer_at(timeout, fn))
  else
    assert(timer_at(timeout, function(premature)
      if premature then return end
      fn()
    end))
  end

  return true
end

return _M
