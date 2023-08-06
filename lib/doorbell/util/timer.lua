local _M = {}

local log = require "doorbell.log"

local exiting = ngx.worker.exiting
local timer_at = ngx.timer.at
local pcall = pcall
local sleep = ngx.sleep
local now = ngx.now
local update_time = ngx.update_time

local ROUNDS = 1000
local EMPTY = {}
local NOOP = function() end

---@class doorbell.util.timer.opts : table
---
---@field stop_on_error boolean
---@field run_on_premature boolean


local function updated_time()
  update_time()
  return now()
end


---@param name string
---@param f function
---@return function
local function wrapped(name, f)
  return function()
    log.debug("executing timer: ", name)

    local ok, err = pcall(f)
    if not ok then
      log.errf("timer %s threw an error: %s", name, err)
    end

    return ok, err
  end
end



---@param premature boolean
---@param period number
---@param name string
---@param fn function
---@param opts doorbell.util.timer.opts
local function run_every(premature, time, name, period, fn, opts)
  local stop_on_error = opts.stop_on_error
  local on_premature = opts.run_on_premature and fn or NOOP

  if premature then
    on_premature()
    return
  end

  for _ = 1, ROUNDS do
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

    if elapsed >= period then
      log.warnf("timer %s took longer than its period (%s) to execute: %s",
                name, elapsed, period)

      sleep(0.001)

    else
      sleep(period - elapsed)
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
function _M.every(period, name, fn, opts)
  fn = wrapped(name, fn)

  local time = now
  if period < 1 then
    time = updated_time
  end

  opts = opts or EMPTY
  assert(timer_at(0, run_every, time, name, period, fn, opts))
end


---@param timeout number
---@param name string
---@param fn function
---@param opts? doorbell.util.timer.opts
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
end

return _M
