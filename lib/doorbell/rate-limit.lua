---@class doorbell.rate-limit
local _M = {}

local now = ngx.now
local max = math.max
local floor = math.floor

local MIN_PERIOD = 1
_M.MIN_PERIOD = MIN_PERIOD

local remaining = require("doorbell.shm").with_namespace("rl-remaining")
local reset = require("doorbell.shm").with_namespace("rl-reset")


---@param key string
---@param limit number
---@param period number
---
---@return boolean allow
---@return integer remaining
---@return number resets_in
function _M.request(key, limit, period)
  assert(limit > 0 and period >= MIN_PERIOD)

  local time = now()
  local next_reset

  if remaining:add(key, limit - 1, period) then
    -- first request, we just set the remaining amount
    next_reset = time + period
    assert(reset:set(key, next_reset))
    return true, limit - 1, period
  end

  local remain = remaining:incr(key, -1, limit, period)
  assert(remain, "this probably shouldn't fail")

  next_reset = reset:get(key)

  local reset_in = next_reset
               and max(0, floor(next_reset - time))
                or period

  if remain > 0 then
    return true, remain, reset_in

  elseif remain < 0 then
    return false, 0, reset_in
  end

  -- remain == 0
  -- only one request should hit this condition, right?
  if next_reset <= time then
    remaining:set(key, nil)
    return true, limit, period
  end

  return true, 0, reset_in
end

return _M
