local function back_off(step)
  return (step * 1.25) + (0.01 * math.random())
end

local function no_back_off(step)
  return step
end

---@param timeout? number
---@param step?    number
---@param fn       function
---@param ...      any
---@return boolean ok
---@return number elapsed
local function await(timeout, step, fn, ...)
  local next_step
  if step then
    next_step = no_back_off

  else
    step = 0.01
    next_step = back_off
  end

  timeout = timeout or 5

  ngx.update_time()
  local start = ngx.now()
  local deadline = start + timeout

  while true do
    if fn(...) then
      ngx.update_time()
      return true, ngx.now() - start
    end

    ngx.update_time()
    local time = ngx.now()
    local remain = deadline - time
    if remain < 0 then
      break
    end

    step = math.min(next_step(step), remain)
    ngx.sleep(step)
  end

  return false, ngx.now() - start
end


local _M = setmetatable({}, { __call = function(_, ...)
  return await(...)
end })

_M.truthy = await

---@param  timeout? number
---@param  step?    number
---@param  fn       function
---@param  ...      any
---@return boolean  ok
---@return number elapsed
function _M.falsy(timeout, step, fn, ...)
  local args = { ... }
  return await(timeout, step, function()
    return not fn(unpack(args))
  end)
end

return _M
