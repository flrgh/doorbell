---@param timeout? number
---@param step?    number
---@param fn       function
---@param ...      any
---@return boolean ok
local function await(timeout, step, fn, ...)
  step = step or 0.05
  local remain = timeout or 5

  while remain > 0 do
    if fn(...) then
      return true
    end
    ngx.sleep(step)
    remain = remain - step
  end

  return false
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
function _M.falsy(timeout, step, fn, ...)
  local args = { ... }
  return await(timeout, step, function()
    return not fn(unpack(args))
  end)
end

return _M
