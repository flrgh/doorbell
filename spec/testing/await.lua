---@param timeout number
---@param fn function
---@param ... any
local function await(timeout, fn, ...)
  local step = 0.05
  local remain = timeout

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

---@param timeout number
---@param fn function
---@param ... any
function _M.falsy(timeout, fn, ...)
  local args = { ... }
  return await(timeout, function()
    return not fn(unpack(args))
  end)
end

return _M
