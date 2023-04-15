---@param timeout? number
---@param step?    number
---@param fn       function
---@param ...      any
---@return boolean ok
local function await(timeout, step, fn, ...)
  step = step or 0.05
  timeout = timeout or 5

  ngx.update_time()
  local start = ngx.now()
  local elapsed = 0

  while elapsed < timeout do
    if fn(...) then
      return true
    end
    ngx.sleep(step)
    ngx.update_time()
    elapsed = ngx.now() - start
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
