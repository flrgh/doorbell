---@param timeout? number
---@param step?    number
---@param fn       function
---@param ...      any
---@return boolean ok
---@return number elapsed
local function await(timeout, step, fn, ...)
  step = step or 0.05
  timeout = timeout or 5

  ngx.update_time()
  local start = ngx.now()
  local deadline = start + timeout

  repeat
    if fn(...) then
      ngx.update_time()
      return true, ngx.now() - start
    end

    ngx.sleep(step)
    ngx.update_time()
  until ngx.now() >= deadline

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
