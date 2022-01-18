local _M = {}

local defaults = require "doorbell.nginx.defaults"
local util = require "doorbell.util"

---@param f string|file*
---@param mode openmode
---@return file*
local function get_file_handle(f, mode)
  if type(f) == "string" then
    return assert(io.open(f, mode))
  end

  return f
end

local EMPTY = {}

---@param input string|file*
---@param output string|file*
---@param env? table
function _M.render(input, output, env)
  input = get_file_handle(input, "r")
  output = get_file_handle(output, "w+")

  env = env or EMPTY

  local buf = {}
  for line in input:lines() do
    line = line:gsub("%${([^}]+)}", function(var)
      local name = var:lower():gsub("^doorbell_", "")

      local value = env[name]
      if value ~= nil then
        return value
      end

      value = os.getenv(var)
      if value ~= nil then
        return value
      end

      value = defaults[name]
      if value ~= nil then
        return value
      end

      util.errorf("template variable %s is undefined", var)

    end)
    table.insert(buf, line)
  end

  input:close()

  local ok, err = output:write(table.concat(buf, "\n") .. "\n")

  output:close()

  assert(ok, err)
end

return _M
