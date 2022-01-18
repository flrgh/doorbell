local _M = {}

local defaults = require "doorbell.nginx_defaults"
local util = require "doorbell.util"

---@param var string
---@return string
local function getenv(var)
  local val = os.getenv(var)
  if val then return val end

  local name = var:lower():gsub("^doorbell_", "")
  val = defaults[name]

  if not val then
    util.errorf("template variable %s is undefined", var)
  end

  return val
end

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

function _M.render(input, output, env)
  input = get_file_handle(input, "r")
  output = get_file_handle(output, "w+")

  env = env or EMPTY

  local buf = {}
  for line in input:lines() do
    line = line:gsub("%${([^}]+)}", function(var)
      local name = var:lower():gsub("^doorbell_", "")
      if env[name] then
        return env[name]
      end

      return getenv(var)
    end)
    table.insert(buf, line)
  end

  input:close()

  output:write(table.concat(buf, "\n") .. "\n")

  output:close()
end

return _M
