local _M = {}

do
  local configure = assert(ngx.config.nginx_configure(),
                           "failed to read ngx.config.configure")

  if not configure:find("with-http_realip_module", nil, true) then
    print(string.rep("-", 120))
    print((configure:gsub(" %-", "\n-")))
    print(string.rep("-", 120))

    error("realip module not found")
  end
end

local defaults = require "doorbell.nginx.defaults"
local util = require "doorbell.util"
local ENV = require "doorbell.env"

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


---@param ... string
---@return string
function _M.lua_path(...)
  local path = {}
  for i = 1, select("#", ...) do
    local p = select(i, ...)
    if p then
      p = p:gsub("/+$", "")
      table.insert(path, p .. "/?.lua")
      table.insert(path, p .. "/?/init.lua")
    end
  end

  return table.concat(path, ";")
end

---@param ... string
---@return string
function _M.lua_cpath(...)
  local path = {}
  for i = 1, select("#", ...) do
    local p = select(i, ...)
    p = p:gsub("/+$", "")
    table.insert(path, p .. "/?.so")
  end

  return table.concat(path, ";")
end


---@param input string|file*
---@param output string|file*
---@param env? table
function _M.render(input, output, env)
  input = get_file_handle(input, "r")
  output = get_file_handle(output, "w+")

  env = env or EMPTY

  local function get_value(var)
    local name = var:lower():gsub("^doorbell_", "")

    local value = env[name]
    if value ~= nil then
      return value
    end

    value = ENV[name:upper()]
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
  end

  local function render_value(var)
    local value = get_value(var)
    if type(value) == "table" then
      value = table.concat(value, "\n")
    end

    return value
  end

  local buf = {}
  for line in input:lines() do
    line = line:gsub("%${([^}]+)}", render_value)
    table.insert(buf, line)
  end

  input:close()

  local ok, err = output:write(table.concat(buf, "\n") .. "\n")

  output:close()

  assert(ok, err)
end

return _M
