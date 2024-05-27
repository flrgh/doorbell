local log = require "doorbell.log"

local ffi = require "ffi"


ffi.cdef [[
  extern char **environ;
]]

---@type table<string, string>
local defaults = {
  BASE_URL     = "http://127.0.0.1",

  ASSET_PATH   = "/usr/local/share/doorbell",
  LIBEXEC_PATH = "/usr/local/libexec/doorbell",
  LIB_PATH     = "/usr/local/lib/doorbell",

  LOG_PATH     = "/var/log/doorbell",
  RUNTIME_PATH = "/var/run/doorbell",
  STATE_PATH   = "/var/run/doorbell",
}

---@return table<string, string>
local function make_defaults()
  local t = {}
  setmetatable(t, { __index = defaults })
  return t
end


---@type table<string, string|table<string, string>>
local env = {
  or_default = make_defaults(),
  ---@type table<string, string>
  all = {},
}


function env.init()
  local e = ffi.C.environ

  if not e then
    log.warn("could not access environment variables")
    return
  end

  local i = 0
  while e[i] ~= nil do
    local var = ffi.string(e[i])
    local name, value = var:match("^DOORBELL_([^=]+)=(.+)")

    if name and value and value ~= "" and value ~= defaults[name] then
      log.debug("Setting ", name, " from env var")
      env[name] = value
      env.or_default[name] = value

    else
      name, value = var:match("^([^=]+)=(.+)")
      if name then
        env.all[name] = value
      end
    end
    i = i + 1
  end
end

function env.reset()
  env.all = {}
  env.or_default = make_defaults()

  local reset = {}
  for k, v in pairs(env) do
    if type(v) == "string" then
      table.insert(reset, k)
    end
  end

  for _, k in ipairs(reset) do
    env[k] = nil
  end
end


return env
