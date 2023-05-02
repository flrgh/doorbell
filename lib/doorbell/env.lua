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

---@type table<string, string|table<string, string>>
local env = {
  ---@type table<string, string>
  or_default = setmetatable({}, { __index = defaults }),
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
      log.debugf("Setting %s from env var: %q", name, value)
      env[name] = value
      env.or_default[name] = value
    end
    i = i + 1
  end
end


return env
