local config = {}

local const = require "spec.testing.constants"
local join = require("spec.testing.fs").join

--- just a helper that returns a sensible default config for integration tests
---@param runtime_path? string
---@return doorbell.config
function config.new(runtime_path)
  runtime_path = runtime_path or const.RUNTIME_PATH

  return {
    base_url     = "http://127.0.0.1/",
    trusted      = { "127.0.0.1/32" },
    asset_path   = const.ASSET_PATH,
    runtime_path = runtime_path,
    state_path   = runtime_path,
    log_path     = join(runtime_path, "logs"),
    metrics      = { disable  = true },
    allow        = {},
    deny         = {},
    notify       = {
      strategy = "spec.testing.mock-notify",
      config   = {
        file = join(runtime_path, "notify.log"),
      },
    },
    auth = {
      disabled = true,
    },
  }
end

return config
