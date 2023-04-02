local config = {}

local const = require "spec.testing.constants"
local join = require("spec.testing.fs").join

--- just a helper that returns a sensible default config for integration
-- tests
---@param prefix string
---@return doorbell.config
function config.new(prefix)
  return {
    base_url = "http://127.0.0.1/",
    trusted = { "127.0.0.1/32" },
    asset_path = const.ASSET_DIR,
    state_path = join(prefix, "state"),
    log_path   = join(prefix, "logs"),
    metrics    = { disable  = true },
    allow      = {},
    deny       = {},
    notify     = {
      strategy = "spec.testing.mock-notify",
      config   = {
        file = join(prefix, "notify.log"),
      },
    },
  }
end

return config
