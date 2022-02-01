local pl_util = require "pl.utils"

local function exec(cmd, ...)
  local args = pl_util.quote_arg({ ... })
  cmd = cmd .. " " .. args
  return pl_util.executeex(cmd)
end

return exec
