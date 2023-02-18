local pl_util = require "pl.utils"

local function exec(cmd, ...)
  local env
  local args = {}

  for i = 1, select("#", ...) do
    local arg = select(i, ...)

    if type(arg) == "table" then
      env = arg
    else
      table.insert(args, pl_util.quote_arg(arg))
    end
  end

  cmd = cmd .. " " .. table.concat(args, " ")

  if env then
    local env_args = {}

    for k, v in pairs(env) do
      table.insert(env_args, tostring(k):upper() .. "=" .. pl_util.quote_arg(v))
    end

    cmd = table.concat(env_args, " ") .. " " .. cmd
  end

  return pl_util.executeex(cmd, false)
end

return exec
