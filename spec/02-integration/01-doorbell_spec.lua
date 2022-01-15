local pl_dir = require "pl.dir"
local pl_util = require "pl.utils"

local function prepare(dir)
  dir = dir:gsub("/+$", "") .. "/"
  pl_dir.makepath(dir)
  pl_dir.makepath(dir .. "logs")
  pl_dir.makepath(dir .. "state")
  pl_dir.copyfile("./nginx.conf", dir, true)
end

local function exec(cmd, ...)
  local args = pl_util.quote_arg({ ... })
  cmd = cmd .. " " .. args
  return pl_util.executeex(cmd)
end

describe("doorbell", function()
  local prefix = os.getenv("DB_PREFIX") or (os.getenv("PWD") .. "/test")

  lazy_setup(function()
    prepare(prefix)
  end)

  lazy_teardown(function()
    pl_dir.rmtree(prefix)
  end)

  it("works?", function()
    local ok, code, stdout, stderr = exec("nginx", "-p", prefix, "-c", prefix .. "/nginx.conf", "-t")
    print(require("inspect")( { ok, code, stdout, stderr } ))
  end)
end)
