local _M = {}

local util = require "doorbell.util"
local render = require("doorbell.nginx").render

local pl_dir = require "pl.dir"
local pl_util = require "pl.utils"
local pl_path = require "pl.path"
local assert = require "luassert"

local join = util.join
local fmt = string.format

local ROOT = os.getenv("PWD")

local function await(timeout, fn, ...)
  local step = 0.05
  while not fn(...) do
    if timeout < 0 then
      error("timed out waiting for function to return truth-y")
    end
    ngx.sleep(step)
    timeout = timeout - step
  end
end

local function exec(cmd, ...)
  local args = pl_util.quote_arg({ ... })
  cmd = cmd .. " " .. args
  return pl_util.executeex(cmd)
end

---@param prefix string
---@param conf doorbell.config
local function prepare(prefix, conf)
  pl_dir.makepath(prefix)
  pl_dir.makepath(join(conf.log_path))
  pl_dir.makepath(join(conf.state_path))
  render(
    join(ROOT, "assets", "nginx.template.conf"),
    join(prefix, "nginx.conf"),
    {
       -- at the moment this populates the lua package path, so it needs to be
       -- relative to the repository root
      prefix = ROOT,
      daemon = "on",
    }
  )
  util.write_json_file(
    join(prefix, "config.json"),
    conf
  )
end

local function format_cmd_result(cmd, code, stdout, stderr)
  return fmt(
    "command: %q\ncode: %s\nstdout: %s\nstderr: %s\n",
    table.concat(cmd, " "),
    code,
    stdout,
    stderr
  )
end

---@class spec.testing.nginx
local nginx = {}

function nginx:exec(...)
  local prefix = self.prefix
  local cmd = {
    "nginx",
    "-p", prefix,
    "-c", join(prefix, "nginx.conf"),
  }

  for i = 1, select("#", ...) do
    local elem = select(i, ...)
    table.insert(cmd, elem)
  end

  local ok, code, stdout, stderr = exec(unpack(cmd))
  assert.truthy(ok, format_cmd_result(cmd, code, stdout, stderr))
  assert.equals(0, code, format_cmd_result(cmd, code, stdout, stderr))
end

function nginx:conf_test()
  return self:exec("-t")
end

function nginx:start()
  self:exec()
  local pidfile = join(self.prefix, "logs", "nginx.pid")
  await(1, pl_path.exists, pidfile)

  self.pid = assert(pl_util.readfile(pidfile))
end

function nginx:stop()
  self:exec("-s", "stop")

  local proc = join("/proc", tostring(self.pid))

  await(5, function()
    return not pl_path.exists(proc)
  end)
  return true
end

function nginx:restart()
  self:stop()
  self:start()
end

function nginx:reload()
  self:exec("-s", "reload")
end

function nginx:update_config(config)
  util.write_json_file(
    join(self.prefix, "config.json"),
    config
  )
  self:restart()
end

nginx.__index = nginx

---@param prefix string
---@param conf doorbell.config
---@return spec.testing.nginx
function _M.new(prefix, conf)
  prepare(prefix, conf)
  local self = { prefix = prefix, conf = conf }
  return setmetatable(self, nginx)
end

return _M
