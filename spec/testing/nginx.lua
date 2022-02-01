local _M = {}

local render = require("doorbell.nginx").render

local const = require "spec.testing.constants"
local fs = require "spec.testing.fs"
local exec = require "spec.testing.exec"
local await = require "spec.testing.await"

local assert = require "luassert"

local join = fs.join
local fmt = string.format

local TEMPLATE_PATH = join(const.ASSET_DIR, "nginx.template.conf")

---@param prefix string
---@param conf doorbell.config
local function prepare(prefix, conf)
  fs.mkdir(prefix)
  fs.reset_dir(conf.log_path)
  fs.reset_dir(conf.state_path)
  render(
    TEMPLATE_PATH,
    join(prefix, "nginx.conf"),
    {
       -- at the moment this populates the lua package path, so it needs to be
       -- relative to the repository root
      prefix = const.ROOT_DIR,
      daemon = "on",
    }
  )
  fs.write_json_file(
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
  if not await(1, fs.exists, pidfile) then
    error("timed out waiting for NGINX pid file (" .. pidfile .. ") to exist")
  end

  self.pid = fs.file_contents(pidfile)
end

function nginx:stop()
  self:exec("-s", "stop")

  local proc = join("/proc", tostring(self.pid))

  if not await.falsy(5, fs.exists, proc) then
    error("timed out waiting for NGINX " .. proc .. " to go away")
  end

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
  fs.write_json_file(
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
