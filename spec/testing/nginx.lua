local _M = {}

local render = require("doorbell.nginx").render
local lua_path = require("doorbell.nginx").lua_path

local const = require "spec.testing.constants"
local fs = require "spec.testing.fs"
local exec = require "spec.testing.exec"
local await = require "spec.testing.await"

local assert = require "luassert"

local join = fs.join
local fmt = string.format

local TEMPLATE_PATH = join(const.FIXTURES_DIR, "busted.nginx.conf")

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
      test_fixtures_dir = const.FIXTURES_DIR,
      worker_processes = 1,
    }
  )
  fs.write_json_file(
    join(prefix, "config.json"),
    conf
  )
end

local function format_cmd_result(cmd, code, stdout, stderr)
  local env = table.remove(cmd)
  return fmt(
    "\ncommand: %q\nenv:%s\ncode: %s\nstdout: %s\nstderr: %s\n",
    table.concat(cmd, " "),
    require("cjson").encode(env),
    code,
    stdout,
    stderr
  )
end

---@class spec.testing.nginx
---
---@field prefix string
---
---@field config doorbell.config
---
---@field pid string
local nginx = {}

function nginx:exec(...)
  local prefix = self.prefix
  local cmd = {
    "nginx",
    "-p", prefix,
    "-c", join(prefix, "nginx.conf"),
  }

  local env

  for i = 1, select("#", ...) do
    local elem = select(i, ...)
    if type (elem) == "table" then
      env = elem
    else
      table.insert(cmd, elem)
    end
  end

  env = env or {}
  env.LUA_PATH = env.LUA_PATH or lua_path(const.ROOT_DIR)
  if os.getenv("LUA_PATH") then
    env.LUA_PATH = env.LUA_PATH .. ";" .. os.getenv("LUA_PATH")
  end
  env.LUA_PATH = env.LUA_PATH .. ";;"

  table.insert(cmd, env)

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
  if not await(5, 0.1, fs.exists, pidfile) then
    error("timed out waiting for NGINX pid file (" .. pidfile .. ") to exist")
  end

  self.pid = fs.file_contents(pidfile)
end

function nginx:stop()
  if not self.pid then
    return nil, "nginx is not running"
  end

  self:exec("-s", "stop")

  local proc = join("/proc", tostring(self.pid))

  if not await.falsy(5, 0.1, fs.exists, proc) then
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

---@return string? contents
---@return string? error
function nginx:read_error_log()
  local fname = fs.join(self.config.log_path, "error.log")
  if not fs.exists(fname) then
    return nil, fname .. " not found"
  end

  return fs.file_contents(fname)
end


nginx.__index = nginx

---@param prefix string
---@param conf doorbell.config
---@return spec.testing.nginx
function _M.new(prefix, conf)
  prepare(prefix, conf)
  local self = { prefix = prefix, config = conf }
  return setmetatable(self, nginx)
end

return _M
