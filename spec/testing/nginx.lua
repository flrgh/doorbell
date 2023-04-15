local _M = {}

local render = require("doorbell.nginx").render
local lua_path = require("doorbell.nginx").lua_path
local resty_signal = require "resty.signal"

local const = require "spec.testing.constants"
local fs = require "spec.testing.fs"
local exec = require "spec.testing.exec"
local await = require "spec.testing.await"

local assert = require "luassert"

local QUIT = assert(resty_signal.signum("QUIT"))
local TERM = assert(resty_signal.signum("TERM"))
local HUP = assert(resty_signal.signum("HUP"))

local join = fs.join
local fmt = string.format
local kill = resty_signal.kill

local function dead(pid)
  local _, err = kill(pid, 0)
  return err == "No such process"
end


local function alive(pid)
  return (kill(pid, 0) and true) or false
end


local TEMPLATE_PATH = join(const.FIXTURES_DIR, "busted.nginx.conf")

---@param prefix string
---@param conf doorbell.config
local function prepare(prefix, conf)
  fs.reset_dir(prefix)
  fs.reset_dir(conf.log_dir)

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
      log_dir = conf.log_dir,
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
---@field pid integer
---
---@field pidfile string
local nginx = {}


---@param sig integer|string
function nginx:signal(sig)
  assert(self.pid, "nginx is not running")
  return kill(self.pid, sig)
end


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

  if not await.truthy(5, 0.05, fs.not_empty, self.pidfile) then
    error("timed out waiting for NGINX pid file (" .. self.pidfile .. ") to exist")
  end

  self.pid = assert(tonumber(fs.file_contents(self.pidfile)))

  if not await.truthy(5, 0.05, alive, self.pid) then
    error("timed out waiting for NGINX process (" .. self.pid .. ") to exist")
  end
end

function nginx:stop()
  if not self.pid then
    return nil, "nginx is not running"
  end

  assert(self:signal(QUIT))

  if not await.truthy(5, 0.05, dead, self.pid) then
    self:signal(TERM)

    if not await.truthy(5, 0.05, dead, self.pid) then
      error("timed out waiting for NGINX " .. self.pid .. " to go away")
    end
  end

  fs.rm(self.pidfile, true)
  self.pid = nil

  return true
end

function nginx:restart()
  self:stop()
  self:start()
end

function nginx:reload()
  assert(self:signal(HUP))
end

function nginx:update_config(config)
  fs.write_json_file(
    join(self.prefix, "config.json"),
    config
  )
end

---@return string? contents
---@return string? error
function nginx:read_error_log()
  local fname = fs.join(self.config.log_dir, "error.log")
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
  local pidfile = join(prefix, "logs", "nginx.pid")
  local self = { prefix = prefix, config = conf, pidfile = pidfile }
  return setmetatable(self, nginx)
end

return _M
