local _M = {}

local render = require("doorbell.nginx").render
local lua_path = require("doorbell.nginx").lua_path
local resty_signal = require "resty.signal"
local cjson = require("cjson")

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


local TEMPLATE_PATH = join(const.ASSET_PATH, "nginx.template.conf")

---@param conf doorbell.config
local function prepare(conf)
  fs.reset_dir(conf.runtime_path)
  fs.reset_dir(conf.log_path)

  for _, inc in ipairs(fs.dir(const.FIXTURES_PATH, "nginx.include.*.conf")) do
    local link = join(conf.runtime_path, fs.basename(inc))
    assert(os.execute(fmt("ln -sf %q %q", inc, link)))
  end

  render(
    TEMPLATE_PATH,
    join(conf.runtime_path, "nginx.conf"),
    {
      log_path = conf.log_path,
      worker_processes = 2,
      daemon = "on",
      runtime_path = conf.runtime_path,
      asset_path = const.ASSET_PATH,
      lua_path = const.LUA_PATH,
    }
  )

  fs.write_json_file(
    join(conf.runtime_path, "config.json"),
    conf
  )
end

local function format_cmd_result(cmd, code, stdout, stderr)
  local env = table.remove(cmd)
  return fmt(
    "\ncommand: %q\nenv:%s\ncode: %s\nstdout: %s\nstderr: %s\n",
    table.concat(cmd, " "),
    cjson.encode(env),
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
---
---@field clients table<spec.testing.client, true>
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

  for client in pairs(self.clients) do
    client:close()
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
  for client in pairs(self.clients) do
    client:close()
  end

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
  local fname = fs.join(self.config.log_path, "error.log")
  if not fs.exists(fname) then
    return nil, fname .. " not found"
  end

  return fs.file_contents(fname)
end

function nginx:truncate_logs()
  local errlog = fs.join(self.config.log_path, "error.log")
  if fs.exists(errlog) then
    fs.truncate(errlog)
  end

  local access = fs.join(self.config.log_path, "access.log")
  if fs.exists(access) then
    fs.truncate(access)
  end
end


---@param client spec.testing.client
---@return spec.testing.client
function nginx:add_client(client)
  assert(type(client) == "table")
  if not self.clients[client] then
    self.clients[client] = true
  end

  return client
end

---@alias spec.testing.nginx.json.log.iter fun():doorbell.request.log.entry?


---@return spec.testing.nginx.json.log.iter|nil
---@return string? error
function nginx:iter_json_log_entries()
  local fname = fs.join(self.config.log_path, "doorbell.json.log")

  local iter, err = fs.lines(fname)

  if not iter then
    return nil, err
  end

  return function()
    local line = iter()

    if line then
      return cjson.decode(line)
    end
  end
end

---@param id string
---@return doorbell.request.log.entry|nil
function nginx:get_json_log_entry(id)
  assert(id ~= nil, "id is required")
  assert(type(id) == "string", "id must be a string")

  local iter = self:iter_json_log_entries()
  if not iter then return end

  for entry in iter do
    if entry.request_id == id then
      return entry
    end
  end
end

nginx.__index = nginx

---@param conf doorbell.config
---@return spec.testing.nginx
function _M.new(conf)
  prepare(conf)

  local self = {
    prefix = conf.runtime_path,
    config = conf,
    pidfile = join(conf.runtime_path, "logs", "nginx.pid"),
    clients = {},
  }

  return setmetatable(self, nginx)
end


return _M
