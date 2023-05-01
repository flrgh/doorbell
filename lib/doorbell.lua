setmetatable(_G, nil)
pcall(require, "luarocks.loader")

local _M = {
  _VERSION = require("doorbell.constants").version,
}


local manager = require "doorbell.rules.manager"
local metrics = require "doorbell.metrics"
local request = require "doorbell.request"
local ip      = require "doorbell.ip"
local auth    = require "doorbell.auth"
local views   = require "doorbell.views"
local notify  = require "doorbell.notify"
local cache   = require "doorbell.cache"
local config  = require "doorbell.config"
local routes  = require "doorbell.routes"
local router  = require "doorbell.router"
local http    = require "doorbell.http"
local ota     = require "doorbell.ota"
local env     = require "doorbell.env"

local proc       = require "ngx.process"

local ngx        = ngx
local header     = ngx.header
local start_time = ngx.req.start_time
local get_method = ngx.req.get_method
local get_query  = ngx.req.get_uri_args
local var        = ngx.var
local assert     = assert
local send       = http.send

---@type ngx.shared.DICT
local SHM = require("doorbell.shm").doorbell

local MAX_QUERY_ARGS = 20


---@class doorbell.ctx : table
---@field rule            doorbell.rule
---@field request_headers table
---@field trusted_ip      boolean
---@field request         doorbell.request
---@field country_code    string
---@field geoip_error     string
---@field cached          boolean
---@field no_log          boolean
---@field no_metrics      boolean
---@field template        fun(env:table):string
---@field route           doorbell.route
---@field query?          table<string, any>


function _M.init()
  env.init()
  config.init()

  metrics.init(config)
  cache.init(config)
  ip.init(config)
  views.init(config)
  notify.init(config)
  auth.init(config)
  manager.init(config)
  request.init(config)
  ota.init(config)
  routes.init(config)

  assert(proc.enable_privileged_agent(10))

  manager.reload()
end

local function init_worker()
  metrics.init_worker()
  manager.init_worker()
  request.init_worker()
  cache.init_worker()
  notify.init_worker()
end

local function init_agent()
  manager.init_agent()
  ota.init_agent()
end

function _M.init_worker()
  assert(SHM, "doorbell was not initialized")

  require("resty.jit-uuid").seed()

  if proc.type() == "privileged agent" then
    return init_agent()
  end

  return init_worker()
end

function _M.run()
  assert(SHM, "doorbell was not initialized")
  header.server = "doorbell"

  local path = var.uri:gsub("?.*", "")
  local route, match = router.match(path)
  if not route then
    return send(405)
  end

  ---@type doorbell.ctx
  local ctx = ngx.ctx
  ctx.route = route

  if route.content_type then
    header["content-type"] = route.content_type
  end

  if route.log_enabled == false then
    var.doorbell_log = 0
    request.no_log(ctx)
  end

  if route.metrics_enabled == false then
    request.no_metrics(ctx)
  end

  if not route.allow_untrusted then
    ip.require_trusted(ctx)
  end

  local method = get_method()
  local handler = route[method] or route["*"]
  if not handler then
    send(405)
  end

  if route.need_query then
    ctx.query = get_query(MAX_QUERY_ARGS)
  end

  return handler(ctx, match)
end

function _M.log()
  local ctx = ngx.ctx

  local start = start_time()

  if not ctx.no_metrics then
    manager.log(ctx, start)
  end

  request.log(ctx)
  request.release(ctx)
end

return _M
