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
local middleware = require "doorbell.middleware"

local proc       = require "ngx.process"

local ngx        = ngx
local start_time = ngx.req.start_time
local assert     = assert
local send       = http.send
local exec_mw    = middleware.exec
local new_ctx    = request.new
local cors_preflight = http.CORS.preflight
local set_header = http.response.set_header

local PRE_AUTH = middleware.phase.PRE_AUTH
local PRE_HANDLER = middleware.phase.PRE_HANDLER
local PRE_LOG = middleware.phase.PRE_LOG
local POST_LOG = middleware.phase.POST_LOG

local SERVER = "doorbell " .. _M._VERSION
local REQUEST_ID = require("doorbell.constants").headers.request_id

---@type ngx.shared.DICT
local SHM = require("doorbell.shm").doorbell


---@type doorbell.middleware[]
local GLOBAL_MIDDLEWARE = {
  request.middleware.pre_handler,
  router.on_match,
  http.CORS.middleware,
}


---@param phase doorbell.middleware.phase
---@param ctx doorbell.ctx
local function exec_route_middleware(phase, ctx)
  local route = ctx.route
  if not route then return end

  local mw = route.middleware
  if not mw then return end

  local phase_mw = mw[phase]
  if not phase_mw then return end

  exec_mw(phase_mw, ctx, route)
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
  set_header("server", SERVER)

  local ctx = new_ctx(ngx.ctx)

  set_header(REQUEST_ID, ctx.id)

  local route, match = router.match(ctx.path)
  if not route then
    return send(405)
  end

  ctx.route = route

  exec_route_middleware(PRE_AUTH, ctx)

  ---@type doorbell.route.handler
  local handler = route[ctx.method]

  if not handler and ctx.method == "OPTIONS" then
    handler = cors_preflight
  end

  exec_mw(GLOBAL_MIDDLEWARE, ctx, route, match)
  exec_route_middleware(PRE_HANDLER, ctx)

  if not handler then
    send(405)
  end

  return handler(ctx, match)
end


function _M.log()
  ---@type doorbell.ctx
  local ctx = ngx.ctx

  exec_route_middleware(PRE_LOG, ctx)

  local start = start_time()

  if not ctx.no_metrics then
    manager.log(ctx, start)
  end

  request.log(ctx)

  exec_route_middleware(POST_LOG, ctx)
end


return _M
