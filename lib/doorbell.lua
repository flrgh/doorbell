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
local assert     = assert
local send       = http.send
local exec_mw    = middleware.exec
local new_ctx    = request.new
local get_ctx    = request.get
local cors_preflight = http.CORS.preflight
local set_header = http.response.set_header

local REWRITE       = middleware.phase.REWRITE
local AUTH          = middleware.phase.AUTH
local PRE_HANDLER   = middleware.phase.PRE_HANDLER
local LOG           = middleware.phase.LOG
local POST_RESPONSE = middleware.phase.POST_RESPONSE

local SERVER = "doorbell " .. _M._VERSION
local REQUEST_ID = require("doorbell.constants").headers.request_id

---@type ngx.shared.DICT
local SHM = require("doorbell.shm").doorbell

---@type doorbell.middleware[]
local GLOBAL_REWRITE_MWARE = {
  request.middleware.pre_handler,
  router.on_match,
}

---@type doorbell.middleware[]
local GLOBAL_PRE_HANDLER_MWARE = {
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


-- the rewrite handler runs during NGINX's rewrite phase and is responsible
-- for matching the request to an existing route and performing any request
-- mutations before checking auth and executing a route handler
function _M.rewrite()
  assert(SHM, "doorbell was not initialized")

  set_header("server", SERVER)

  local ctx = new_ctx(ngx.ctx)

  set_header(REQUEST_ID, ctx.id)

  local route, match = router.match(ctx.path)
  if not route then
    return send(405)
  end

  ctx.route = route
  ctx.route_match = match

  exec_mw(GLOBAL_REWRITE_MWARE, ctx, route, match)
  exec_route_middleware(REWRITE, ctx)
end


-- the auth handler runs during NGINX's access phase and is responsible for,
-- as you might expect, authentication and authorization
function _M.auth()
  assert(SHM, "doorbell was not initialized")

  local ctx = get_ctx()
  exec_route_middleware(AUTH, ctx)
end


-- the content handler runs during NGINX's content phase and is where most
-- application business logic is performed
function _M.content()
  assert(SHM, "doorbell was not initialized")

  local ctx = get_ctx()

  local route = assert(ctx.route)
  local match = ctx.route_match

  ---@type doorbell.route.handler
  local handler = route[ctx.method]

  if not handler and ctx.method == "OPTIONS" then
    handler = cors_preflight
  end

  exec_mw(GLOBAL_PRE_HANDLER_MWARE, ctx, route, match)
  exec_route_middleware(PRE_HANDLER, ctx)

  if not handler then
    send(405)
  end

  return handler(ctx, match)
end


function _M.log()
  local ctx = get_ctx()

  exec_route_middleware(LOG, ctx)

  request.log(ctx)

  exec_route_middleware(POST_RESPONSE, ctx)
end


return _M
