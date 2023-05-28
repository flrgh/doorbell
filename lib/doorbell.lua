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
local new_ctx    = request.new
local get_ctx    = request.get
local cors_preflight = http.CORS.preflight
local set_header = http.response.set_header
local exec_route_middleware = router.exec_middleware

local REWRITE       = middleware.phase.REWRITE
local AUTH          = middleware.phase.AUTH
local PRE_HANDLER   = middleware.phase.PRE_HANDLER
local LOG           = middleware.phase.LOG
local POST_RESPONSE = middleware.phase.POST_RESPONSE

local SERVER = "doorbell " .. _M._VERSION
local REQUEST_ID = require("doorbell.constants").headers.request_id

---@type ngx.shared.DICT
local SHM = require("doorbell.shm").doorbell

local GLOBAL_REWRITE_MWARE = middleware.compile({
  request.middleware.pre_handler,
  router.on_match,
})

local GLOBAL_PRE_HANDLER_MWARE = middleware.compile({
  http.CORS.middleware,
})

-- keeping these in a single table ensures that we run init() and init_worker()
-- functions in a consistent order
local submodules = {
  metrics,
  cache,
  ip,
  views,
  notify,
  auth,
  manager,
  request,
  ota,
  routes,
}


local function init_agent()
  manager.init_agent()
  ota.init_agent()
end


function _M.init()
  env.init()
  config.init()

  for _, mod in ipairs(submodules) do
    if type(mod.init) == "function" then
      mod.init(config)
    end
  end

  assert(proc.enable_privileged_agent(10))

  manager.reload()
end


function _M.init_worker()
  assert(SHM, "doorbell was not initialized")

  require("resty.jit-uuid").seed()

  if proc.type() == "privileged agent" then
    return init_agent()
  end

  for _, mod in ipairs(submodules) do
    if type(mod.init_worker) == "function" then
      mod.init_worker()
    end
  end
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

  GLOBAL_REWRITE_MWARE(ctx, route, match)
  exec_route_middleware(REWRITE, ctx, route, match)
end


-- the auth handler runs during NGINX's access phase and is responsible for,
-- as you might expect, authentication and authorization
function _M.auth()
  assert(SHM, "doorbell was not initialized")

  local ctx = get_ctx()
  exec_route_middleware(AUTH, ctx, ctx.route)
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

  GLOBAL_PRE_HANDLER_MWARE(ctx, route, match)
  exec_route_middleware(PRE_HANDLER, ctx, route, match)

  if not handler then
    send(405)
  end

  return handler(ctx, match)
end


function _M.log()
  local ctx = get_ctx()

  local route = ctx.route
  exec_route_middleware(LOG, ctx, route)

  request.log(ctx)

  exec_route_middleware(POST_RESPONSE, ctx, route)
end


return _M
