setmetatable(_G, nil)
pcall(require, "luarocks.loader")

local _M = {
  _VERSION = require("doorbell.constants").version,
}


local rules   = require "doorbell.rules.manager"
local const   = require "doorbell.constants"
local log     = require "doorbell.log"
local metrics = require "doorbell.metrics"
local request = require "doorbell.request"
local ip      = require "doorbell.ip"
local auth    = require "doorbell.auth"
local views   = require "doorbell.views"
local notify  = require "doorbell.notify"
local cache   = require "doorbell.cache"
local config  = require "doorbell.config"
local routes  = require "doorbell.routes"
local http    = require "doorbell.http"
local util    = require "doorbell.util"
local ota     = require "doorbell.ota"

local proc       = require "ngx.process"
local safe_decode = require("cjson.safe").decode

local ngx        = ngx
local header     = ngx.header
local start_time = ngx.req.start_time
local get_method = ngx.req.get_method
local var        = ngx.var
local assert     = assert
local shared     = ngx.shared
local send       = http.send

---@type string
local SHM_NAME = const.shm.doorbell
---@type ngx.shared.DICT
local SHM = assert(ngx.shared[SHM_NAME], "missing shm " .. SHM_NAME)


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


local function init_core_routes()
  routes["/ring"] = require("doorbell.ring")

  routes["/answer"] = {
    description     = "who is it?",
    log_enabled     = true,
    metrics_enabled = true,
    GET             = views.answer,
    POST            = views.answer,
  }

  routes["/reload"] = {
    description     = "reload from disk",
    metrics_enabled = false,
    content_type    = "text/plain",
    POST = function()
      local ok, err = rules.load(config.state_path, false)
      if ok then
        return send(201, "success")
      end
      log.err("failed reloading rules from disk: ", err)
      return send(500, "failure")
    end
  }

  routes["/save"] = {
    description     = "save to disk",
    metrics_enabled = false,
    content_type    = "text/plain",
    POST            = function()
      local ok, err = rules.save()
      if not ok then
        log.err("failed saving rules to disk: ", err)
        return send(500, "failure")
      end
      return send(201, "success")
    end
  }

  routes["/shm"] = {
    description = "shm zone list",
    metrics_enabled = false,
    content_type    = "application/json",
    GET = function()
      return send(200, util.table_keys(shared, true))
    end,
  }

  routes["~^/shm/(?<name>[^/]+)/?$"] = {
    description = "shm key list",
    metrics_enabled = false,
    content_type    = "application/json",
    GET = function(_, match)
      local name = match.name
      local shm = shared[name]
      if not shm then
        return send(404, { error = "ngx.shared[" .. name .. "] not found" })
      end

      return send(200, shm:get_keys(0))
    end
  }

  routes["~^/shm/(?<zone>[^/]+)?(/(?<key>.+))?"] = {
    description     = "shm key",
    metrics_enabled = false,
    allow_untrusted = false,
    content_type    = "application/json",
    GET = function(_, match)
      local zone, key = match.zone, match.key

      local shm = shared[zone]
      if not shm then
        return send(404, { error = "ngx.shared[" .. zone .. "] does not exist" })
      end

      local v = shm:get(key)
      if v == nil then
        return send(404, { error = "shm key " .. key .. "does not exist" })
      end

      local decoded = safe_decode(v)
      if not decoded then
        return send(200, v)
      end

      return send(200, decoded)
    end
  }

  routes["/notify/test"] = {
    description     = "send a test notification",
    metrics_enabled = false,
    content_type    = "application/json",
    POST            = function()
      local req = {
        addr    = "178.45.6.125",
        ua      = "Mozilla/5.0 (X11; Ubuntu; Linux i686) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2830.76 Safari/537.36",
        host    = "prometheus.pancakes2.com",
        uri     = "/wikindex.php?f=/NmRtJOUjAdutReQj/scRjKUhleBpzmTyO.txt",
        scheme  = "https",
        country = "US",
        method  = "GET",
        path    = "/wikindex.php",
      }

      local token = "TEST"

      local ok, err, res = notify.send(req, token)

      local response = {
        strategy = notify.strategy,
        status   = (ok and "OK") or "FAIL",
        error    = err,
        response = res,
      }

      send((ok and 200) or 500, response)
    end,
  }

  routes["/rules.html"] = {
    description     = "rules list, in html",
    metrics_enabled = false,
    allow_untrusted = false,
    content_type    = "text/html",
    GET             = views.rule_list,
  }

  routes["/rules"] = {
    description     = "rules API",
    metrics_enabled = false,
    allow_untrusted = false,
    content_type    = "application/json",
    GET             = function()
      return send(200, rules.list(true))
    end,

    POST = function()
      local json = http.get_json_request_body()

      local rule, rerr = rules.add(json)
      if not rule then
        return send(200, {
          error = "failed adding rule: " .. tostring(rerr or "unknown")
        })
      end

      return send(201, rule)
    end
  }

  routes["~^/rules/(?<hash>[a-z0-9-]+)$"] = {
    description     = "rules API",
    metrics_enabled = false,
    allow_untrusted = false,
    content_type    = "application/json",
    GET             = function(_, match)
      local rule = rules.get(match.hash)
      return send(rule and ngx.HTTP_OK or ngx.HTTP_NOT_FOUND, rule)
    end,

    PATCH          = function(_, match)
      local rule = rules.get(match.hash)
      if not rule then
        return send(404, { error = "rule not found" })
      end

      local json = http.get_json_request_body()
      local updated, err = rules.upsert(json)
      if not updated then
        return send(400, { error = err })
      end

      return send(201, updated)
    end,

    DELETE = function(_, match)
      local ok, err = rules.delete(match.hash)
      if not ok then
        return send(400, { error = err })
      end

      return send(204)
    end
  }

  routes["/favicon.ico"] = {
    description     = "stop asking me about this, browsers",
    metrics_enabled = false,
    log_enabled     = false,
    GET             = function() return send(404) end,
  }

end

function _M.init()
  for _, shm in pairs(const.shm) do
    if not ngx.shared[shm] then
      util.errorf("fatal: ngx.shared.%s is missing", shm)
    end
  end

  config.init()

  metrics.init(config)
  cache.init(config)
  ip.init(config)
  views.init(config)
  notify.init(config)
  auth.init(config)
  rules.init(config)
  request.init(config)
  ota.init(config)

  init_core_routes()

  assert(proc.enable_privileged_agent(10))

  rules.reload()
end

local function init_worker()
  metrics.init_worker()
  rules.init_worker()
  request.init_worker()
  cache.init_worker()
  notify.init_worker()
end

local function init_agent()
  rules.init_agent()
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
  local route, match = routes.match(path)
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

  return handler(ctx, match)
end

function _M.log()
  local ctx = ngx.ctx

  local start = start_time()

  if not ctx.no_metrics then
    rules.log(ctx, start)
  end

  request.log(ctx)
  request.release(ctx)
end

return _M
