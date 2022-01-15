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

local cjson      = require "cjson"
local proc       = require "ngx.process"
local safe_decode = require("cjson.safe").decode

local ngx               = ngx
local header            = ngx.header
local say               = ngx.say
local start_time        = ngx.req.start_time
local get_method        = ngx.req.get_method
local exit              = ngx.exit
local sleep             = ngx.sleep
local var               = ngx.var

local HTTP_OK                    = ngx.HTTP_OK
local HTTP_FORBIDDEN             = ngx.HTTP_FORBIDDEN
local HTTP_UNAUTHORIZED          = ngx.HTTP_UNAUTHORIZED
local HTTP_INTERNAL_SERVER_ERROR = ngx.HTTP_INTERNAL_SERVER_ERROR
local HTTP_CREATED               = ngx.HTTP_CREATED
local HTTP_BAD_REQUEST           = ngx.HTTP_BAD_REQUEST
local HTTP_NOT_ALLOWED           = ngx.HTTP_NOT_ALLOWED

local assert   = assert

---@class doorbell.config : table
local config

local TARPIT_INTERVAL = const.periods.minute * 5

---@type string
local SHM_NAME = const.shm.doorbell
---@type ngx.shared.DICT
local SHM = assert(ngx.shared[SHM_NAME], "missing shm " .. SHM_NAME)

local STATES = const.states

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


---@alias doorbell.handler fun(req:doorbell.request, ctx:doorbell.ctx)

---@type table<doorbell.auth_state, doorbell.handler>
local HANDLERS = {
  [STATES.allow] = function(req)
    log.debugf("ALLOW %s => %s %s://%s%s", req.addr, req.method, req.scheme, req.host, req.uri)
    return exit(HTTP_OK)
  end,

  [STATES.deny] = function(req, ctx)
    log.notice("denying access for ", req.addr)
    if ctx.rule.deny_action == const.deny_actions.tarpit then
      log.debugf("tarpit %s for %s seconds", req.addr, TARPIT_INTERVAL)
      sleep(TARPIT_INTERVAL)
    end
    return exit(HTTP_FORBIDDEN)
  end,

  [STATES.none] = function(req)
    if notify.in_notify_period() then
      log.notice("requesting access for ", req.addr)
      if auth.request(req) and auth.await(req) then
        log.notice("access approved for ", req.addr)
        return exit(HTTP_OK)
      end
    else
      log.notice("not sending request outside of notify hours for ", req.addr)
      notify.inc("snoozed")
    end
    return exit(HTTP_UNAUTHORIZED)
  end,

  [STATES.pending] = function(req)
    log.notice("awaiting access for ", req.addr)
    if auth.await(req) then
      return exit(HTTP_OK)
    end
    return exit(HTTP_UNAUTHORIZED)
  end,

  [STATES.error] = function(req)
    log.err("something went wrong while checking auth for ", req.addr)
    return exit(HTTP_INTERNAL_SERVER_ERROR)
  end,
}

---@param opts doorbell.config
function _M.init(opts)
  config = require("doorbell.config").new(opts)

  metrics.init(config)
  cache.init(config)
  ip.init(config)
  views.init(config)
  notify.init(config)
  auth.init(config)
  rules.init(config)
  request.init(config)

  assert(proc.enable_privileged_agent(10))

  rules.reload()
end

function _M.ring()
  assert(SHM, "doorbell was not initialized")
  local ctx = ngx.ctx

  ip.require_trusted(ctx)

  local req, err = request.new(ctx)
  if not req then
    log.alert("failed building request: ", err)
    return exit(HTTP_BAD_REQUEST)
  end

  if req.host == config.host and req.path == "/answer" then
    log.debugf("allowing request to %s/answer endpoint", config.host)
    return exit(HTTP_OK)
  end

  local state = auth.get_state(req, ctx)

  return HANDLERS[state](req, ctx)
end

function _M.answer()
  assert(SHM, "doorbell was not initialized")
  local ctx = ngx.ctx
  ip.require_trusted(ctx)
  return views.answer(ctx)
end

local function get_json_request_body()
  ngx.req.read_body()
  local body, err = ngx.req.get_body_data()
  if not body then
    local fname = ngx.req.get_body_file()
    if fname then
      local fh
      fh, err = io.open(fname, "r")
      if fh then
        body, err = fh:read("*a")
        fh:close()
      end
    end
  end

  if body and body ~= "" then
    local json, jerr = safe_decode(body)
    if jerr then
      return nil, err
    elseif json ~= nil then
      return json
    end
  end

  return nil, err
end

function _M.rules_api()
  assert(SHM, "doorbell was not initialized")
  ip.require_trusted(ngx.ctx)

  local hash = var.rule_hash
  if hash == "" then hash = nil end

  local status, res

  local method = get_method()

  if method == "GET" then
    local list = rules.list()
    if hash then
      res = rules.get(hash)
    else
      res = list
    end

    if res then
      status = ngx.HTTP_OK
    else
      status = ngx.HTTP_NOT_FOUND
    end

  elseif method == "POST" then
    if hash then
      status = HTTP_NOT_ALLOWED
      res = { error = "method not allowed" }

    else
      local json, err = get_json_request_body()
      if not json then
        status = HTTP_BAD_REQUEST
        res = { error = "failed reading request body json: " .. tostring(err or "unknown") }

      else
        local rule, rerr = rules.add(json)
        if not rule then
          status = HTTP_BAD_REQUEST
          res = { error = "failed adding rule: " .. tostring(rerr or "unknown") }

        else
          res = rule
          status = ngx.HTTP_CREATED
        end
      end
    end
  end

  ngx.status = status or 200
  header["content-type"] = "application/json"
  say(cjson.encode(res))
end

function _M.list_html()
  assert(SHM, "doorbell was not initialized")
  local ctx = ngx.ctx
  ip.require_trusted(ctx)
  return views.rule_list(ctx)
end

local function init_worker()
  metrics.init_worker()
  rules.init_worker()
  request.init_worker()
  cache.init_worker()
end

local function init_agent()
  rules.init_agent()
end

function _M.save()
  local ctx = ngx.ctx
  request.no_log(ctx)
  request.no_metrics(ctx)

  assert(SHM, "doorbell was not initialized")
  if get_method() ~= "POST" then
    return exit(HTTP_NOT_ALLOWED)
  end

  local ok, err = rules.save()

  ngx.status = (ok and HTTP_CREATED) or HTTP_INTERNAL_SERVER_ERROR

  header["content-type"] = "text/plain"

  if err then
    log.err("failed saving rules to disk: ", err)
    say("failure")
  else
    say("success")
  end

  return exit(0)
end

function _M.notify_test()
  local ctx = ngx.ctx
  request.no_log(ctx)
  request.no_metrics(ctx)

  assert(SHM, "doorbell was not initialized")
  if get_method() ~= "POST" then
    return exit(HTTP_NOT_ALLOWED)
  end

  local req = {
    addr = "178.45.6.125",
    ua = "Mozilla/5.0 (X11; Ubuntu; Linux i686) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2830.76 Safari/537.36",
    host = "prometheus.pancakes2.com",
    uri = "/wikindex.php?f=/NmRtJOUjAdutReQj/scRjKUhleBpzmTyO.txt",
    scheme = "https",
    country = "US",
    method = "GET",
    path = "/wikindex.php",
  }
  local token = "TEST"

  local ok, err, res = notify.send(req, token)

  local response = {
    strategy = notify.strategy,
    status   = (ok and "OK") or "FAIL",
    error    = err,
    response = res,
  }

  local status = ok and HTTP_OK or HTTP_INTERNAL_SERVER_ERROR
  ngx.status = status
  header["content-type"] = "application/json"
  ngx.print(cjson.encode(response))
  exit(0)
end


function _M.init_worker()
  assert(SHM, "doorbell was not initialized")

  require("resty.jit-uuid").seed()

  if proc.type() == "privileged agent" then
    return init_agent()
  end

  return init_worker()
end

function _M.reload()
  local ctx = ngx.ctx
  request.no_log(ctx)
  request.no_metrics(ctx)

  assert(SHM, "doorbell was not initialized")
  if get_method() ~= "POST" then
    return exit(HTTP_NOT_ALLOWED)
  end
  header["content-type"] = "text/plain"
  local ok, err = rules.load(config.save_path, false)
  if ok then
    say("success")
    return exit(HTTP_CREATED)
  end
  log.err("failed reloading rules from disk: ", err)
  say("failure")
  exit(HTTP_INTERNAL_SERVER_ERROR)
end

function _M.metrics()
  local ctx = ngx.ctx
  request.no_log(ctx)
  request.no_metrics(ctx)

  metrics.collect()
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

function _M.shm_api()
  assert(SHM, "doorbell was not initialized")
  ip.require_trusted(ngx.ctx)

  local zone, key = var.zone, var.key
  log.debugf("zone: %s, key: %s", zone, key)
  if key == "" then
    key = nil
  end
  if zone == "" then
    zone = nil
  end

  local res, err
  if not zone then
    res = {}
    for name in pairs(ngx.shared) do
      table.insert(res, name)
    end
  elseif not key then
    local shm = ngx.shared[zone]
    if shm then
      res, err = shm:get_keys(0)
    end
  else
    local shm = ngx.shared[zone]
    if shm then
      res, err = shm:get(key)
      if res ~= nil then
        local json, jerr = safe_decode(res)
        if jerr == nil then
          res = json
        end
      end
    end
  end

  ngx.status = (res ~= nil and 200) or 404
  header["content-type"] = "application/json"
  if res == nil then
    res = err
  end
  ngx.say(cjson.encode(res))
  ngx.exit(0)
end

return _M
