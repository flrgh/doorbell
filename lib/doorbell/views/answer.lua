local rules = require "doorbell.rules"
local log = require "doorbell.log"
local const = require "doorbell.constants"
local auth = require "doorbell.auth"
local metrics = require "doorbell.metrics"

local var = ngx.var
local header = ngx.header


local SCOPES = const.scopes
local SUBJECTS = const.subjects
local PERIODS = const.periods

---@param req doorbell.request
local function render_form(tpl, req, errors, current)
  return tpl({
    req = {
      { "addr",   req.addr    },
      { "country", req.country },
      { "user-agent",   req.ua     },
      { "host",         req.host   },
      { "method",       req.method },
      { "uri",          req.uri    },
    },
    errors = errors or {},
    current_ip = current,
  })
end


---@type doorbell.view
---@param ctx doorbell.ctx
return function(ctx)
  local t = var.arg_t
  if not t then
    log.notice("/answer accessed with no token")
    return ngx.exit(ngx.HTTP_NOT_FOUND)
  end

  if t == "TEST" then
    ---@type doorbell.request
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

    local errors
    if var.arg_errors then
      errors = { "error: invalid action 'nope'" }
    end

    local current_ip = (var.arg_current and true) or false

    header["content-type"] = "text/html"
    ngx.print(render_form(ctx.template, req, errors, current_ip))
    return ngx.exit(ngx.HTTP_OK)
  end

  local req = auth.get_token_address(t)

  if not req then
    log.noticef("/answer token %s not found", t)
    return ngx.exit(ngx.HTTP_NOT_FOUND)
  end

  req.url = req.scheme .. "://" .. req.host .. req.uri

  local method = ngx.req.get_method()
  if not (method == "GET" or method == "POST") then
    ngx.exit(ngx.HTTP_BAD_REQUEST)
  end

  local current_ip = req.addr == var.http_x_forwarded_for

  if method == "GET" then
    header["content-type"] = "text/html"
    print(render_form(ctx.template, req, nil, current_ip))
    return ngx.exit(ngx.HTTP_OK)
  end

  ngx.req.read_body()
  local args = ngx.req.get_post_args()
  local action = args.action or "NONE"
  local scope = args.scope or "NONE"
  local period = args.period or "NONE"
  local subject = args.subject or "NONE"

  local err

  if not (action == "approve" or action == "deny") then
    err = "invalid action: " .. tostring(action)
  elseif not SCOPES[scope] then
    err = "invalid scope: " .. tostring(scope)
  elseif not PERIODS[period] then
    err = "invalid period: " .. tostring(period)
  elseif not SUBJECTS[subject] then
    err = "invalid subject: " .. tostring(subject)
  end

  if err then
    header["content-type"] = "text/html"
    print(render_form(ctx.template, req, { err }, current_ip))
    return ngx.exit(ngx.HTTP_BAD_REQUEST)
  end

  local terminate = false
  local host, path = req.host, req.path
  if scope == SCOPES.global then
    host = nil
    path = nil
    terminate = true
  elseif scope == SCOPES.host then
    path = nil
  end

  local addr, ua = req.addr, req.ua
  if subject == SUBJECTS.addr then
    ua = nil
  elseif subject == SUBJECTS.ua then
    addr = nil
  end

  local rule = {
    action    = (action == "approve" and "allow") or "deny",
    source    = "user",
    addr      = addr,
    host      = host,
    path      = path,
    ua        = ua,
    ttl       = PERIODS[period],
    terminate = terminate,
  }

  assert(rules.add(rule))

  metrics.notify:inc(1, {"answered"})

  auth.set_pending(req.addr, false)

  local msg = fmt(
    "%s access for %q to %s %s",
    (action == "approve" and "Approved") or "Denied",
    (addr or ua),
    (scope == SCOPES.global and "all apps.") or (scope == SCOPES.host and req.host) or req.url,
    (PERIODS[period] == PERIODS.forever and "for all time") or ("for one " .. period)
  )

  header["content-type"] = "text/plain"
  ngx.say(msg)
  return ngx.exit(ngx.HTTP_CREATED)
end
