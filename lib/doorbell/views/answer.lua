local log     = require "doorbell.log"
local const   = require "doorbell.constants"
local access  = require "doorbell.auth.access"
local ip      = require "doorbell.ip"
local notify  = require "doorbell.notify"
local http    = require "doorbell.http"
local request = require "doorbell.request"
local util    = require "doorbell.util"

local var = ngx.var
local fmt = string.format
local EMPTY = {}

local SCOPES = const.scopes
local PERIODS = const.periods

---@param req doorbell.forwarded_request
local function render_form(tpl, req, errors, current)
  local info = ip.get_ip_info(req.addr) or EMPTY

  return tpl({
    req = {
      { "addr",         req.addr         },
      { "country",      info.country     },
      { "state/region", info.region      },
      { "city",         info.city        },
      { "zip",          info.postal_code },

      { "user-agent",   req.ua           },
      { "host",         req.host         },
      { "method",       req.method       },
      { "uri",          req.uri          },
    },
    errors      = errors or {},
    current_ip  = current,
    map_link    = info.map_link,
    search_link = info.search_link,
  })
end


---@type doorbell.view
---@param ctx doorbell.ctx
return function(ctx)
  local t = request.get_query_arg(ctx, "t")
  if not t then
    log.notice("/answer accessed with no token")
    return http.send(400)
  end

  if t == "TEST" then
    ---@type doorbell.forwarded_request
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

    local errors = request.get_query_arg(ctx, "errors")
    if util.truthy(errors) then
      errors = { "error: invalid action 'nope'" }
    end

    local current_ip = util.truthy(request.get_query_arg(ctx, "current"))
                    or false

    http.send(200,
              render_form(ctx.template, req, errors, current_ip),
              { ["content-type"] = "text/html" })
  end

  local approval = access.get_pending_approval(t)

  if not approval then
    log.noticef("/answer token %s not found", t)
    return http.send(404)
  end

  local req = approval.request

  req.url = req.scheme .. "://" .. req.host .. req.uri

  local method = ngx.req.get_method()
  if not (method == "GET" or method == "POST") then
    return http.send(400)
  end

  local current_ip = req.addr == var.http_x_forwarded_for

  if method == "GET" then
    return http.send(200,
                     render_form(ctx.template, req, nil, current_ip),
                     { ["content-type"] = "text/html" })
  end

  ngx.req.read_body()
  local args = ngx.req.get_post_args()

  if args.action == "approve" then
    args.action = "allow"
  end


  ---@type doorbell.auth.access.api.intent
  local ans = {
    action  = args.action,
    token   = approval.token,
    scope   = args.scope,
    subject = args.subject,
    ttl     = PERIODS[args.period] or args.period,
    renew   = args.renew == "on",
  }


  local status, err, rule = access.answer(ans)

  if status >= 500 then
    log.errf("POST /answer failed to insert rule: %s", err)
    return http.send(500)

  elseif status >= 400 then
    log.noticef("POST /answer invalid form input: %s", err)
    return http.send(400,
                     render_form(ctx.template, req, { err }, current_ip),
                     { ["content-type"] = "text/plain" })

  else
    assert(status == 201, "unexpected status: " .. tostring(status))
  end

  notify.inc("answered")

  local msg = fmt("%s access for %q to %s %s",
                  (rule.action == "allow" and "Approved")
                  or "Denied",

                  (rule.addr or rule.ua),

                  (ans.scope == SCOPES.global and "all apps.")
                  or (ans.scope == SCOPES.host and req.host)
                  or req.url,

                  (ans.ttl == PERIODS.forever and "for all time")
                  or ("for one " .. args.period)
  )

  return http.send(201, msg, { ["content-type"] = "text/plain" })
end
