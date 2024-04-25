local log     = require "doorbell.log"
local const   = require "doorbell.constants"
local access  = require "doorbell.auth.access"
local ip      = require "doorbell.ip"
local notify  = require "doorbell.notify"
local http    = require "doorbell.http"
local request = require "doorbell.request"
local util    = require "doorbell.util"
local users   = require "doorbell.users"
local validate   = require "doorbell.policy.validate-by-email"

local var = ngx.var
local fmt = string.format
local EMPTY = {}

local SCOPES = const.scopes
local PERIODS = const.periods

local function tarpit_delay()
  ngx.sleep(math.random(3, 6) + math.random())
end

---@type doorbell.view
---@param ctx doorbell.ctx
return function(ctx)
  local method = ngx.req.get_method()

  if method == "GET" then
    local v = request.get_query_arg(ctx, "v")

    if v then
      local ok, err = v.validate(ctx, v)
      if not ok then
        log.info("failed to process email validation: ", err)
        tarpit_delay()
        return http.send(404)
      end

      -- returning from email validation link
      local html = ctx.template({
        validated = true,
      })
      return http.response.new()
        :status(200)
        :body(html)
        :header("Content-Type", "text/html")
        :send()

    else
      -- redirect from an unauthorized access attempt
      local html = ctx.template({})
      return http.response.new()
        :status(200)
        :body(html)
        :header("Content-Type", "text/html")
        :send()
    end

  elseif method == "POST" then
    local args = http.request.get_post_args(false)

    local email = args.email

    if not email then
      tarpit_delay()
      return http.send(400, "email address is required")
    end

    local ok, err = validate.send_validation_email(email)
    if not ok then
      log.info("could not validate email or send message to ", email, ", ", err)
      tarpit_delay()
    end

    local html = ctx.template({
      form_filled = true,
    })
    return http.response.new()
      :status(200)
      :body(html)
      :header("Content-Type", "text/html")
      :send()


  else
    tarpit_delay()
    return http.send(400)
  end
end
