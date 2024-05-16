local log     = require "doorbell.log"
local http    = require "doorbell.http"
local request = require "doorbell.request"
local users   = require "doorbell.users"
local email   = require "doorbell.auth.email"
local rules = require "doorbell.rules.api"

local fmt = string.format

local CHECK_YOUR_EMAILS = [[<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Check Your Email</title>
    <style>
        body, html {
            height: 100%;
            margin: 0;
            font-family: Arial, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            background-color: #f4f4f4;
        }
        .container {
            text-align: center;
            padding: 20px;
            background: white;
            border-radius: 8px;
            box-shadow: 0 4px 8px rgba(0,0,0,0.1);
            width: 90%;
            max-width: 600px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Please check your email</h1>
        <p>We've sent a verification link to your email address. Please click on that link to proceed.</p>
    </div>
</body>
</html>
]]


local function plain_error(status, body)
  ngx.sleep(1)
  return http.send(status, body)
end

local function html_error(status, tpl, env, msg)
  ngx.sleep(1)
  env.error_message = msg
  return http.send(status, tpl(env), {
    ["content-type"] = "text/html",
  })
end


---@class doorbell.view.email-validate.env
---
---@field request_email boolean
---@field addr? string
---@field addr_is_current? boolean
---@field state_token? string
---@field error_message? string
---@field validated_email? boolean

---@type doorbell.view
---@param ctx doorbell.ctx
return function(ctx)
  local method = ctx.method

  local secret = request.get_query_arg(ctx, "v")
  local current_addr = ctx.forwarded_addr or ctx.client_addr

  local env = {
    addr = current_addr,
  }

  if method == "GET" then
    env.csrf_token = http.csrf.generate()

    -- returning from clicking the validation link in an email
    if secret then
      env.validated_email = true
      env.need_finalize = true

    else
      env.need_email = true
      env.state_token = request.get_query_arg(ctx, "s")

      -- got here via redirect
      if env.state_token then
        local state = email.get(env.state_token)

        if not state then
          return plain_error(400, "what're you even doing?")
        end

        env.addr = state.addr

      -- explicitly navigated to the email validation page
      else
        local state = email.incoming(current_addr)
        env.state_token = state.token
      end
    end

    return http.send(200, ctx.template(env), {
      ["content-type"] = "text/html",
    })

  elseif method == "POST" then
    local args = http.request.get_post_args(true)

    local csrf_token = args.csrf_token
    if not csrf_token then
      log.info("got a POST request without a CSRF token")
      return plain_error(400, "you did something wrong")

    elseif not http.csrf.validate(csrf_token) then
      log.info("got a POST request with an invalid CSRF token")
      return plain_error(400, "you did something wrong")
    end

    -- final step!
    if secret then
      local state = email.get_by_secret(secret)

      if not state then
        return html_error(400, ctx.template, env,
                          "I don't recognize you")
      end

      local ok, err = rules.insert({
        addr = state.addr,
        action = "allow",
        source = "user",
        comment = fmt("via email for %s", state.email),
        ttl = 24 * 60 * 60,
      })

      email.teardown(state)

      if ok then
        log.info("created allow rule for ", state.email)

        env.access_granted = true

        return http.send(200, ctx.template(env), {
          ["content-type"] = "text/html",
        })
      else
        log.err("failed creating allow rule: ", err)
        return html_error(400, ctx.template, env,
                          "internal server error")
      end

    else
      if not args.email then
        return plain_error(400, "you gotta include your email dude")
      end

      local user = users.get_by_email(args.email)
                or users.get_by_email(args.email:lower())

      if not user then
        log.notice("got an email validation request for an unknown email address: ",
                   args.email)

        -- not gonna tell 'em the real reason
        local msg = "Oops, something went wrong."
        return html_error(500, ctx.template, env, msg)
      end

      log.info("incoming email validation request for ", args.email)

      local state_token = args.state_token
                       or request.get_query_arg(ctx, "s")

      if not state_token then
        return html_error(400, ctx.template, env,
                          "invalid request, please try again")
      end

      local state = email.get(state_token)

      if not state then
        return html_error(400, ctx.template, env,
                          "invalid request, please try again")
      end

      state.email = args.email
      local ok, err = email.send_email(state)
      if ok then
        return http.send(200, CHECK_YOUR_EMAILS, {
          ["content-type"] = "text/html",
        })

      else
        log.errf("failed sending email to %s: %s", args.email, err)
        return html_error(400, ctx.template, env,
                          "internal server error")
      end
    end

  else
    return http.send(405, "you can't do that!")
  end
end
