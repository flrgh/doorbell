---@class doorbell.verify
local _M = {}

local twilio = require "doorbell.verify.twilio"
local const = require "doorbell.constants"
local http = require "doorbell.http"
local users = require "doorbell.users"
local rules = require "doorbell.rules.api"
local mail = require "doorbell.mail"
local shm  = require "doorbell.shm"

local log = require("doorbell.log").with_namespace("verify")
local SHM = shm.with_namespace("verify")
local ALLOW_TTL = 60 * 60 * 24

local sleep = ngx.sleep
local rand = math.random
local fmt = string.format

local function delay()
  sleep(rand(1, 2) + rand())
end

local function random_code()
  return fmt("%s%s%s%s%s%s",
             rand(0, 9),
             rand(0, 9),
             rand(0, 9),
             rand(0, 9),
             rand(0, 9),
             rand(0, 9))
end


local HTML = [[
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Request Access for %s</title>
    <link rel="icon" href="/public/favicon.svg"/>
    <link rel="stylesheet" href="/public/verify.css">
</head>
<body>
    <div class="container">
        <h1>Request Access for %s</h1>
        <div id="initial-step">
            <div>
                <label for="verification-method">Choose a verification method:</label>
                <select id="verification-method" onchange="showInputField()">
                    <option value="" disabled selected>Select an option</option>
                    <option value="email">Email</option>
                    <option value="phone">Phone</option>
                </select>
            </div>
            <div id="input-field"></div>
            <input type="hidden" id="csrf" value="%s">
            <button id="send-button" onclick="sendVerification()" disabled class="disabled">Send</button>
        </div>

        <div id="verification-step" class="hidden">
            <p id="verification-message"></p>
            <label for="verification-code">Enter the verification code:</label>
            <input type="text" inputmode="numeric" pattern="\d*" id="verification-code" maxlength="16">
            <button onclick="verifyCode()">Verify Code</button>
        </div>
        <div id="spinner" class="spinner hidden"></div>
        <div id="result" class="error hidden"></div>
    </div>
    <script src="/public/verify.js"></script>
</body>
</html>
]]

local ENABLED = false

---@class doorbell.verify.args
---
---@field method "phone"|"email"
---@field value  string
---@field csrf   string
---@field code   string

---@param status integer
---@param message string
---@param extra? table
local function send_json(status, message, extra)
  local res
  if extra then
    res = extra

  else
    res = {}
  end

  res.message = message
  return http.send(status, res)
end

---@param ctx doorbell.ctx
local function show_form(ctx)
  local addr = ctx.forwarded_addr or ctx.client_addr
  local csrf = http.csrf.generate()

  http.response.set_header(http.headers.CONTENT_TYPE, http.types.HTML)
  return http.send(200, HTML:format(addr, addr, csrf))
end

---@class doorbell.verify.email.verification
---
---@field email      string
---@field created_at number
---@field addr       string
---@field code       string

---@param addr string
---@param mode "email"|"phone"
---@param value string
---@param user doorbell.config.auth.user
---@return doorbell.rule?
---@return string? error
local function add_rule(addr, mode, value, user)
  local meta = {
    ["verify.user.name"] = user.name,
    ["verify.user.identifier"] = value,
    ["verify.user.identifier.type"] = mode,
  }

  local created, err, _, conflict = rules.insert({
    addr = addr,
    action = "allow",
    source = "user",
    meta = meta,
    ttl = ALLOW_TTL,
  })

  if created then
    return created

  elseif not conflict then
    return nil, err
  end

  assert(conflict.addr == addr)

  if conflict.expires == 0 then
    log.noticef("tried to create addr(%s) allow rule for user(%s) via %s(%s)"
             .. " but a permanent allow rule already exists (id: %s)",
                addr,
                user.name,
                mode, value,
                conflict.id)

    -- try to update the meta just because, but we don't care if this fails
    rules.patch(conflict.id, {
      meta = meta,
    })

    return conflict
  end

  log.infof("updating addr(%s) allow rule %s for user(%s) via %s(%s)",
            addr,
            conflict.id,
            user.name,
            mode, value)

  return rules.patch(conflict.id, {
    ttl = ALLOW_TTL,
    meta = meta,
  })
end

---@param ctx doorbell.ctx
---@param args doorbell.verify.args
local function verify_email(ctx, args)
  local email = assert(args.value)
  local user = users.get_by_email(email)

  if not user then
    delay()
    return send_json(400, "cannot do that")
  end

  local key = "email: " .. email:lower()

  local code = args.code

  -- verify
  if code then
    ---@type doorbell.verify.email.verification|nil
    local task = SHM:get(key)

    if not task then
      delay()
      return send_json(400, "cannot do that")
    end

    if task.code ~= code then
      delay()
      return send_json(400, "cannot do that")
    end

    SHM:delete(key)
    local rule, err = add_rule(task.addr, "email", email, user)

    if rule then
      return send_json(200, "success, access granted")

    else
      log.warn("failed creating allow rule for ", email, ": ", err)
      return send_json(500, "something went wrong")
    end

  -- generate code
  else
    ---@type doorbell.verify.email.verification
    local task = {
      email = email,
      created_at = ngx.now(),
      addr = ctx.forwarded_addr or ctx.client_addr,
      code = random_code(),
    }

    assert(SHM:add(key, task))

    local ok, err = mail.send({
      subject = "Your doorbell verification code",
      to = { email },
      text = "Your code is: " .. task.code .. "\n",
    })

    if ok then
      return send_json(201, "Verification code sent. Please check your email.", {
        code_length = 6,
        csrf = http.csrf.generate(),
      })

    else
      SHM:delete(key)
      log.warn("failed creating verification task for ", email, ": ", err)
      return send_json(500, "something went wrong")
    end
  end
end


---@param ctx doorbell.ctx
---@param args doorbell.verify.args
local function verify_phone(ctx, args)
  if not twilio.enabled() then
    return send_json(400, "cannot do that")
  end

  local tel = users.validate.tel(args.value)

  if not tel then
    return send_json(400, "invalid telephone number")
  end

  local user = users.get_by_phone_number(tel)
  if not user then
    delay()
    return send_json(400, "invalid telephone number")
  end

  -- check verify
  if args.code then
    local code = tostring(args.code)
    local task, err = twilio.check_verify(tel, code)

    if not task then
      log.notice("verification of ", tel, " failed: ", err)
      delay()
      return send_json(500, "something went wrong")
    end

    local rule
    rule, err = add_rule(task.addr, "phone", tel, user)

    if rule then
      return send_json(200, "success, access granted")

    else
      log.warn("failed creating allow rule for ", tel, ": ", err)

      return send_json(500, "something went wrong")
    end

  -- new verify
  else
    local addr = ctx.forwarded_addr or ctx.client_addr
    local task, err = twilio.new_verify_task(tel, addr)
    if task then
      return send_json(201, "Verification code sent. Please check your phone.", {
        code_length = 6,
        csrf = http.csrf.generate(),
      })

    else
      log.err("failed creating verification task for ", tel, ": ", err)

      delay()
      return send_json(500, "oops")
    end
  end
end


---@param ctx doorbell.ctx
local function verify_user(ctx)
  ---@type doorbell.verify.args
  local args = http.request.get_json_body("table", false)

  if not args.csrf or not http.csrf.validate(args.csrf) then
    delay()
    return send_json(400, "invalid request")
  end

  if not args.method or not args.value then
    return send_json(400, "invalid request data")
  end

  if args.method == "phone" then
    return verify_phone(ctx, args)

  elseif args.method == "email" then
    return verify_email(ctx, args)

  else
    delay()
    return send_json(400, "unknown verification method")
  end
end

---@param conf doorbell.config
function _M.init(conf)
  if conf.twilio then
    twilio.init(conf.twilio)
    ENABLED = true
  end

  if conf.smtp then
    ENABLED = true
  end

  if ENABLED then
    local mw = require "doorbell.middleware"
    local router = require "doorbell.router"

    router.add(const.endpoints.verify, {
      id = "verify",
      description = "user verification",
      metrics_enabled = true,
      auth_strategy = require("doorbell.auth").require_none(),
      GET = show_form,
      POST = verify_user,
      middleware = {
        [mw.phase.PRE_HANDLER] = {
          http.request.middleware.rate_limit(function(ctx)
            if ctx.method ~= "POST" then return end
            local addr = ctx.forwarded_addr
            if not addr then return end
            return "global:" .. addr, 10, 10 -- ~1 req/sec
          end)
        },
      },
    })

    local ring = require "doorbell.auth.ring"

    ring.add_hook("allow-verify", function(req, _, state)
      if state ~= const.states.deny and req.path == const.endpoints.verify then
        return const.states.allow
      end
    end)
  end
end

return _M
