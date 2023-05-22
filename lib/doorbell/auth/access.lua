---@class doorbell.auth.access
local _M = {}

local const   = require "doorbell.constants"
local log     = require "doorbell.log"
local rules   = require "doorbell.rules.manager"
local notify  = require "doorbell.notify"
local util    = require "doorbell.util"
local schema  = require "doorbell.schema"
local api     = require "doorbell.rules.api"

local random     = require "resty.random"
local str        = require "resty.string"
local buffer     = require "string.buffer"
local bit        = require "bit"

local encode   = buffer.encode
local decode   = buffer.decode
local fmt      = string.format
local now      = ngx.now
local sleep    = ngx.sleep
local band     = bit.band


local TTL_PENDING = const.ttl.pending
local APPROVALS   = require("doorbell.shm").approvals
local PENDING     = require("doorbell.shm").pending
local WAIT_TIME   = const.wait_time
local STATES      = const.states
local SCOPES      = const.scopes
local SUBJECTS    = const.subjects

local base_url

---@type doorbell.config.approvals
local approvals

---@type string
local E_ALLOWED_TTL
---@type string
local E_ALLOWED_SCOPES
---@type string
local E_ALLOWED_SUBJECTS

---@type table<string, true>
local ALLOWED_SUBJECTS

---@type table<string, true>
local ALLOWED_SCOPES


---@param subject string
---@param fn function
---@param ... any
---@return any ...
local function with_lock(subject, fn, ...)
  local lock, err = util.lock("addr", subject, "auth-request")

  if not lock then
    return STATES.error, "failed to acquire lock: " .. tostring(err)
  end

  local a, b, c, d = fn(...)

  lock:unlock()

  return a, b, c, d
end


---@alias doorbell.auth.access.pending.type
---| "pre-approved"
---| "pending"
---| "none"

-- bitflags for shm
local F_PENDING      = bit.tobit(1)
local F_PRE_APPROVED = bit.lshift(F_PENDING, 1)


---@param flags integer
---@param flag integer
---@return boolean
local function is_set(flags, flag)
  return band(flags or 0, flag) == flag
end


---@param flags integer
---@return doorbell.auth.access.pending.type
local function state_type(flags)
  if is_set(flags, F_PENDING) then
    return STATES.pending

  elseif is_set(flags, F_PRE_APPROVED) then
    return STATES.pre_approved
  end

  return STATES.none
end


---@param req doorbell.auth.access.api.intent|doorbell.auth.access.api.pre-approval
---@return boolean? ok
---@return string? error
local function validate_allowed_limits(req)
  if not ALLOWED_SUBJECTS[req.subject] then
    return nil, E_ALLOWED_SUBJECTS
  end

  if not ALLOWED_SCOPES[req.scope] then
    return nil, E_ALLOWED_SCOPES
  end

  if approvals.max_ttl > 0 then
    if req.ttl == 0 or req.ttl > approvals.max_ttl then
      return nil, E_ALLOWED_TTL
    end
  end

  return true
end

---@alias doorbell.auth.pending.state
---| doorbell.auth.access.pending
---| doorbell.auth.access.pre-approval


---@param typ doorbell.subject
---@param subject string
---@return doorbell.auth.access.state
---@return string|nil
local function check_state(typ, subject)
  local res, flags = PENDING:get(typ .. ":" .. subject)

  if res then
    return state_type(flags), res
  end

  return STATES.none
end


---@param  typ      doorbell.subject
---@param  subject    string
---@return boolean pending
---@return string? token
local function is_pending(typ, subject)
  local state, res = check_state(typ, subject)

  if state == STATES.pending then
    return true, res
  end

  return false
end

_M.is_pending = is_pending


---@param typ doorbell.subject
---@param subject string
local function clear_pending_state(typ, subject)
  local key = typ .. ":" .. subject
  local token = PENDING:get(key)

  assert(PENDING:set(key, nil))

  if token then
    assert(APPROVALS:set(token, nil))
  end
end

---@param typ     doorbell.subject
---@param subject string
---@param token   string
local function set_pending(typ, subject, token)
  assert(PENDING:safe_set(typ .. ":" .. subject,
                          token,
                          TTL_PENDING,
                          F_PENDING))
end

---@param typ     doorbell.subject
---@param subject string
---@param token   string
local function set_pre_approved(typ, subject, token)
  local ttl = approvals.pre_approval_ttl

  local key = typ .. ":" .. subject
  local current, flags = PENDING:get(key)

  assert(PENDING:safe_set(key,
                          token,
                          ttl,
                          F_PRE_APPROVED))

  if current then
    local state = state_type(flags)
    log.debug("replacing existing '", state, "' state for ", key)
    assert(APPROVALS:set(current, nil))
  end
end

---@param token string
---@return doorbell.auth.access.pending?
---@return string? error
local function get_pending_approval(token)
  local v, flags = APPROVALS:get(token)
  if v and is_set(flags, F_PENDING) then
    return decode(v)
  end
end


---@param token string
---@return doorbell.auth.access.pre-approval?
local function get_pre_approval(token)
  local v, flags = APPROVALS:get(token)
  if v and is_set(flags, F_PRE_APPROVED) then
    return decode(v)
  end
end



_M.set_pending = set_pending


---@param params doorbell.rule.new.opts
---@param req doorbell.forwarded_request
---@param pre doorbell.auth.access.pre-approval
local function create_rule_for_pre_approval(params, req, pre)
  local rule, err = api.insert(params)

  if not rule then
    return nil, "failed creating rule for pre-approved access: " .. tostring(err)
  end

  if req.addr then
    clear_pending_state(SUBJECTS.addr, req.addr)
  end

  if req.ua then
    clear_pending_state(SUBJECTS.ua, req.ua)
  end

  APPROVALS:set(pre.token, nil)

  return true
end


---@param req doorbell.forwarded_request
---@param token string
---@return doorbell.auth.access.state state
local function handle_pre_approval(req, token)
  local pre = get_pre_approval(token)

  if not pre then
    return STATES.error
  end

  local addr, host, ua, path

  if pre.subject == SUBJECTS.ua then
    ua = assert(req.ua)

  else
    assert(pre.subject == SUBJECTS.addr)
    addr = req.addr
  end

  if pre.scope == SCOPES.url then
    host = req.host
    path = req.path

  elseif pre.scope == SCOPES.host then
    host = req.host

  else
    assert(pre.scope == SCOPES.global)
  end

  local params = {
    action  = "allow",
    source  = const.sources.user,
    ttl     = pre.ttl,
    addr    = addr,
    ua      = ua,
    host    = host,
    path    = path,
    comment = "pre-approved access",
  }

  local ok, err = with_lock(req.addr, create_rule_for_pre_approval,
                            params, req, pre)

  if not ok then
    log.err(err)
    return STATES.error
  end

  return STATES.allow
end


---@param req doorbell.forwarded_request
---@return doorbell.auth.access.state state
---@return string? error
---@return string? token
local function get_state(req, ctx)
  local rule, cached = rules.match(req)
  if rule then
    if ctx then
      ctx.rule = rule
      ctx.rule_cache_hit = cached
    end
    return rule.action
  end

  local pend, token = check_state(SUBJECTS.addr, req.addr)

  if pend == "none" and req.ua then
    pend, token = check_state(SUBJECTS.ua, req.ua)
  end


  if pend == "none" then
    return STATES.none

  elseif pend == "pending" then
    return STATES.pending, nil, token

  elseif pend == "pre-approved" then
    return handle_pre_approval(req, token)

  else
    error("unreachable!")
  end
end

_M.get = get_state


---@param item doorbell.auth.access.pending|doorbell.auth.access.api.pre-approval
---@param flags integer
---@return string? token
---@return string? error
local function generate_request_token(item, flags)
  local bytes = random.bytes(24, true)
  local token = str.to_hex(bytes)

  item.created = now()
  item.token = token

  local item_ttl

  if is_set(flags, F_PENDING) then
    item_ttl = TTL_PENDING
    item.state = STATES.pending

  else
    assert(is_set(flags, F_PRE_APPROVED))
    item_ttl = approvals.pre_approval_ttl
    item.state = STATES.pre_approved
  end

  item.expires = ngx.now() + item_ttl

  local value = encode(item)
  local ok, err = APPROVALS:safe_add(token, value, item_ttl, flags)

  if not ok then
    return nil, err
  end

  return token
end


_M.get_pending_approval = get_pending_approval

---@param req doorbell.forwarded_request
---@param timeout? number
function _M.await(req, timeout)
  timeout = timeout or WAIT_TIME
  local deadline = now() + timeout

  while now() < deadline and is_pending("addr", req.addr) do
    sleep(0.25)
  end

  if is_pending("addr", req.addr) then
    return false
  end

  local state = get_state(req)

  if state == STATES.allow then
    return true

  elseif state == STATES.deny then
    return false
  end
end



---@param req doorbell.forwarded_request
---@param token string
local function send_notification(req, token)
  if not notify.enabled() then
    return

  elseif not notify.in_notify_period() then
    log.notice("not sending request outside of notify hours for ", req.addr)
    notify.inc("snoozed")
    return
  end

  local url = fmt("%s/answer?t=%s", base_url, token)

  local sent, err = notify.ring(req, url)

  if not sent then
    log.err("failed sending auth request: ", err)
    notify.inc("failed")
  else
    notify.inc("sent")
  end
end



---@param req doorbell.forwarded_request
---@return doorbell.auth.access.state? state
---@return string? error
---@return string? token
local function create_access_request(req)
  local addr = req.addr
  local pending, token = is_pending("addr", addr)

  if pending then
    log.notice("access for ", addr, " is already waiting on a pending request")
    return STATES.pending, nil, token

  else
    local rule = rules.match(req)
    local state = (rule and rule.action)

    if state == STATES.allow then
      log.debug("acccess for ", addr, " was allowed before requesting it")
      return STATES.allow

    elseif state == STATES.deny then
      log.notice("access was denied for ", addr, " before requesting it")
      return STATES.deny
    end
  end

  local err
  token, err = generate_request_token({
    request = req,
  }, F_PENDING)

  if not token then
    return STATES.error, "failed creating auth request token for "
                         .. addr .. ": " .. tostring(err)
  end

  set_pending("addr", addr, token)

  send_notification(req, token)

  return STATES.pending, nil, token
end



---@param req doorbell.forwarded_request
---@return doorbell.auth.access.state state
---@return string? token
function _M.new_access_request(req)
  local addr = req.addr

  local state, err, token = with_lock(addr, create_access_request, req)

  if not state or err then
    state = STATES.error
    log.err(err)
  end

  return state, token
end


---@param req doorbell.forwarded_request
---@return boolean
function _M.request(req)
  local addr = req.addr
  local state, err = with_lock(addr, create_access_request, req)
  if not state then
    log.err(err)
  end

  return state == STATES.pending
      or state == STATES.allow
      or state == STATES.pre_approved
end


---@param conf doorbell.config
function _M.init(conf)
  base_url = conf.base_url
  approvals = conf.approvals

  ALLOWED_SCOPES = util.lookup_from_values(approvals.allowed_scopes)
  ALLOWED_SUBJECTS = util.lookup_from_values(approvals.allowed_subjects)

  E_ALLOWED_TTL = fmt("ttl must be <= %s", approvals.max_ttl)
  E_ALLOWED_SUBJECTS = fmt("subject must be one of: %s",
                           table.concat(approvals.allowed_subjects, ", "))
  E_ALLOWED_SCOPES = fmt("scope must be one of: %s",
                           table.concat(approvals.allowed_scopes, ", "))
end


---@param state doorbell.auth.access.state
---@return doorbell.auth.access.pending[]
function _M.list_approvals(state)
  local keys = assert(APPROVALS:get_keys(0))
  local values = {}
  local c = 0

  for _, key in ipairs(keys) do
    local value, flags = APPROVALS:get(key)
    if value and state_type(flags) == state then
      c = c + 1
      values[c] = decode(value)
    end
  end

  return values
end


---@param pre doorbell.auth.access.api.pre-approval
---@param typ "ua"|"addr"
---@param subject string
local function create_pre_approval(pre, typ, subject)
  local token, err = generate_request_token(pre, F_PRE_APPROVED)
  if not token then
    return nil, err
  end

  set_pre_approved(typ, subject, token)

  log.notice("created ", pre.scope, " pre-approval for ", pre.subject, " ", subject)

  return true
end



---@param pre doorbell.auth.access.api.pre-approval
---@param req table
---@return integer status
---@return string? error
function _M.pre_approve(pre, req)
  local ok, err = schema.auth.access.api.pre_approval.validate(pre)

  if not ok then
    return 400, err
  end

  ok, err = validate_allowed_limits(pre)
  if not ok then
    return 400, err
  end

  local stype = pre.subject
  local subject = req[stype]

  if subject == nil then
    return 400, "empty subject"
  end

  ok, err = with_lock(req.addr, create_pre_approval, pre, stype, subject)
  if not ok then
    log.err(err)
    return 500, err
  end

  return 201
end



---@param ans doorbell.auth.access.api.intent
---@return integer status
---@return string? error
---@return doorbell.rule? rule
function _M.answer(ans)
  local ok, err = schema.auth.access.api.intent.validate(ans)

  if not ok then
    return 400, err
  end

  ok, err = validate_allowed_limits(ans)
  if not ok then
    return 400, err
  end

  local req = get_pending_approval(ans.token)
  if not req then
    return 404, "Not Found"
  end

  local addr, host, path, ua

  if ans.scope == SCOPES.host then
    host = req.request.host

  elseif ans.scope == SCOPES.url then
    host = req.request.host
    path = req.request.path

  else
    assert(ans.scope == SCOPES.global)
  end


  if ans.subject == SUBJECTS.addr then
    addr = req.request.addr

  else
    assert(ans.subject == SUBJECTS.ua)
    ua = req.request.ua
  end


  local rule, status
  rule, err, status = api.insert({
    action    = ans.action,
    addr      = addr,
    host      = host,
    path      = path,
    ttl       = ans.ttl,
    ua        = ua,
    source    = const.sources.api,
    terminate = ans.scope == SCOPES.global,
  })

  if not rule then
    return status, err
  end

  if req.request.addr then
    log.noticef("Clearing pending state for addr: %s", req.request.addr)
    clear_pending_state(SUBJECTS.addr, req.request.addr)
  end

  if ua and req.request.ua then
    log.noticef("Clearing pending state for user-agent: %q", req.request.ua)
    clear_pending_state(SUBJECTS.ua, req.request.ua)
  end

  assert(APPROVALS:set(ans.token, nil))

  return 201, nil, rule
end

return _M
