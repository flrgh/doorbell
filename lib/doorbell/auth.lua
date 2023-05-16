local _M = {
  _VERSION = require("doorbell.constants").version,
}

local const   = require "doorbell.constants"
local log     = require "doorbell.log"
local rules   = require "doorbell.rules.manager"
local notify  = require "doorbell.notify"
local util    = require "doorbell.util"
local schema  = require "doorbell.schema"
local api     = require "doorbell.rules.api"

local random     = require "resty.random"
local str        = require "resty.string"
local cjson      = require "cjson"

local encode   = cjson.encode
local decode   = cjson.decode
local fmt      = string.format
local now      = ngx.now
local sleep    = ngx.sleep


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



---@param ans doorbell.auth.approval.answer
---@return boolean? ok
---@return string? error
local function validate_allowed_limits(ans)
  if not ALLOWED_SUBJECTS[ans.subject] then
    return nil, E_ALLOWED_SUBJECTS
  end

  if not ALLOWED_SCOPES[ans.scope] then
    return nil, E_ALLOWED_SCOPES
  end

  if approvals.max_ttl > 0 then
    if ans.ttl == 0 or ans.ttl > approvals.max_ttl then
      return nil, E_ALLOWED_TTL
    end
  end

  return true
end


---@param  addr    string
---@return boolean pending
---@return string? token
local function is_pending(addr)
  local token = PENDING:get(addr)
  return token ~= nil, token
end
_M.is_pending = is_pending


---@param addr string
---@param token? string
local function set_pending(addr, token)
  if not token then
    assert(PENDING:set(addr, nil))

  else
    assert(PENDING:safe_set(addr, token, TTL_PENDING))
  end
end
_M.set_pending = set_pending


---@param req doorbell.forwarded_request
---@return doorbell.auth_state state
---@return string? error
local function get_state(req, ctx)
  local rule, cached = rules.match(req)
  if rule then
    if ctx then
      ctx.rule = rule
      ctx.rule_cache_hit = cached
    end
    return rule.action
  end

  if is_pending(req.addr) then
    return STATES.pending
  end

  return STATES.none
end
_M.get_state = get_state


---@param req doorbell.forwarded_request
---@return string? token
---@return string? error
local function generate_request_token(req)
  local bytes = random.bytes(24, true)
  local token = str.to_hex(bytes)
  local item = {
    request = req,
    created = now(),
    token   = token,
  }
  local value = encode(item)
  local ok, err = APPROVALS:safe_add(token, value, TTL_PENDING)
  if not ok then
    return nil, err
  end
  return token
end


---@param token string
---@return doorbell.auth.approval.request?
---@return string? error
function _M.get_approval(token)
  local v = APPROVALS:get(token)
  if v then
    return decode(v)
  end
end


---@param req doorbell.forwarded_request
---@param timeout? number
function _M.await(req, timeout)
  local start = now()
  timeout = timeout or WAIT_TIME
  while (now() - start) < timeout do
    if not is_pending(req.addr) then
      break
    end
    sleep(1)
  end

  if is_pending(req.addr) then
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
---@return doorbell.auth_state state
---@return string? token
function _M.new_approval(req)
  local addr = req.addr
  local lock, err = util.lock("addr", addr, "auth-request")
  if not lock then
    log.errf("failed acquiring addr lock for %s: %s", addr, err)
    return STATES.error
  end

  local pending, token = is_pending(addr)

  if pending then
    log.notice("access for ", addr, " is already waiting on a pending request")
    return lock:unlock(STATES.pending, token)

  else
    local rule = rules.match(req)
    local state = (rule and rule.action)

    if state == STATES.allow then
      log.debug("acccess for ", addr, " was allowed before requesting it")
      return lock:unlock(STATES.allow)

    elseif state == STATES.deny then
      log.notice("access was denied for ", addr, " before requesting it")
      return lock:unlock(STATES.deny)
    end
  end

  token, err = generate_request_token(req)
  if not token then
    log.errf("failed creating auth request token for %s: %s", addr, err)
    return lock:unlock(STATES.error)
  end

  set_pending(addr, token)

  return lock:unlock(STATES.pending, token)
end


---@param req doorbell.forwarded_request
---@return boolean
function _M.request(req)
  local addr = req.addr
  local lock, err = util.lock("addr", addr, "auth-request")
  if not lock then
    log.errf("failed acquiring addr lock for %s: %s", addr, err)
    return false
  end

  if is_pending(addr) then
    log.notice("access for ", addr, " is already waiting on a pending request")
    return lock:unlock(false)
  else
    local rule = rules.match(req)
    local state = (rule and rule.action)

    if state == STATES.allow then
      log.debug("acccess for ", addr, " was allowed before requesting it")
      return lock:unlock(true)

    elseif state == STATES.deny then
      log.notice("access was denied for ", addr, " before requesting it")
      return lock:unlock(false)
    end
  end

  local token
  token, err = generate_request_token(req)
  if not token then
    log.errf("failed creating auth request token for %s: %s", addr, err)
    return lock:unlock(false)
  end

  set_pending(addr, token)

  if not notify.enabled() then
    return lock:unlock(false)
  end

  if not notify.in_notify_period() then
    log.notice("not sending request outside of notify hours for ", req.addr)
    notify.inc("snoozed")

    return lock:unlock(false)
  end

  local url = fmt("%s/answer?t=%s", base_url, token)
  log.debug("approve/deny link: ", url)

  local sent
  sent, err = notify.ring(req, url)

  if not sent then
    log.err("failed sending auth request: ", err)
    notify.inc("failed")
  else
    notify.inc("sent")
  end

  return lock:unlock(sent and true)
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


---@return doorbell.auth.approval.request[]
function _M.list_approvals()
  local keys = assert(APPROVALS:get_keys(0))
  local values = {}
  local c = 0

  for _, key in ipairs(keys) do
    local value = APPROVALS:get(key)
    if value then
      c = c + 1
      values[c] = decode(value)
    end
  end

  return values
end


---@param ans doorbell.auth.approval.answer
---@return integer status
---@return string? error
---@return doorbell.rule? rule
function _M.answer(ans)
  local ok, err = schema.auth.approval.answer.validate(ans)

  if not ok then
    return 400, err
  end

  ok, err = validate_allowed_limits(ans)
  if not ok then
    return 400, err
  end

  local req = _M.get_approval(ans.token)
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

  set_pending(req.request.addr, nil)
  APPROVALS:delete(ans.token)

  return 201, nil, rule
end

return _M
