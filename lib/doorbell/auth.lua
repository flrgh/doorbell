local _M = {
  _VERSION = require("doorbell.constants").version,
}

local const   = require "doorbell.constants"
local log     = require "doorbell.log"
local rules   = require "doorbell.rules"
local notify  = require "doorbell.notify"

local resty_lock = require "resty.lock"
local random     = require "resty.random"
local str        = require "resty.string"
local cjson      = require "cjson"

local encode     = cjson.encode
local decode     = cjson.decode
local fmt = string.format
local now = ngx.now
local sleep = ngx.sleep


local TTL_PENDING = const.ttl.pending
local SHM_NAME = const.shm.doorbell
local SHM = assert(ngx.shared[SHM_NAME], "missing shm " .. SHM_NAME)
local WAIT_TIME   = const.wait_time
local STATES      = const.states

local base_url

---@param addr string
---@return boolean
local function is_pending(addr)
  return SHM:get("pending:" .. addr)
end
_M.is_pending = is_pending

---@param addr string
---@param pending boolean
local function set_pending(addr, pending)
  local key = "pending:" .. addr
  if not pending then
    assert(SHM:delete(key))
  else
    assert(SHM:safe_set(key, true, TTL_PENDING))
  end
end
_M.set_pending = set_pending

---@param req doorbell.request
---@return doorbell.auth_state state
---@return string? error
local function get_state(req, ctx)
  local rule, cached = rules.match(req)
  if rule then
    if ctx then
      ctx.rule = rule
      ctx.cached = cached
    end
    return rule.action
  end

  if is_pending(req.addr) then
    return STATES.pending
  end

  return STATES.none
end
_M.get_state = get_state


---@param addr string
---@return resty.lock? lock
---@return string? error
local function lock_addr(addr)
  local lock, err = resty_lock:new(SHM_NAME)
  if not lock then
    log.err("failed to create lock: ", err)
    return nil, err
  end

  local elapsed
  elapsed, err = lock:lock("lock:" .. addr)
  if not elapsed then
    log.err("failed to lock auth state for ", addr)
    return nil, err
  end

  return lock
end


---@param req doorbell.request
---@return string? token
---@return string? error
local function generate_request_token(req)
  local bytes = random.bytes(32, true)
  local token = str.to_hex(bytes)
  local key = "token:" .. token
  local value = encode(req)
  local ok, err = SHM:safe_add(key, value, TTL_PENDING)
  if not ok then
    return nil, err
  end
  return token
end


---@param token string
---@return doorbell.request req
---@return string? error
function _M.get_token_address(token)
  local key = "token:" .. token
  local v = SHM:get(key)
  if v then
    return decode(v)
  end
end

---@param req doorbell.request
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


---@param req doorbell.request
---@return boolean
function _M.request(req)
  local addr = req.addr
  local lock, err = lock_addr(addr)
  if not lock then
    log.errf("failed acquiring addr lock for %s: %s", addr, err)
    return false
  end

  if is_pending(addr) then
    log.notice("access for ", addr, " is already waiting on a pending request")
    lock:unlock()
    return false
  else
    local rule = rules.match(req)
    local state = (rule and rule.action)

    if state == STATES.allow then
      log.debug("acccess for ", addr, " was allowed before requesting it")
      lock:unlock()
      return true

    elseif state == STATES.deny then
      log.notice("access was denied for ", addr, " before requesting it")
      lock:unlock()
      return false
    end
  end
  local token
  token, err = generate_request_token(req)
  if not token then
    log.errf("failed creating auth request token for %s: %s", addr, err)
    lock:unlock()
    return false
  end

  local url = fmt("%s/answer?t=%s", base_url, token)
  log.debug("approve/deny link: ", url)

  local sent
  sent, err = notify.send(req, url)

  if not sent then
    log.err("failed sending auth request: ", err)
    lock:unlock()
    notify.inc("failed")
    return false
  end

  notify.inc("sent")
  set_pending(addr, true)
  lock:unlock()
  return true
end

---@param conf doorbell.config
function _M.init(conf)
  base_url = conf.base_url
end


return _M
