local _M = {
  _VERSION = require("doorbell.constants").version,
}

local const = require "doorbell.constants"
local log   = require "doorbell.log"
local util  = require "doorbell.util"
local cjson = require "cjson"

local ngx    = ngx
local assert = assert
local type   = type
local tostring = tostring

local errorf = util.errorf

local SHM = assert(ngx.shared[const.shm.rules], "rules SHM missing")
local V_CURRENT = "current-version"
local V_LATEST = "latest-version"
local PENDING = "pending"

_M.PENDING = PENDING
_M.PENDING_TTL = 30
_M.V_CURRENT = V_CURRENT
_M.V_LATEST = V_LATEST
_M.SHM = SHM


---@param version string|integer
---@return any
local function raw_get(version)
  return SHM:get(tostring(version))
end


---@param version string|integer
local function delete(version)
  SHM:delete(tostring(version))
end


---@return integer
local function get_current_version()
  return SHM:get(V_CURRENT) or 0
end


---@return integer
local function get_latest_version()
  return SHM:get(V_LATEST)
end


function _M.reset()
  SHM:flush_all()
  assert(SHM:flush_expired(0))
end


_M.get_current_version = get_current_version
_M.get_latest_version = get_latest_version

---@param version? number
---@return doorbell.rule[]
function _M.get(version)
  version = version or get_current_version()
  if version == 0 then
    return {}
  end

  local data = SHM:get(tostring(version))
  if not data then
    errorf("missing SHM data for version %s", version)
  end

  return cjson.decode(data)
end


---@param rules doorbell.rule[]
---@param version integer
function _M.set(rules, version)
  assert(type(rules) == "table", "rules parameter is required and must be a table")
  assert(type(version) == "number", "version is required and must be an integer")

  local latest = get_latest_version()
  assert(latest ~= nil, "tried to store rules without allocating a new version")
  assert(latest >= version, "tried to store rules with an invalid version")

  local v = tostring(version)
  local value = SHM:get(v)

  if value == nil then
    errorf("transaction for version %s already timed out", version)

  elseif value ~= PENDING then
    errorf("unexpected value for pending version %s: %q: ", version, value)
  end

  local data = cjson.encode(rules)

  local added, err = SHM:safe_set(v, data, 0)
  if not added then
    errorf("failed to store rules version %s: %s", v, err)
  end

  return true
end


---@return integer
function _M.allocate_new_version()
  local version = SHM:incr(V_LATEST, 1, 0)
  local v = tostring(version)
  assert(SHM:safe_add(v, PENDING, _M.PENDING_TTL))

  log.debug("allocated new shm version: ", v)
  return version
end

---@param version integer
function _M.cancel_pending_version(version)
  if get_current_version() > version then
    return
  end

  assert(get_latest_version() >= version)

  local v = tostring(version)
  local value = SHM:get_stale(v)
  assert(value == PENDING or value == nil)
  SHM:delete(v)
end

function _M.update_current_version()
  local current = get_current_version()
  local latest = get_latest_version() or current

  if current == latest then
    log.debugf("current version %s is already up-to-date", current)
    return current
  end

  local pointer = current
  local last_valid = current

  while pointer < latest do
    local next_version = pointer + 1

    local value = raw_get(next_version)

    if value == nil then
      log.debugf("skipping expired version: %s", next_version)

    elseif value == PENDING then
      log.debugf("stopping at pending version: %s", next_version)
      break

    elseif type(value) == "string" then
      last_valid = next_version

      assert(SHM:safe_set(V_CURRENT, next_version))
      delete(pointer)
    end

    pointer = next_version
    latest = get_latest_version()
  end

  log.debugf("current version increased from %s => %s (latest: %s)", current, last_valid, latest)

  return last_valid
end


return _M
