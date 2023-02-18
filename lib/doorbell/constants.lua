local const = {}

const.version = "0.1.0"

---@alias doorbell.action "allow"|"deny"

--- lookup table of valid authorization rule actions
const.actions = {
  allow = "allow",
  deny  = "deny",
}

---@alias doorbell.source "config"|"user"|"ota"


--- lookup table of valid doorbell rule sources
const.sources = {
  config = "config",
  user   = "user",
  ota    = "ota",
}

---@alias doorbell.deny_action "exit"|"tarpit"

-- lookup table of possible rule deny methods
const.deny_actions = {
  tarpit = "tarpit",
  exit   = "exit",
}

---@alias doorbell.auth_state
---| "allow"   # allowed
---| "deny"    # explicitly denied
---| "pending" # awaiting approval
---| "none"    # never seen this IP before
---| "error"   # something's wrong

--- lookup table of valid authorization states
const.states = {
  allow      = "allow",
  deny       = "deny",
  pending    = "pending",
  none       = "none",
  error      = "error",
}

do
  local minute = 60
  local hour   = 60 * minute
  local day    = hour * 24
  local week   = day * 7

  --- valid time periods for rule TTLs
  const.periods = {
    minute  = minute,
    hour    = hour,
    day     = day,
    week    = week,
    forever = 0,
  }
end

---@alias doorbell.scope "global"|"host"|"url"

--- lookup table of valid rule scopes
const.scopes = {
  global = "global",
  host   = "host",
  url    = "url",
}

---@alias doorbell.subject "addr"|"ua"

--- lookup table of valid rule subjects
const.subjects = {
  addr = "addr",
  ua   = "ua",
}

--- how long to await auth approval for in-flight requests
const.wait_time = const.periods.minute

const.ttl = {
  --- how long to persist auth approval records for
  pending = const.periods.hour,
}

-- ngx.shared shm names
const.shm = {
  doorbell  = "doorbell",    -- primary storage
  rules     = "rules",       -- doorbell rules
  rule_hash = "rules_hash",  -- rules hash secondary lookups
  stats     = "stats",       -- rule statistics
  metrics   = "metrics",     -- prometheus metrics
  locks     = "locks",       -- locks
}

return const
