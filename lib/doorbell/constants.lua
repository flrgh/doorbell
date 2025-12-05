local const = {}

const.version = "0.1.0"

---@alias doorbell.action "allow"|"deny"

--- lookup table of valid authorization rule actions
const.actions = {
  allow = "allow",
  deny  = "deny",
}

---@alias doorbell.source "config"|"user"|"ota"|"api"|"plugin"|"webhook"


--- lookup table of valid doorbell rule sources
const.sources = {
  config  = "config",
  user    = "user",
  ota     = "ota",
  api     = "api",
  plugin  = "plugin",
  webhook = "webhook",
}

---@alias doorbell.deny_action "exit"|"tarpit"

-- lookup table of possible rule deny methods
const.deny_actions = {
  tarpit = "tarpit",
  exit   = "exit",
}

---@alias doorbell.auth.access.state
---| "allow"         # allowed
---| "deny"          # explicitly denied
---| "pending"       # awaiting approval
---| "none"          # never seen this IP before
---| "error"         # something's wrong
---| "pre-approved"  # request has been pre-approved

--- lookup table of valid authorization states
const.states = {
  allow        = "allow",
  deny         = "deny",
  pending      = "pending",
  none         = "none",
  error        = "error",
  pre_approved = "pre-approved",
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
  -- "main", use sparingly for metadata and global things
  doorbell   = "doorbell",

  -- doorbell.rules.*
  rules      = "rules",
  stats      = "stats",

  -- prometheus metric storage
  metrics    = "metrics",     -- prometheus metrics

  -- locks, used by multiple submodules
  locks      = "locks",

  -- nginx IPC
  nginx      = "nginx",

  -- doorbell.auth.*
  approvals  = "approvals",
  pending    = "pending",

  -- doorbell.cache.shared / lua-resty-mlcache
  mlcache_ipc   = "mlcache_ipc",
  mlcache_locks = "mlcache_locks",
  mlcache_main  = "mlcache_main",
  mlcache_miss  = "mlcache_miss",

  -- shared storage, see `doorbell.shm.namespace`
  shared = "shared",
}

---@enum doorbell.unauthorized
const.unauthorized = {
  return_401            = "return-401",
  request_approval      = "request-approval",
  redirect_for_approval = "redirect-for-approval",
  validate_email        = "validate-email",
  verify                = "verify",
}

const.endpoints = {
  get_access = "/letmein",
  ring       = "/ring",
  answer     = "/answer",
  email      = "/email-validate",
  verify     = "/verify",
}

const.testing = false

do
  local test = os.getenv("_DOORBELL_TEST")
  if test == "1" or test == "true" then
    const.testing = true
  end
end


const.headers = {
  request_id = "x-doorbell-request-id",
  api_key    = "x-doorbell-api-key",
}


return const
