local const = require "doorbell.constants"
local valid_uuid = require("resty.jit-uuid").is_valid
local ip = require "doorbell.ip"
local http = require "doorbell.http"
local util = require "doorbell.util"

local NULL = ngx.null
local re_match = ngx.re.match

--local generate_validator = require("jsonschema").generate_validator
local generate_validator = require("resty.ljsonschema").generate_validator

local function is_set(value)
  return value ~= nil and value ~= NULL
end

local function noop(_) return true end

local function validator(schema)
  local name = assert(schema.title)
  local post_validate = schema.post_validate or noop

  local validate_schema = assert(generate_validator(schema, { name = name }))

  return function(value)
    local ok, err = validate_schema(value)

    if ok and is_set(value) then
      ok, err = post_validate(value)
    end

    if not ok then
      return nil, err
    end

    return true
  end
end

---@class doorbell.schema.base : table
---
---@field title string
---
---@field description string
---
---@field allOf doorbell.schema[]
---
---@field anyOf doorbell.schema[]
---
---@field not doorbell.schema
---
---@field extra_validator fun(value:any):boolean?, string?
--_
---@field validate fun(value:any):boolean?, string?
---
---@field examples any[]
---
---@field default any


---@class doorbell.schema.object : doorbell.schema.base
---
---@field type "object"
---
---@field properties table<string, doorbell.schema>
---
---@field additionalProperties boolean,
---
---@field required string[]


---@class doorbell.schema.array : doorbell.schema.base
---
---@field type "array"
---
---@field items doorbell.schema
---
---@field uniqueItems boolean


---@class doorbell.schema.string : doorbell.schema.base
---
---@field type "string"
---
---@field format string
---
---@field pattern string
---
---@field minLength integer
---
---@field maxLength integer


---@class doorbell.schema.number : doorbell.schema.base
---
---@field type "integer"|"number"
---
---@field minimum number
---@field maximum number
---@field exclusiveMinimum boolean
---@field exclusiveMaximum boolean


---@class doorbell.schema.boolean : doorbell.schema.base
---
---@field type "boolean"

---@alias doorbell.schema
---| doorbell.schema.object
---| doorbell.schema.array
---| doorbell.schema.string
---| doorbell.schema.boolean
---| doorbell.schema.number


---@param cidr string|string[]
---@return boolean? ok
---@return string? error
local function validate_cidr(cidr)
  if type(cidr) == "table" then
    for _, v in ipairs(cidr) do
      local ok, err = validate_cidr(v)
      if not ok then
        return nil, err
      end
    end

    return true
  end

  local addr, mask
  local m = re_match(cidr, "([^/]+)(/(.+))?")

  if m then
    addr = m[1]
    mask = m[3]
  end

  local typ = ip.is_valid(addr)

  if not typ then
    return nil, "invalid CIDR: " .. cidr
  end

  if typ == 4 then
    mask = mask or 32

  elseif typ == 6 then
    mask = mask or 128
  end


  mask = tonumber(mask)
  if not mask then
    return nil, "invalid CIDR: " .. cidr
  end

  if typ == 4 and (mask >= 0 and mask <= 32) then
    return true

  elseif typ == 6 and (mask >= 0 and mask <= 128) then
    return true
  end

  return nil, "invalid CIDR: " .. cidr
end


local function validate_expires(expires)
  if expires > 0 and expires <= ngx.now() then
    return nil, "rule is already expired"
  end

  return true
end


---@param addr string
---@return boolean? ok
---@return string? error
local function validate_ip_addr(addr)
  if ip.is_valid(addr) then
    return true
  end
  return nil, "invalid IP address: " .. addr
end


---@param config doorbell.config
---@return boolean? ok
---@return string? error
local function validate_config(config)
  local ok, err

  if config.trusted then
    ok, err = validate_cidr(config.trusted)
    if not ok then
      return nil, "invalid trusted IP cidrs: " .. tostring(err)
    end
  end

  if config.base_url then
    ok, err = http.parse_url(config.base_url)
    if not ok then
      return nil, "invalid base_url: " .. tostring(err)
    end
  end

  return true
end


local rule = {}

---@type table<string, doorbell.schema>
rule.fields = {}


rule.fields.action = {
  description = "Action to take when the rule matches a request",
  type = "string",
  enum = util.table_values(const.actions),
}

rule.fields.source = {
  description = "Origin of the rule",
  type = "string",
  enum = util.table_values(const.sources),
}

rule.fields.expires = {
  description = "Absolute timestamp (as a Unix epoch) that dictates when the rule expires",
  type = "number",
  minimum = 0,
  post_validate = validate_expires,
}

rule.fields.ttl = {
  description = "Relative timestamp (in seconds) of the rule's expiration",
  type = "number",
  exclusiveMinimum = true,
  minimum = 0,
}

rule.fields.id = {
  description = "Universally unique identifier (UUID) for this rule",
  type = "string",
  minLength = 36,
  maxLength = 36,
  pattern = "^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$",
  post_validate = valid_uuid,
}

rule.fields.host = {
  description = "Request Host header",
  type = "string",
  minLength = 1,
  format = "hostname",
}

rule.fields.ua = {
  description = "Request User-Agent header",
  type = "string",
  minLength = 0,
  examples = {
    "my specific user agent",
    "~.*my regex user agent match version: [0-9]+.*",
  }
}

rule.fields.path = {
  description = "Request path",
  type = "string",
  minLength = 1,
  examples = {
    "/foo",
    "~^/foo/.+",
  }
}

rule.fields.addr = {
  description = "Client IP address of the request",
  type = "string",
  minLength = 1,
  examples = {
    "1.2.3.4",
    "2607:f8b0:400a:800::200e",
  },
  post_validate = validate_ip_addr,
}

rule.fields.cidr = {
  description = "Subnet (in CIDR notation)",
  type = "string",
  minLength = 1,
  pattern = ".+/([0-9]+)$",
  examples = {
    "1.2.3.0/24",
  },
  post_validate = validate_cidr,
}

rule.fields.method = {
  description = "Request HTTP method",
  type = "string",
  enum = {
    "CONNECT",
    "DELETE",
    "GET",
    "HEAD",
    "OPTIONS",
    "PATCH",
    "POST",
    "PUT",
    "TRACE",
  },
}

rule.fields.deny_action = {
  description = "Specific action to take when the rule matches a request and the action is 'deny'",
  type = "string",
  enum = util.table_values(const.deny_actions),
}

rule.fields.created = {
  description = "A Unix epoch timestamp of when the rule was created",
  type = "number",
  minimum = 0,
}

rule.fields.terminate = {
  description = "If `true`, do not attempt to match any other rules after this one",
  type = "boolean",
}

rule.fields.comment = {
  description = "An informative comment about the rule",
  type = "string",
  minLength = 1,
}

rule.fields.country = {
  description = "Country code of the request",
  type = "string",
  minLength = 1,
  maxLength = 2,
  pattern = "^[A-Z][A-Z]$",
  enum = util.table_keys(require("doorbell.ip.countries")),
}

rule.fields.hash = {
  description = "(generated) hash of a rule's match conditions",
  type = "string",
}

rule.fields.conditions = {
  description = "(generated) number of match conditions a rule has",
  type = "integer",
  minimum = 1,
}

rule.fields.asn = {
  description = "Network ASN",
  type = "integer",
  minimum = 0,
}

rule.fields.org = {
  description = "Network Org",
  type = "string",
}

for name, field in pairs(rule.fields) do
  field.title = name
  field.validate = validator(field)
end

local function required(name)
  return {
    type = "object",
    properties = {
      [name] = { type = assert(assert(rule.fields[name]).type) },
    },
    required = { name },
    additionalProperties = true,
  }
end

---@type table<string, doorbell.schema>
rule.policy = {}

rule.policy.at_least_one_condition = {
  description = "Require at least one condition",
  anyOf = {
    required("addr"),
    required("cidr"),
    required("host"),
    required("path"),
    required("method"),
    required("ua"),
    required("country"),
    required("asn"),
    required("org"),
  },
}

rule.policy.expires_or_ttl = {
  description = "`expires` and `ttl` are mutually exclusive",
  oneOf = {
    {
      properties = { expires = { type = "null" },
                         ttl = { type = "number" } },
      required = { "ttl" },
      additionalProperties = true
    },
    {
      properties = { expires = { type = "number" },
                         ttl = { type = "null" } },
      required = { "expires" },
      additionalProperties = true
    },
    {
      properties = { expires = { type = "null" },
                         ttl = { type = "null" } },
      additionalProperties = true
    },
  },
}

rule.policy.deny_action_deny = {
  description = "`deny_action` is only valid when `action` is `deny`",
  ["not"] = {
    properties = {
      action      = { const = const.actions.allow, enum = { const.actions.allow } },
      deny_action = { type = "string" },
    },
    required = { "deny_action", "action" },
  },
}


---@param obj doorbell.rule.new.opts
---@return boolean? ok
---@return string? error
local function validate_rule(obj)
  local errors = {}
  local fail = false

  for name, value in pairs(obj) do
    local field_schema = assert(rule.fields[name],
                                "no schema found for field: " .. name)
    local ok, err = field_schema.validate(value)
    if not ok then
      fail = true
      errors[name] = err or "validation failed"
    end
  end

  if obj.terminate then
    if require("doorbell.rules").count_conditions(obj) > 1 then
      fail = true
      errors.terminate = "can only have one match condition with `terminate`"
    end
  end

  if fail then
    return nil, "validation failed", errors
  end

  return true
end


---@type doorbell.schema
rule.entity = {
  title = "rule",
  description  = "Doorbell rule object",
  type = "object",

  properties = {
    action      = rule.fields.action,
    addr        = rule.fields.addr,
    asn         = rule.fields.asn,
    cidr        = rule.fields.cidr,
    comment     = rule.fields.comment,
    conditions  = rule.fields.conditions,
    created     = rule.fields.created,
    deny_action = rule.fields.deny_action,
    expires     = rule.fields.expires,
    hash        = rule.fields.hash,
    host        = rule.fields.host,
    id          = rule.fields.id,
    method      = rule.fields.method,
    org         = rule.fields.org,
    path        = rule.fields.path,
    source      = rule.fields.source,
    terminate   = rule.fields.terminate,
    ua          = rule.fields.ua,
  },

  additionalProperties = false,

  required = {
    "action",
    "source",
    "id",
  },

  allOf = {
    rule.policy.deny_action_deny,
    rule.policy.at_least_one_condition,
  },

  post_validate = validate_rule,
}
rule.entity.validate = validator(rule.entity)

rule.create = {
  title = "doorbell.rule.create",
  description = "Schema for rule creation",
  type = "object",
  required = { "action", "source" },

  properties = {
    action      = rule.fields.action,
    asn         = rule.fields.asn,
    deny_action = rule.fields.deny_action,
    addr        = rule.fields.addr,
    cidr        = rule.fields.cidr,
    comment     = rule.fields.comment,
    created     = rule.fields.created,
    country     = rule.fields.country,
    expires     = rule.fields.expires,
    host        = rule.fields.host,
    id          = rule.fields.id,
    method      = rule.fields.method,
    org         = rule.fields.org,
    path        = rule.fields.path,
    source      = rule.fields.source,
    terminate   = rule.fields.terminate,
    ttl         = rule.fields.ttl,
    ua          = rule.fields.ua,
  },

  additionalProperties = false,

  allOf = {
    rule.policy.at_least_one_condition,
    rule.policy.expires_or_ttl,
    rule.policy.deny_action_deny,
  },

  post_validate = validate_rule,
}
rule.create.validate = validator(rule.create)

---@type doorbell.schema
rule.patch = {
  title = "doorbell.rule.patch",
  description = "schema for rule PATCH request body",
  type = "object",
  properties = {
    action      = rule.fields.action,
    asn         = rule.fields.asn,
    deny_action = rule.fields.deny_action,
    addr        = rule.fields.addr,
    cidr        = rule.fields.cidr,
    comment     = rule.fields.comment,
    country     = rule.fields.country,
    expires     = rule.fields.expires,
    host        = rule.fields.host,
    method      = rule.fields.method,
    org         = rule.fields.org,
    path        = rule.fields.path,
    terminate   = rule.fields.terminate,
    ttl         = rule.fields.ttl,
    ua          = rule.fields.ua,
  },
  additionalProperties = false,
  allOf = {
    rule.policy.expires_or_ttl,
    rule.policy.deny_action_deny,
  },
  post_validate = validate_rule,
}
rule.patch.validate = validator(rule.patch)


local config = {}

---@type doorbell.schema
local config_rule = {
  type = "object",
  properties = {
    addr        = rule.fields.addr,
    asn         = rule.fields.asn,
    cidr        = rule.fields.cidr,
    comment     = rule.fields.comment,
    country     = rule.fields.country,
    host        = rule.fields.host,
    method      = rule.fields.method,
    org         = rule.fields.org,
    path        = rule.fields.path,
    ua          = rule.fields.ua,
    deny_action = rule.fields.deny_action,
    terminate   = rule.fields.terminate,
  },

  additionalProperties = false,

  allOf = {
    rule.policy.at_least_one_condition,
  },
}

---@type table<string, doorbell.schema>
config.fields = {}

config.fields.allow = {
  description = "static allow rules",
  type = "array",
  items = config_rule,
  default = util.array(),
}

config.fields.deny = {
  description = "static deny rules",
  type = "array",
  items = config_rule,
  default = util.array(),
}

config.fields.asset_path = {
  description = "Directory containing static assets for the application",
  type = "string",
  default = "/usr/local/share/doorbell",
}

config.fields.base_url = {
  description = "External URL for the application (used to generate hyperlinks)",
  type = "string",
  minLength = 1,
  default = "http://127.0.0.1",
}

config.fields.cache_size = {
  description = "Dictates the number of items kept in the application's LRU cache",
  type = "integer",
  minimum = 1000,
  maximum = 100000,
  default = 1000,
}

config.fields.trusted = {
  description = "Trusted IP addresses/CIDR ranges",
  type = "array",
  uniqueItems = true,
  items = {
    type = "string",
    minLength = 1,
  },
  minLength = 1,
  examples = {
    { "127.0.0.1", "10.0.3.1", "10.0.4.0/24" },
  },
  default = util.array({ "127.0.0.1/32" }),
}

config.fields.log_path = {
  description = "Path to the directory where log files will be stored",
  type = "string",
  minLength = 1,
  default = "/var/log/doorbell",
}

config.fields.runtime_path = {
  description = "Directory for NGINX-related files (and the default state path)",
  type = "string",
  minLength = 1,
  default = "/var/run/doorbell",
}

config.fields.state_path = {
  description = "State directory, where rules and stat data are persisted",
  type = "string",
  minLength = 1,
  default = "/var/run/doorbell",
}


config.fields.ota = {
  description = "OTA configuration",
  type = "object",
  properties = {
    url = {
      description = "URL to remote rules list",
      type = "string",
      minLength = 1,
    },

    headers = {
      description = "Headers that will be sent with update requests",
      type = "object",
      properties = {},
      additionalProperties = true,
    },

    interval = {
      description = "How often (in seconds) to check for remote updates",
      type = "number",
      exclusiveMinimum = true,
      minimum = const.testing and 0 or 60,
      default = 60,
    }
  },
  required = { "url" },
}

config.fields.metrics = {
  description = "Application metrics configuration",
  type = "object",
  properties = {
    disable = {
      description = "Disable all instrumentation and metrics collection",
      type = "boolean",
      default = false,
    },

    interval = {
      description = "How often (in seconds) to measure and evaluate things",
      type = "number",
      exclusiveMinimum = true,
      default = 5,
    }
  },
}

config.fields.notify = {
  description = "Notification subsystem configuration",
  type = "object",
  properties = {
    strategy = {
      description = "Notification provider",
      type = "string",
      minLength = 1,
      default = "none",
    },

    config = {
      description = "Provider-specific configuration",
      type = "object",
      properties = {},
      additionalProperties = true,
    },

    periods = {
      description = "Time periods when notifications can be sent",
      type = "array",
      items = {
        type = "object",
        properties = {
          from = {
            description = "Start of the period (HH)",
            type = "integer",
            minimum = 0,
            maximum = 23,
          },

          to = {
            description = "End of the period (HH)",
            type = "integer",
            minimum = 0,
            maximum = 23,
          },
        }
      }
    },
  }
}

config.fields.host = {
  description = "Server Hostname",
  type = "string",
  minLength = 1,
}

config.fields.geoip_country_db = {
  description = "Path to GeoIP Country database (.mmdb file)",
  type = "string",
  pattern = ".+[.]mmdb$",
}

config.fields.geoip_asn_db = {
  description = "Path to GeoIP ASN database (.mmdb file)",
  type = "string",
  pattern = ".+[.]mmdb$",
}

config.fields.geoip_city_db = {
  description = "Path to GeoIP City database (.mmdb file)",
  type = "string",
  pattern = ".+[.]mmdb$",
}

config.fields.unauthorized = {
  description = "How to handle incoming requests that don't match a rule",
  type = "string",
  enum = util.table_values(const.unauthorized),
  default = const.unauthorized.return_401,
}

---@type doorbell.schema
config.entity = {
  title = "doorbell.config",
  description = "Doorbell runtime configuration object",
  type = "object",

  properties = {
    allow                = config.fields.allow,
    asset_path           = config.fields.asset_path,
    base_url             = config.fields.base_url,
    cache_size           = config.fields.cache_size,
    deny                 = config.fields.deny,
    geoip_asn_db         = config.fields.geoip_asn_db,
    geoip_city_db        = config.fields.geoip_city_db,
    geoip_country_db     = config.fields.geoip_country_db,
    host                 = config.fields.host,
    log_path             = config.fields.log_path,
    metrics              = config.fields.metrics,
    notify               = config.fields.notify,
    ota                  = config.fields.ota,
    runtime_path         = config.fields.runtime_path,
    state_path           = config.fields.state_path,
    trusted              = config.fields.trusted,
    unauthorized         = config.fields.unauthorized,
  },

  additionalProperties = false,

  required = {
    "asset_path",
    "base_url",
    "cache_size",
    "host",
    "log_path",
    "runtime_path",
    "trusted",
  }
}
config.entity.validate = validator(config.entity)

---@type doorbell.schema
config.input = {
  title = "doorbell.config",
  description = "Doorbell runtime configuration input",
  type = "object",

  properties = {
    allow              = config.fields.allow,
    asset_path         = config.fields.asset_path,
    base_url           = config.fields.base_url,
    cache_size         = config.fields.cache_size,
    deny               = config.fields.deny,
    geoip_asn_db       = config.fields.geoip_asn_db,
    geoip_city_db      = config.fields.geoip_city_db,
    geoip_country_db   = config.fields.geoip_country_db,
    log_path           = config.fields.log_path,
    metrics            = config.fields.metrics,
    notify             = config.fields.notify,
    ota                = config.fields.ota,
    runtime_path       = config.fields.runtime_path,
    state_path         = config.fields.state_path,
    trusted            = config.fields.trusted,
    unauthorized       = config.fields.unauthorized,
  },

  additionalProperties = false,

  post_validate = validate_config,
}
config.input.validate = validator(config.input)


return {
  rule = rule,
  config = config,
}
