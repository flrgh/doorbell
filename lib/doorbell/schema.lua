local const = require "doorbell.constants"
local valid_uuid = require("resty.jit-uuid").is_valid
local ip = require "doorbell.ip"
local http = require "doorbell.http"
local util = require "doorbell.util"
local isarray = require "table.isarray"

---@alias doorbell.schema.timestamp number

---@type fun(doorbell.schema, table):function
local generate_validator = require("resty.ljsonschema").generate_validator

local NULL = ngx.null
local re_match = ngx.re.match


---@param s doorbell.schema
---@param value any
---@param cb fun(s:doorbell.schema, value:any)
local function map_schema(s, value, cb)
  value = cb(s, value)

  if value == nil then
    return
  end

  if type(value) == "table" then
    if s.type == "object" then
      assert(type(s.properties) == "table" or type(s.patternProperties) == "table")

      if s.properties then
        for name, sub in pairs(s.properties) do
          value[name] = map_schema(sub, value[name], cb)
        end
      end

    elseif s.type == "array" then
      assert(type(s.items) == "table")

      for i = 1, #value do
        value[i] = map_schema(s.items, value[i], cb)
      end
    end
  end

  return value
end


---@generic T
---@param s doorbell.schema
---@param t T[]
---@return T[]
local function arrayify(s, t)
  if s.type == "array" and type(t) == "table" and isarray(t) then
    t = util.array(t)
  end

  return t
end


---@generic T
---@param s doorbell.schema
---@param t T
---@return T
local function convert_arrays(s, t)
  return map_schema(s, t, arrayify)
end


local function is_set(value)
  return value ~= nil and value ~= NULL
end

local function noop(_) return true end


---@param schema doorbell.schema
local function validator(schema)
  local name = assert(schema.title)
  local post_validate = schema.post_validate or noop

  local validate_schema = assert(generate_validator(schema, { name = name }))

  schema.validate = function(value)
    value = convert_arrays(schema, value)
    local ok, err = validate_schema(value)

    if ok and is_set(value) then
      ok, err = post_validate(value)
    end

    if not ok then
      return nil, err
    end

    return true
  end

  return schema.validate
end

---@class doorbell.schema.example : table
---
---@field comment string
---@field value   any


---@class doorbell.schema.base : table
---
---@field title? string
---
---@field description? string
---
---@field allOf? doorbell.schema[]
---
---@field anyOf? doorbell.schema[]
---
---@field not? doorbell.schema
---
---@field post_validate? fun(value:any):boolean?, string?
---
---@field validate? fun(value:any):boolean?, string?
---
---@field examples? doorbell.schema.example[]
---
---@field default? any


---@class doorbell.schema.anyOf : doorbell.schema.base
---
---@field anyOf doorbell.schema[]


---@class doorbell.schema.allOf : doorbell.schema.base
---
---@field allOf doorbell.schema[]


---@class doorbell.schema.not : doorbell.schema.base
---
---@field not doorbell.schema


---@class doorbell.schema.oneOf : doorbell.schema.base
---
---@field oneOf doorbell.schema[]


---@class doorbell.schema.object : doorbell.schema.base
---
---@field type? "object"
---
---@field properties? table<string, doorbell.schema>
---
---@field patternProperties? table<string, doorbell.schema>
---
---@field additionalProperties? boolean,
---
---@field required? string[]


---@class doorbell.schema.null : doorbell.schema.base
---
---@field type "null"

---@class doorbell.schema.array : doorbell.schema.base
---
---@field type "array"
---
---@field items doorbell.schema
---
---@field uniqueItems boolean
---
---@field minItems integer


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
---| doorbell.schema.null
---| doorbell.schema.anyOf
---| doorbell.schema.allOf
---| doorbell.schema.oneOf
---| doorbell.schema.not


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
    {
      comment = "match 'my specific user agent' exactly",
      value   = "my specific user agent",
    },
    {
      comment = "regex match",
      value   = "~.*my regex user agent match version: [0-9]+.*",
    },
  }
}

rule.fields.path = {
  description = "Request path",
  type = "string",
  minLength = 1,
  examples = {
    { comment = "match '/foo' exactly", value = "/foo" },
    { comment = "match paths that start with '/foo'", value = "~^/foo/.+" },
  }
}

rule.fields.addr = {
  description = "Client IP address of the request",
  type = "string",
  minLength = 1,
  examples = {
    { comment = "IPv4", value = "1.2.3.4" },
    { comment = "IPv6", value = "2607:f8b0:400a:800::200e" },
  },
  post_validate = validate_ip_addr,
}

rule.fields.cidr = {
  description = "Subnet (in CIDR notation)",
  type = "string",
  minLength = 1,
  pattern = ".+/([0-9]+)$",
  examples = {
    { comment = "match IPv4 addresses 1.2.3.0-1.2.3.255",
      value = "1.2.3.0/24" },
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
  validator(field)
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
validator(rule.entity)

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

  examples = {
    {
      comment = "allow requests to foo.com from 1.2.3.4",
      value = {
        addr   = "1.2.3.4",
        host   = "foo.com",
        action = "allow",
      },
    },

    {
      comment = "allow all GET requests foo.com/public/*",
      value = {
        host   = "foo.com",
        method = "GET",
        path   = "~^/public/.+",
        action = "allow",
      },
    },

    {
      comment = "explicitly deny access from a particular subnet",
      value = {
        cidr   = "4.2.3.0/24",
        action = "deny",
      },
    },

    {
      comment = "allow an IP to access all hosts for the next hour",
      value = {
        addr   = "1.2.3.4",
        ttl    = 60 * 60,
        action = "allow",
      },
    },


  },

  post_validate = validate_rule,
}
validator(rule.create)

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

  examples = {
    {
      comment = "change a rule action from deny to allow",
      value = {
        action = "allow",
      }
    },

    {
      comment = "update the expiration time for a rule to 10 minutes from now",
      value = {
        ttl = 10 * 60,
      }
    },

    {
      comment = "remove the host condition from a rule and add/update a method condition",
      value = {
        host = ngx.null,
        method = "GET",
      }
    },

  },

  post_validate = validate_rule,
}
validator(rule.patch)


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
  default = {},
  examples = {
    {
      comment = "allow requests to all hosts from private networks",
      value = {
        {
          cidr = "10.0.0.0/8",
        },
        {
          cidr = "192.168.0.0/16",
        },
      },
    },
  },
}

config.fields.deny = {
  description = "static deny rules",
  type = "array",
  items = config_rule,
  default = {},
  examples = {
    {
      comment = "deny requests from a pesky bot",
      value = {
        {
          ua = "Super Duper Crawler v1.0",
        },
      },
    },
  },
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
    { comment = "trust localhost and two private networks",
      value   = { "127.0.0.1", "10.0.3.1", "10.0.4.0/24" },
    },

    { comment = "trust localhost only",
      value   = { "127.0.0.1" },
    },

  },
  default = { "127.0.0.1/32" },
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

  examples = {
    {
      comment = "update rules from https://foo.com/rules.json every 15 minutes",
      value = {
        url = "https://foo.com/rules.json",
        interval = 60 * 15,
      },
    },

    {
      comment = "sending additional headers with the request",
      value = {
        url = "https://foo.com/rules",
        headers = {
          Accept = "application/json",
        },
      },
    },


  },
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
  title = "config.fields.notify",
  additionalProperties = false,
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
      minItems = 1,
      items = {
        type = "object",
        properties = {
          from = {
            description = "Start of the period (HH)",
            type = "integer",
            default = 0,
            minimum = 0,
            maximum = 23,
          },

          to = {
            description = "End of the period (HH)",
            type = "integer",
            minimum = 0,
            maximum = 23,
            default = 0,
          },
        },

        additionalProperties = false,

        anyOf = {
          { required = { "to"   } },
          { required = { "from" } },
        },
      },

      examples = {
        {
          comment = "send notifications between 9pm and midnight",
          value = { { from = 21 } },
        },

        {
          comment = "send notifications between 8am and 6pm",
          value = { { from = 8,  to = 18 } },
        },

        {
          comment = "send notifactions between 9am-1pm and 8pm-10pm",
          value = {
            { from = 9, to = 13 },
            { from = 20, to = 22 },
          },
        },

        {
          comment = "send notifactions between 11pm and 3am",
          value = {
            { from = 23, to = 0 },
            { from = 0,  to = 3 },
          },
        },
      },
    },
  },

  examples = {
    {
      comment = "explicitly disable notifications",
      value = {
        strategy = "none",
      },
    },
  },
}
validator(config.fields.notify)

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

config.fields.redirect_uri = {
  description = "URI to redirect unauthorized requests to.",
  type = "string",
  default = const.endpoints.get_access,
}

config.fields.utc_offset = {
  description = "Offset from UTC time (in hours)",
  type = "integer",
  default = 0,
  minimum = -23,
  maximum = 23,
}

---@class doorbell.config.approvals : table
---
---@field allowed_scopes doorbell.scope[]
---
---@field allowed_subjects doorbell.subject[]
---
---@field max_ttl number
---
---@field pre_approval_ttl number


config.fields.approvals = {
  description = "Settings for approving access for new clients. These only apply "
             .. "when `unauthorized` is set to \"" .. const.unauthorized.return_401
             .. "\"",

  type = "object",

  properties = {
    allowed_scopes = {
      description = "types of access that can be granted for clients via the approvals system",
      type        = "array",
      items       = {
        enum      = util.table_values(const.scopes),
      },
      default     = util.table_values(const.scopes),
    },

    allowed_subjects = {
      description = "subject types that can be granted access via the approvals system",
      type        = "array",
      items       = {
        enum      = util.table_values(const.subjects),
      },
      default     = util.table_values(const.subjects),
    },

    max_ttl = {
      description = "maximum amount of time (in seconds), that clearance can be "
                 .. "granted for (0: unlimited)",
      type        = "number",
      minimum     = 0,
      default     = 0,
    },

    pre_approval_ttl = {
      description = "amount of time (in seconds) that pre-approved access requests "
                 .. "are valid for before expiring",
      type        = "number",
      minimum     = -1,
      default     = 300,
    },


  },

  additionalProperties = false,
}


---@alias doorbell.config.network_tags table<string, string>

config.fields.network_tags = {
  title = "doorbell.config.network_tags",
  description = "A mapping of network addresses (CIDR notation or individual IPs) to string labels",
  type = "object",

  patternProperties = {
    [".+"] = {
      type = "string",
    },
  },

  post_validate = function(tags)
    if not tags then return true end

    local ok, err = true, nil

    for net in pairs(tags) do
      if net ~= "default" then
        ok, err = validate_cidr(net)
        if not ok then break end
      end
    end

    return ok, err
  end,
}
validator(config.fields.network_tags)


---@class doorbell.config.auth : table
---
---@field openid doorbell.config.auth.openid
---@field users  doorbell.config.auth.user[]

---@class doorbell.config.auth.openid : table
---
---@field issuer string
---@field disabled boolean

---@class doorbell.config.auth.user : table
---
---@field name string
---@field identifiers doorbell.config.auth.user.identifier[]

---@class doorbell.config.auth.user.identifier : table
---
---@field email  string
---@field sub    string
---@field apikey string

config.fields.auth = {
  title = "doorbell.config.auth",
  description = "Auth{entication,orization} settings",
  type = "object",

  properties = {
    openid = {
      type = "object",
      properties = {
        issuer = { type = "string" },
        disabled = { type = "boolean" },
      },
    },

    users = {
      type = "array",
      items = {
        type = "object",
        properties = {
          name = { type = "string" },
          identifiers = {
            type = "array",
            items = {
              type = "object",
              properties = {
                email = { type = "string" },
                sub   = { type = "string" },
              },
            },
          },
        },
      },
    },
  },
}

---@type doorbell.schema.object
config.entity = {
  title = "doorbell.config",
  description = "Doorbell runtime configuration object",
  type = "object",

  properties = {
    allow                = config.fields.allow,
    approvals            = config.fields.approvals,
    asset_path           = config.fields.asset_path,
    auth                 = config.fields.auth,
    base_url             = config.fields.base_url,
    cache_size           = config.fields.cache_size,
    deny                 = config.fields.deny,
    geoip_asn_db         = config.fields.geoip_asn_db,
    geoip_city_db        = config.fields.geoip_city_db,
    geoip_country_db     = config.fields.geoip_country_db,
    host                 = config.fields.host,
    log_path             = config.fields.log_path,
    metrics              = config.fields.metrics,
    network_tags         = config.fields.network_tags,
    notify               = config.fields.notify,
    ota                  = config.fields.ota,
    redirect_uri         = config.fields.redirect_uri,
    runtime_path         = config.fields.runtime_path,
    state_path           = config.fields.state_path,
    trusted              = config.fields.trusted,
    unauthorized         = config.fields.unauthorized,
    utc_offset           = config.fields.utc_offset,
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
validator(config.entity)

---@type doorbell.schema.object
config.input = {
  title = "doorbell.config",
  description = "Doorbell runtime configuration input",
  type = "object",

  properties = {
    allow              = config.fields.allow,
    approvals          = config.fields.approvals,
    auth               = config.fields.auth,
    asset_path         = config.fields.asset_path,
    base_url           = config.fields.base_url,
    cache_size         = config.fields.cache_size,
    deny               = config.fields.deny,
    geoip_asn_db       = config.fields.geoip_asn_db,
    geoip_city_db      = config.fields.geoip_city_db,
    geoip_country_db   = config.fields.geoip_country_db,
    log_path           = config.fields.log_path,
    metrics            = config.fields.metrics,
    network_tags       = config.fields.network_tags,
    notify             = config.fields.notify,
    ota                = config.fields.ota,
    redirect_uri       = config.fields.redirect_uri,
    runtime_path       = config.fields.runtime_path,
    state_path         = config.fields.state_path,
    trusted            = config.fields.trusted,
    unauthorized       = config.fields.unauthorized,
    utc_offset         = config.fields.utc_offset,
  },

  additionalProperties = false,

  post_validate = validate_config,
}
validator(config.input)


local auth = {}

auth.common = {}

auth.common.action  = { enum = util.table_values(const.actions) }
auth.common.scope   = { enum = util.table_values(const.scopes) }
auth.common.subject = { enum = util.table_values(const.subjects) }
auth.common.token   = { type = "string" }
auth.common.ttl     = { type = "number" }


---@class doorbell.forwarded_request : table
---@field addr     string
---@field asn?     integer
---@field scheme   string
---@field host     string
---@field uri      string
---@field org?     string
---@field path     string
---@field method   string
---@field ua       string
---@field country? string


---@type doorbell.schema.object
auth.forwarded_request = {
  description = "summary of a request submitted via the forward auth endpoint",
  type = "object",

  properties = {
    addr    = { type = "string" },
    asn     = { type = "integer" },
    country = { type = "string" },
    host    = { type = "string" },
    method  = { type = "string" },
    org     = { type = "string" },
    path    = { type = "string" },
    scheme  = { type = "string" },
    ua      = { type = "string" },
    uri     = { type = "string" },
  },

  required = {
    "addr",
    "scheme",
    "host",
    "uri",
    "path",
    "method",
  },

  additionalProperties = false,

}


auth.access = {}


---@class doorbell.auth.access.pre-approval
---
---@field created number
---@field scope   doorbell.scope
---@field subject doorbell.subject
---@field token   string
---@field ttl     number


---@type doorbell.schema.object
auth.access.pre_approval = {
  title       = "doorbell.auth.access.pre-approval",
  description = "represents a pre-approval for a pending request",
  type        = "object",

  properties = {
    created      = { type = "number" },
    scope        = auth.common.scope,
    subject      = auth.common.subject,
    token        = auth.common.token,
    ttl          = auth.common.ttl,
  },

  required = { "created", "scope", "subject", "token", "ttl" },

  additionalProperties = false,
}


---@class doorbell.auth.access.pending
---
---@field request doorbell.forwarded_request
---
---@field created number
---
---@field token string



---@type doorbell.schema.object
auth.access.pending = {
  title       = "doorbell.auth.access.pending",
  description = "represents a pending access request",
  type = "object",

  properties = {
    token        = auth.common.token,
    created      = { type = "number" },
    request      = auth.forwarded_request,
  },

  required = { "token", "created", "request" },

  additionalProperties = false,
}


auth.access.api = {}

---@class doorbell.auth.access.api.pre-approval
---
---@field scope   doorbell.scope
---@field subject doorbell.subject
---@field ttl     number


---@type doorbell.schema.object
auth.access.api.pre_approval = {
  title       = "doorbell.auth.access.api.pre-approval",
  description = "parameters for creating a pre-approval",
  type        = "object",

  properties = {
    scope        = auth.common.scope,
    subject      = auth.common.subject,
    ttl          = auth.common.ttl,
  },

  required = { "scope", "subject", "ttl" },

  additionalProperties = false,
}
validator(auth.access.api.pre_approval)


---@class doorbell.auth.access.api.intent
---
---@field action  doorbell.action
---@field scope   doorbell.scope
---@field subject doorbell.subject
---@field token   string
---@field ttl     number


---@type doorbell.schema.object
auth.access.api.intent = {
  title       = "doorbell.auth.access.api.intent",
  description = "approves or denies an access request",
  type        = "object",

  properties = {
    action  = auth.common.action,
    scope   = auth.common.scope,
    subject = auth.common.subject,
    token   = auth.common.token,
    ttl     = auth.common.ttl,
  },

  required = {
    "token",
    "action",
    "ttl",
    "scope",
    "subject",
  },

  additionalProperties = false,
}
validator(auth.access.api.intent)



return {
  auth = auth,
  rule = rule,
  config = config,
}
