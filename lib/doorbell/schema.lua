local const = require "doorbell.constants"
local valid_uuid = require("resty.jit-uuid").is_valid
local ip = require "doorbell.ip"
local http = require "doorbell.http"
local util = require "doorbell.util"
local isarray = require "table.isarray"

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
      assert(type(s.properties) == "table")

      for name, sub in pairs(s.properties) do
        value[name] = map_schema(sub, value[name], cb)
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
end

---@class doorbell.schema.example : table
---
---@field summary string
---@field value   any


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
---
---@field validate fun(value:any):boolean?, string?
---
---@field examples doorbell.schema.example[]
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
---@field exclusiveMinimum number
---@field exclusiveMaximum number


---@class doorbell.schema.boolean : doorbell.schema.base
---
---@field type "boolean"

---@alias doorbell.schema
---| doorbell.schema.object
---| doorbell.schema.array
---| doorbell.schema.string
---| doorbell.schema.boolean
---| doorbell.schema.number


---@generic T
---@param t T
---@return T
local function serialize(t)
  local typ = type(t)

  if typ == "table" then
    local new = {}

    for k, v in pairs(t) do
      local sk = serialize(k)

      if sk ~= nil then
        new[sk] = serialize(v)
      end
    end

    t = new

  elseif typ == "function" then
    t = nil
  end

  return t
end


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
  example = 1683229474.686,
}

rule.fields.ttl = {
  description = "Relative timestamp (in seconds) of the rule's expiration",
  type = "number",
  exclusiveMinimum = 0,
  minimum = 0,
  example = 3600,
}

rule.fields.id = {
  description = "Universally unique identifier (UUID) for this rule",
  type = "string",
  minLength = 36,
  maxLength = 36,
  pattern = "^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$",
  post_validate = valid_uuid,
  example = "92f05a2a-0310-45c6-842f-c34d16363051",
}

rule.fields.host = {
  description = "Request Host header",
  type = "string",
  minLength = 1,
  format = "hostname",
  example = "example.com",
}

rule.fields.ua = {
  description = "Request User-Agent header",
  type = "string",
  minLength = 0,
  examples = {
    {
      summary = "match 'my specific user agent' exactly",
      value   = "my specific user agent",
    },
    {
      summary = "regex match",
      value   = "~.*my regex user agent match version: [0-9]+.*",
    },
  },
  example = "curl/7.85.0",
}

rule.fields.path = {
  description = "Request path",
  type = "string",
  minLength = 1,
  examples = {
    { summary = "match '/foo' exactly", value = "/foo" },
    { summary = "match paths that start with '/foo'", value = "~^/foo/.+" },
  },
  example = "~^/api/.+",
}

rule.fields.addr = {
  description = "Client IP address of the request",
  type = "string",
  minLength = 1,
  examples = {
    { summary = "IPv4", value = "1.2.3.4" },
    { summary = "IPv6", value = "2607:f8b0:400a:800::200e" },
  },
  post_validate = validate_ip_addr,
  example = "10.11.12.13",
}

rule.fields.cidr = {
  description = "Subnet (in CIDR notation)",
  type = "string",
  minLength = 1,
  pattern = ".+/([0-9]+)$",
  examples = {
    { summary = "match IPv4 addresses 1.2.3.0-1.2.3.255",
      value = "1.2.3.0/24" },
  },
  post_validate = validate_cidr,
  example = "10.0.0.0/24",
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
  example = 1683229474.686,
}

rule.fields.terminate = {
  description = "If `true`, do not attempt to match any other rules after this one",
  type = "boolean",
}

rule.fields.comment = {
  description = "An informative comment about the rule",
  type = "string",
  minLength = 1,
  example = "Allow access to ^/api/+ for 10.0.3.2",
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
  example = "8e195d0137c229447f423ffd83a1858b",
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
  example = "GOOGLE-CLOUD-PLATFORM",
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

  examples = {
    {
      summary = "allow requests to foo.com from 1.2.3.4",
      value = {
        addr   = "1.2.3.4",
        host   = "foo.com",
        action = "allow",
      },
    },

    {
      summary = "allow all GET requests foo.com/public/*",
      value = {
        host   = "foo.com",
        method = "GET",
        path   = "~^/public/.+",
        action = "allow",
      },
    },

    {
      summary = "explicitly deny access from a particular subnet",
      value = {
        cidr   = "4.2.3.0/24",
        action = "deny",
      },
    },

    {
      summary = "allow an IP to access all hosts for the next hour",
      value = {
        addr   = "1.2.3.4",
        ttl    = 60 * 60,
        action = "allow",
      },
    },


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

  examples = {
    {
      summary = "change a rule action from deny to allow",
      value = {
        action = "allow",
      }
    },

    {
      summary = "update the expiration time for a rule to 10 minutes from now",
      value = {
        ttl = 10 * 60,
      }
    },

    {
      summary = "remove the host condition from a rule and add/update a method condition",
      value = {
        host = ngx.null,
        method = "GET",
      }
    },

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
  default = {},
  examples = {
    {
      summary = "allow requests to all hosts from private networks",
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
      summary = "deny requests from a pesky bot",
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
    { summary = "trust localhost and two private networks",
      value   = { "127.0.0.1", "10.0.3.1", "10.0.4.0/24" },
    },

    { summary = "trust localhost only",
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
      exclusiveMinimum = const.testing and 0 or 60,
      minimum = const.testing and 0 or 60,
      default = 60,
    }
  },
  required = { "url" },

  examples = {
    {
      summary = "update rules from https://foo.com/rules.json every 15 minutes",
      value = {
        url = "https://foo.com/rules.json",
        interval = 60 * 15,
      },
    },

    {
      summary = "sending additional headers with the request",
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
      exclusiveMinimum = 5,
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
          summary = "send notifications between 9pm and midnight",
          value = { { from = 21 } },
        },

        {
          summary = "send notifications between 8am and 6pm",
          value = { { from = 8,  to = 18 } },
        },

        {
          summary = "send notifactions between 9am-1pm and 8pm-10pm",
          value = {
            { from = 9, to = 13 },
            { from = 20, to = 22 },
          },
        },

        {
          summary = "send notifactions between 11pm and 3am",
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
      summary = "explicitly disable notifications",
      value = {
        strategy = "none",
      },
    },
  },
}
config.fields.notify.validate = validator(config.fields.notify)

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
    redirect_uri         = config.fields.redirect_uri,
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
    redirect_uri       = config.fields.redirect_uri,
    runtime_path       = config.fields.runtime_path,
    state_path         = config.fields.state_path,
    trusted            = config.fields.trusted,
    unauthorized       = config.fields.unauthorized,
  },

  additionalProperties = false,

  post_validate = validate_config,
}
config.input.validate = validator(config.input)


local api = {}

do
  local JSON = "application/json"
  local PLAIN = "text/plain"
  local REF = "$ref"

  local TAG = {
    RULES  = {
      name = "rules",
      description = "CRUD operations for Doorbell rule objects",
    },

    SCHEMA = {
      name = "schema",
      description = "JSONSchema and OpenAPI endpoints",
    },

    IP_INFO = {
      name = "ip-info",
      description = "Endpoints for retrieving IP address information",
    },
  }

  local OP_ID = {
    LIST_RULES         = "list-rules",
    CREATE_RULE        = "create-rule",
    GET_RULE           = "get-rule",
    UPDATE_RULE        = "update-rule",
    DELETE_RULE        = "delete-rule",
    GET_CLIENT_IP      = "get-client-ip-addr",
    GET_CLIENT_IP_INFO = "get-client-ip-addr-info",
    GET_IP_INFO        = "get-ip-addr-info",
  }

  api.openapi = "3.0.3"

  api.info = {
    title = "Doorbell API",
    description = "_A forward auth server for the rest of us._",
    version = const.version,
    license = nil,
  }

  api.tags = {
    TAG.RULES,
    TAG.SCHEMA,
    TAG.IP_INFO,
  }

  api.components = {
    headers       = {},
    links         = {},
    parameters    = {},
    requestBodies = {},
    responses     = {},
    schemas       = {},
  }

  ---@param typ "headers"|"links"|"parameters"|"requestBodies"|"responses"|"schemas"
  ---@param id string
  ---@return table
  local function ref(typ, id)
    assert(api.components[typ], "Unknown component type: " .. typ)
    assert(api.components[typ][id], "Unknown " .. typ .. " id: " .. id)
    return { [REF] = "#/components/" .. typ .. "/" .. id }
  end

  api.components.schemas.Rule = serialize(rule.entity)
  api.components.schemas.RuleCreate = serialize(rule.create)
  api.components.schemas.RuleUpdate = serialize(rule.patch)

  api.components.schemas.IpAddr = {
    type = "string",
    description = "An IPv4 or IPv6 address",
    examples = {
      { summary = "ipv4", value = "10.11.12.13" },
      { summary = "ipv6", value = "2607:f8b0:400a:80b::200e" },
    }
  }

  local optional_string = {
    type = "string",
    --required = false,
    nullable = true,
  }

  local optional_number = {
    type = "number",
    --required = false,
    nullable = true,
  }


  api.components.schemas.IpInfo = {
    description = "GeoIP information about an IP address",
    type = "object",
    properties = {
      addr           = ref("schemas", "IpAddr"),
      asn            = { type = "integer", nullable = true },
      city           = optional_string,
      continent      = optional_string,
      continent_code = optional_string,
      country        = optional_string,
      country_code   = optional_string,
      latitude       = optional_number,
      longitude      = optional_number,
      org            = optional_string,
      postal_code    = optional_string,
      region         = optional_string,
      region_code    = optional_string,
      time_zone      = optional_string,
    },
    examples = {
      {
        value = {
          addr           = "87.236.176.241",
          asn            = 211298,
          continent      = "Europe",
          continent_code = "EU",
          country        = "United Kingdom",
          country_code   = "GB",
          latitude       = 51.4964,
          longitude      = -0.1224,
          org            = "Constantine Cybersecurity Ltd.",
          time_zone      = "Europe/London"
        },
      },

      {
        value = {
          addr           = "99.196.130.195",
          asn            = 7155,
          continent      = "North America",
          continent_code = "NA",
          country        = "United States",
          country_code   = "US",
          latitude       = 37.751,
          longitude      = -97.822,
          org            = "VIASAT-SP-BACKBONE",
          time_zone      = "America/Chicago",
        },
      },
    },
  }


  api.components.schemas.ApiError = {
    type = "object",
    properties = {
      error = {
        type = "string",
      }
    },
    additionalProperties = true,
  }

  api.components.responses.NotFound = {
    description = "Not Found",
    content = {
      [JSON] = { schema = ref("schemas", "ApiError") },
    }
  }

  api.components.responses.BadRequest = {
    description = "Bad Request/Invalid Input",
    content = {
      [JSON] = { schema = ref("schemas", "ApiError") },
    }
  }

  api.components.responses.Rule = {
    content = {
      [JSON] = { schema = ref("schemas", "Rule") },
    }
  }

  api.components.responses.NoContent = {
    description = "No Content",
    content = {},
  }

  api.components.responses.ServerError = {
    description = "Internal Server Error",
    content = {
      [JSON] = { schema = ref("schemas", "ApiError") }
    }
  }

  api.components.responses.IpInfo = {
    description = "GeoIP Address Info",
    content = {
      [JSON] = { schema = ref("schemas", "IpInfo") },
    }
  }

  api.components.parameters.RuleId = {
    name            = "rule_id_or_hash",
    ["in"]          = "path",
    required        = true,
    description     = "A rule UUID or or 32 character hash",
    deprecated      = false,
    allowEmptyValue = false,
    schema          = {
      type = "string",
    },
    examples = {
      uuid = {
        summary = "uuid",
        value = "0289a45a-2c32-48f0-9fee-559c5ab73c27",
      },

      hash = {
        summary = "hash",
        value = "8e195d0137c229447f423ffd83a1858b",
      }
    }
  }


  api.paths = {}
  api.paths["/rules"] = {
    description = "List and create rule objects",
  }

  api.paths["/rules"].get = {
    tags        = { TAG.RULES.name },
    description = "List all rule objects",
    operationId = OP_ID.LIST_RULES,
    responses   = {
      ["200"] = {
        description = "List of all current rules",
        content = {
          [JSON] = {
            schema = {
              type = "object",
              properties = {
                data = {
                  type = "array",
                  items = ref("schemas", "Rule"),
                }
              },
            },
          }
        }
      },
    },
    deprecated  = false,
  }

  api.paths["/rules"].post = {
    tags        = { TAG.RULES.name },
    description = "Create a new rule",
    operationId = OP_ID.CREATE_RULE,
    requestBody = {
      description = "Rule object to create",
      required    = true,
      content     = {
        [JSON] = { schema = ref("schemas", "RuleCreate") },
      },
    },
    responses = {
      ["201"] = ref("responses", "Rule"),
      ["400"] = ref("responses", "BadRequest"),
      ["500"] = ref("responses", "ServerError"),
    },
    deprecated  = false,
  }

  api.paths["/rules/{rule_id_or_hash}"] = {
    description = "CRUD operations for individual rule objects",
    parameters  = { ref("parameters", "RuleId") },
  }

  api.paths["/rules/{rule_id_or_hash}"].get = {
    tags        = { TAG.RULES.name },
    description = "Retrieve a rule object by ID or hash",
    operationId = OP_ID.GET_RULE,
    responses   = {
      ["200"] = ref("responses", "Rule"),
      ["404"] = ref("responses", "NotFound"),
    },
    deprecated  = false,
  }

  api.paths["/rules/{rule_id_or_hash}"].patch = {
    tags        = { TAG.RULES.name },
    description = "Update rule object by ID or hash",
    operationId = OP_ID.UPDATE_RULE,
    requestBody = {
      description = "Updates to the rule object",
      required    = true,
      content     = {
        [JSON] = { schema = ref("schemas", "RuleUpdate") },
      },
    },
    responses   = {
      ["200"] = ref("responses", "Rule"),
      ["400"] = ref("responses", "BadRequest"),
      ["404"] = ref("responses", "NotFound"),
    },
    deprecated  = false,
  }

  api.paths["/rules/{rule_id_or_hash}"].delete = {
    tags        = { TAG.RULES.name },
    description = "Delete rule object by ID or hash",
    operationId = OP_ID.DELETE_RULE,
    responses   = {
      ["404"] = ref("responses", "NotFound"),
      ["204"] = ref("responses", "NoContent"),
      ["500"] = ref("responses", "ServerError"),
    },
    deprecated  = false,
  }


  api.paths["/ip/addr"] = {
    get = {
      description = "Retrieve the client IP address",
      operationId = OP_ID.GET_CLIENT_IP,
      tags        = { TAG.IP_INFO.name },
      deprecated  = false,
      responses = {
        ["200"] = {
          description = "The IP Address",
          content = {
            [PLAIN] = { schema = ref("schemas", "IpAddr") },
          },
        }
      }
    }
  }

  api.paths["/ip/info"] = {
    get = {
      description = "Retrieve client IP address info",
      operationId = OP_ID.GET_CLIENT_IP_INFO,
      tags        = { TAG.IP_INFO.name },
      deprecated  = false,
      responses = {
        ["200"] = {
          description = "GeoIP Address Info",
          content = {
            [JSON] = { schema = ref("schemas", "IpInfo") },
          }
        }
      }
    }
  }
end

return {
  rule = rule,
  config = config,
  api = api,
}
