local const = require "doorbell.constants"
local parse_uri = require("resty.http").parse_uri
local valid_uuid = require("resty.jit-uuid").is_valid
local ip = require "doorbell.ip"

--local generate_validator = require("jsonschema").generate_validator
local generate_validator = require("resty.ljsonschema").generate_validator


local function noop(_) return true end

local function validator(schema)
  local name = assert(schema.title)
  local validate_schema = assert(generate_validator(schema, { name = name }))
  local extra_validator = schema.extra_validator or noop

  return function(value)
    local ok, err = validate_schema(value)

    if ok then
      ok, err = extra_validator(value)
    end

    if not ok then
      return nil, err
    end

    return true
  end
end


---@param cidr string
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
  end

  local addr, mask = cidr:match("(.+)/(.+)")

  local typ = ip.is_valid(addr)

  if not typ then
    return nil, "invalid CIDR: " .. cidr
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


---@param rule doorbell.rule.new.opts
---@return boolean? ok
---@return string? error
local function validate_rule(rule)
  if rule.id and not valid_uuid(rule.id) then
    return nil, "invalid id"
  end

  if rule.addr and not ip.is_valid(rule.addr) then
    return nil, "invalid IP address: " .. rule.addr
  end

  if rule.cidr then
    local ok, err = validate_cidr(rule.cidr)
    if not ok then
      return nil, "invalid cidr: " .. tostring(err)
    end
  end

  if rule.terminate then
    if require("doorbell.rules").count_conditions(rule) > 1 then
      return nil, "can only have one match condition with `terminate`"
    end
  end

  if rule.expires and rule.expires > 0 then
    ngx.update_time()
    if rule.expires <= ngx.now() then
      return nil, "rule is already expired"
    end
  end

  return true
end

---@param config doorbell.config
---@return boolean? ok
---@return string? error
local function validate_config(config)
  if config.trusted then
    local ok, err = validate_cidr(config.trusted)
    if not ok then
      return nil, "invalid trusted IP cidrs: " .. tostring(err)
    end
  end

  if config.base_url then
    local ok, err = parse_uri(nil, config.base_url)
    if not ok then
      return nil, "invalid base_url: " .. tostring(err)
    end
  end

  return true
end


---@param t table<string, any>
---@return string[]
local function keys(t)
  local _keys = {}
  for k in pairs(t) do
    table.insert(_keys, k)
  end

  table.sort(_keys)

  return _keys
end

local rule = {}
rule.fields = {}
rule.fields.action = {
  description = "Action to take when the rule matches a request",
  type = "string",
  enum = keys(const.actions),
}

rule.fields.source = {
  description = "Origin of the rule",
  type = "string",
  enum = keys(const.sources),
}

rule.fields.expires = {
  description = "Absolute timestamp (as a Unix epoch) that dictates when the rule expires",
  type = "number",
  minimum = 0,
}

rule.fields.ttl = {
  description = "Relative timestamp (in seconds) of the rule's expiration",
  type = "number",
  exclusiveMinimum = 0,
}

rule.fields.uuid = {
  description = "Universally unique identifier (UUID) for this rule",
  type = "string",
  minLength = 36,
  maxLength = 36,
  pattern = "^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$",
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
}

rule.fields.cidr = {
  description = "Subnet (in CIDR notation)",
  type = "string",
  minLength = 1,
  pattern = ".+/([0-9]+)$",
  examples = {
    "1.2.3.0/24",
  },
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
  enum = keys(const.deny_actions),
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
  enum = keys(require("doorbell.ip.countries")),
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

local function required(name)
  return {
    type = "object",
    properties = {
      [name] = assert(rule.fields[name]),
    },
    required = { name },
    additionalProperties = true,
  }
end

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
  },
}

rule.policy.expires_or_ttl = {
  description = "`expires` and `ttl` are mutually exclusive",
  oneOf = {
    {
      properties = { expires = { type = "null" },
                         ttl = rule.fields.ttl },
      required = { "ttl" },
      additionalProperties = true
    },
    {
      properties = { expires = rule.fields.expires,
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
      action = { enum = { const.actions.allow } },
      deny_action = { type = "string" },
    },
    required = { "deny_action", "action" },
  },
}


rule.entity = {
  title = "rule",
  description  = "Doorbell rule object",
  type = "object",

  properties = {
    action      = rule.fields.action,
    deny_action = rule.fields.deny_action,
    addr        = rule.fields.addr,
    cidr        = rule.fields.cidr,
    comment     = rule.fields.comment,
    conditions  = rule.fields.conditions,
    created     = rule.fields.created,
    expires     = rule.fields.expires,
    hash        = rule.fields.hash,
    host        = rule.fields.host,
    id          = rule.fields.uuid,
    method      = rule.fields.method,
    path        = rule.fields.path,
    source      = rule.fields.source,
    terminate   = rule.fields.terminate,
    ua          = rule.fields.ua,
  },

  required = {
    "action",
    "source",
    "id",
  },
  allOf = {
    rule.policy.deny_action_deny,
    rule.policy.at_least_one_condition,
  },
  extra_validator = validate_rule,
}
rule.entity.validate = validator(rule.entity)

rule.create = {
  title = "doorbell.rule.create",
  description = "Schema for rule creation",
  allOf = {
    {
      description = "Core properties",
      type = "object",
      required = { "action", "source" },
      properties = {
        action      = rule.fields.action,
        deny_action = rule.fields.deny_action,
        addr        = rule.fields.addr,
        cidr        = rule.fields.cidr,
        comment     = rule.fields.comment,
        created     = rule.fields.created,
        country     = rule.fields.country,
        expires     = rule.fields.expires,
        host        = rule.fields.host,
        id          = rule.fields.uuid,
        method      = rule.fields.method,
        path        = rule.fields.path,
        source      = rule.fields.source,
        terminate   = rule.fields.terminate,
        ttl         = rule.fields.ttl,
        ua          = rule.fields.ua,
      },
      additionalProperties = false,
    },
    rule.policy.at_least_one_condition,
    rule.policy.expires_or_ttl,
    rule.policy.deny_action_deny,
  },
  extra_validator = validate_rule,
}
rule.create.validate = validator(rule.create)

rule.patch = {
  title = "doorbell.rule.patch",
  description = "schema for rule PATCH request body",
  type = "object",
  properties = {
    action      = rule.fields.action,
    deny_action = rule.fields.deny_action,
    addr        = rule.fields.addr,
    cidr        = rule.fields.cidr,
    comment     = rule.fields.comment,
    country     = rule.fields.country,
    expires     = rule.fields.expires,
    host        = rule.fields.host,
    method      = rule.fields.method,
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
  extra_validator = validate_rule,
}
rule.patch.validate = validator(rule.patch)


local config = {}

local conf_rule = {
  type = "object",
  properties = {
    addr        = rule.fields.addr,
    cidr        = rule.fields.cidr,
    comment     = rule.fields.comment,
    country     = rule.fields.country,
    host        = rule.fields.host,
    method      = rule.fields.method,
    path        = rule.fields.path,
    ua          = rule.fields.ua,
    deny_action = rule.fields.deny_action,
    terminate   = rule.fields.terminate,
  },
  additionalProperties = false,
  anyOf = {
    required("addr"),
    required("cidr"),
    required("host"),
    required("country"),
    required("method"),
    required("path"),
    required("ua"),
  }
}

config.fields = {}
config.fields.allow = {
  description = "static allow rules",
  type = "array",
  items = conf_rule,
  default = {},
}

config.fields.deny = {
  description = "static deny rules",
  type = "array",
  items = conf_rule,
  default = {},
}

config.fields.asset_dir = {
  description = "Directory containing static assets for the application",
  type = "string",
  default = "/usr/local/share/doorbell",
}

config.fields.base_url = {
  description = "External URL for the application (used to generate hyperlinks)",
  type = "string",
  minLength = 1,
}

config.fields.cache_size = {
  description = "Dictates the number of items kept in the application's LRU cache",
  type = "integer",
  exclusiveMinimum = 1000,
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
  }
}

config.fields.log_dir = {
  description = "Path to the directory where log files will be stored",
  type = "string",
  minLength = 1,
  default = "/var/log/doorbell",
}

config.fields.runtime_dir = {
  description = "State directory (where nginx.conf and rules state are stored)",
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
      additionalProperties = {},
    },

    interval = {
      description = "How often (in seconds) to check for remote updates",
      type = "number",
      exclusiveMinimum = 0,
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
      exclusiveMinimum = 0,
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

config.object = {
  description = "Doorbell runtime configuration object",
  type = "object",
  properties = {
    allow       = config.fields.allow,
    asset_dir   = config.fields.asset_dir,
    base_url    = config.fields.base_url,
    cache_size  = config.fields.cache_size,
    deny        = config.fields.deny,
    host        = config.fields.host,
    log_dir     = config.fields.log_dir,
    metrics     = config.fields.metrics,
    notify      = config.fields.notify,
    ota         = config.fields.ota,
    runtime_dir = config.fields.runtime_dir,
    trusted     = config.fields.trusted,
  },
  additionalProperties = false,
  required = {
    "asset_dir",
    "base_url",
    "cache_size",
    "host",
    "log_dir",
    "runtime_dir",
    "trusted",
  }
}

config.input = {
  title = "doorbell.config",
  description = "Doorbell runtime configuration input",
  type = "object",
  properties = {
    allow       = config.fields.allow,
    asset_dir   = config.fields.asset_dir,
    base_url    = config.fields.base_url,
    cache_size  = config.fields.cache_size,
    deny        = config.fields.deny,
    host        = config.fields.host,
    log_dir     = config.fields.log_dir,
    metrics     = config.fields.metrics,
    notify      = config.fields.notify,
    ota         = config.fields.ota,
    runtime_dir = config.fields.runtime_dir,
    trusted     = config.fields.trusted,
  },
  additionalProperties = false,
  required = {
    "base_url",
  },
  extra_validator = validate_config,
}
config.input.validate = validator(config.input)

return {
  rule = rule,
  config = config,
}
