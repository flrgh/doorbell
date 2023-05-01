---@class doorbell.config : table
---
---@field allow            doorbell.rule[]
---@field asset_dir        string
---@field base_url         string
---@field cache_size       integer
---@field deny             doorbell.rule[]
---@field geoip_asn_db     string
---@field geoip_city_db    string
---@field geoip_country_db string
---@field host             string
---@field log_dir          string
---@field notify           doorbell.notify.config
---@field runtime_dir      string
---@field trusted          string[]
---@field metrics          doorbell.metrics.config
---@field ota?             doorbell.ota.config
---@field unauthorized     doorbell.unauthorized
local _M = {
  _VERSION = require("doorbell.constants").version,
}

local util = require "doorbell.util"
local http = require "doorbell.http"
local const = require "doorbell.constants"
local pl_path = require "pl.path"
local cjson_safe = require "cjson.safe"
local schema = require "doorbell.schema"

local getenv = os.getenv
local fmt = string.format

local ngx_prefix = ngx.config.prefix()
local prefix = getenv("DOORBELL_RUNTIME_DIR") or ngx_prefix


---@param s string
---@return string[]
local function split_at_comma(s)
  local items = {}
  local _ = s:gsub("[^,]+", function(word)
    word = word:gsub("^%s+", ""):gsub("%s+$", "")
    table.insert(items, word)
  end)
  return items
end


---@param path string
---@return boolean? ok
---@return string? error
local function is_dir(path)
  if pl_path.exists(path) then
    if pl_path.isdir(path) then
      return true
    end

    return nil, fmt("%q is not a directory", path)
  end

  return nil, fmt("%q does not exist", path)
end


---@param path string
---@return boolean? ok
---@return string? error
local function is_file(path)
  if pl_path.exists(path) then
    if pl_path.isfile(path) then
      return true
    end

    return nil, fmt("%q is not a regular file", path)
  end

  return nil, fmt("%q does not exist", path)
end



---@param name string
---@return string
local function require_env(name)
  local value = getenv(name)
  if value == nil then
    util.errorf("env var %q is unset", name)
  elseif value == "" then
    util.errorf("env var %q is empty", name)
  end
  return value
end


local function iter_keys(t)
  local keys = {}
  for k in pairs(t) do
    table.insert(keys, k)
  end

  local i = 0
  return function()
    i = i + 1
    return keys[i]
  end
end


---@generic T : table|string
---@param t T
---@return T
local function replace_env(t)
  local typ = type(t)
  if typ == "string" then
    t = t:gsub("%${%s*([a-zA-Z0-9_]+)%s*}", require_env)
  elseif typ == "table" then
    for k in iter_keys(t) do
      t[k] = replace_env(t[k])
    end
  end

  return t
end


---@param exp string
---@return fun(any):boolean?, string?
local function is_type(exp)
  return function(v)
    local got = type(v)
    if got == exp then
      return true
    end
    return nil, "expected: " .. exp .. ", got: " .. got
  end
end


---@param funcs function[]
---@return fun(any):boolean?, string?
local function all(funcs)
  return function(v)
    for _, fn in ipairs(funcs) do
      local ok, err = fn(v)
      if not ok then
        return nil, err
      end
    end

    return true
  end
end


---@class doorbell.config.field
---
---@field name         string
---@field from_env?    boolean
---@field _validate?    fun(any):boolean?, string?
---@field default?     any
---@field _unserialize? fun(any):any?, string?
---@field required?    boolean
local field_mt = {}


---@param value any
---@return boolean? ok
---@return string? error
function field_mt:validate(value)
  if self._validate then
    local ok, err = self._validate(value)
    if not ok then
      return nil, fmt("invalid value for %s (%q): %s",
                      self.name, value, err)
    end
  end

  return true
end

---@param value any
---@return any? unserialized
---@return string? error
function field_mt:unserialize(value)
  if self._unserialize then
    local unserialized, err = self._unserialize(value)
    if err then
      return nil, fmt("error unserializing %s from %q, %s",
                      self.name, value, err)
    end
    value = unserialized
  end

  return value
end

---@param self doorbell.config.field
---@return any
---@return string? error
function field_mt:get_from_env()
  if not self.from_env then
    return
  end

  local varname = "DOORBELL_" .. self.name:upper()

  local value = getenv(varname)
  if value == nil then
    return
  end

  local err
  value, err = self:unserialize(value)
  if err then
    return nil, fmt("could not unserialize %s: %s", varname, err)
  end

  local ok
  ok, err = self:validate(value)
  if not ok then
    return nil, err
  end

  return value
end



---@type doorbell.config.field[]
local FIELDS = {
  { name = "allow",
    _validate = is_type("table"),
  },

  { name = "asset_dir",
    default = "/usr/local/share/doorbell",
    from_env = true,
    _validate = all {
      is_type("string"),
      is_dir,
    }
  },

  { name = "base_url",
    from_env = true,
    _validate = is_type("string"),
    required = true,
  },

  { name = "cache_size",
    from_env = true,
    default = 1000,
    _validate = is_type("number"),
    _unserialize = tonumber,
  },

  { name = "deny",
    _validate = is_type("table"),
  },

  { name = "geoip_db",
    from_env = true,
    _validate = all {
      is_type("string"),
      is_file,
    }
  },

  { name = "geoip_country_db",
    from_env = true,
    _validate = all {
      is_type("string"),
      is_file,
    }
  },

  { name = "geoip_city_db",
    from_env = true,
    _validate = all {
      is_type("string"),
      is_file,
    }
  },

  { name = "geoip_asn_db",
    from_env = true,
    _validate = all {
      is_type("string"),
      is_file,
    }
  },

  { name = "log_dir",
    from_env = true,
    default = "/var/log/doorbell",
    _validate = all {
      is_type("string"),
      is_dir,
    },
  },

  { name = "notify",
    _validate = is_type("table"),
  },

  { name = "runtime_dir",
    from_env = true,
    default = "/var/run/doorbell",
    _validate = all {
      is_type("string"),
      is_dir,
    },
  },

  { name = "trusted",
    from_env = true,
    _unserialize = split_at_comma,
    _validate = all {
      is_type("table"),
    },
  },

  { name = "metrics",
    _validate = all {
      is_type("table"),
    },
  },

  { name = "ota",
    _validate = is_type("table"),
  },

  { name = "unauthorized",
    from_env = true,
    default = assert(schema.config.fields.unauthorized.default),
    _validate = all {
      is_type("string"),
      function(value)
        for _, policy in pairs(const.unauthorized) do
          if value == policy then
            return true
          end
        end

        return nil, "unknown unauthorized policy"
      end
    },
  },
}

do
  local mt = { __index = field_mt }
  for i = 1, #FIELDS do
    setmetatable(FIELDS[i], mt)
  end
end

function _M.init()
  ngx_prefix = ngx.config.prefix()
  prefix = getenv("DOORBELL_RUNTIME_DIR") or ngx_prefix

  local data, err

  do
    local content = getenv("DOORBELL_CONFIG_STRING")
    local fname
    if content then
      fname = "env://DOORBELL_CONFIG_STRING"

    else
      fname = getenv("DOORBELL_CONFIG")
    end

    if fname and not content then
      content, err = util.read_file(fname)
      if not content then
        util.errorf("failed to open user config file %s: %s",
                    fname, err)
      end

    elseif not content then
      fname = util.join(prefix, "config.json")
      content = util.read_file(fname)
    end

    if content then
      data, err = cjson_safe.decode(content)
      if err then
        util.errorf("config file %s JSON is invalid: %s",
                    fname, err)
      end

    else
      data = {}
    end
  end

  replace_env(data)

  for _, field in ipairs(FIELDS) do
    local value
    value, err = field:get_from_env()

    if err then
      util.errorf(err)
    end

    if value == nil then
      value = data[field.name]
    end

    if value == nil then
      value = field.default

    else
      local ok
      ok, err = field:validate(value)
      if not ok then
        util.errorf(err)
      end
    end

    if value == nil and field.required then
      util.errorf("config.%s is required", field.name)
    end

    _M[field.name] = value
  end

  do
    local parsed = http.parse_url(_M.base_url)
    if not parsed or not parsed.host then
      util.errorf("failed to parse hostname from base_url: %s", _M.base_url)
    end
    _M.host = parsed.host
  end

end

if _G._TEST then
  _M._replace_env = replace_env

  ---@param fn function
  ---@return function
  _M._set_getenv = function(fn)
    local old = getenv
    getenv = fn
    return old
  end
end

return _M
