local routes = {}

local http    = require "doorbell.http"
local router  = require "doorbell.router"
local schema  = require "doorbell.schema"
local mw      = require "doorbell.middleware"
local request = require "doorbell.request"

local send = http.send
local get_json_body = request.get_json_body


---@param t any
---@return any
local function drop_functions(t)
  local typ = type(t)

  if typ == "table" then
    local new = {}
    for k, v in pairs(t) do
      new[k] = drop_functions(v)
    end
    t = new

  elseif typ == "function" then
    t = nil
  end

  return t
end

local middleware      = {
  [mw.phase.REWRITE] = {
    request.middleware.enable_logging,
  },
}

---@param obj table
local function schema_api(obj)
  local serialized = drop_functions(obj)
  local api = {
    metrics_enabled = true,
    allow_untrusted = true,
    content_type    = "application/json",
    middleware      = middleware,

    GET = function()
      return send(200, serialized)
    end,
  }

  if type(obj.validate) == "function" then
    api.PUT = function(ctx)
      local json = get_json_body(ctx, "table")

      local ok, err = obj.validate(json)

      if ok then
        send(200, json)
      else
        send(400, { message = err })
      end
    end
  end

  return api
end

router["/schema/config"]        = schema_api(schema.config)
router["/schema/config/fields"] = schema_api(schema.config.fields)
router["/schema/config/input"]  = schema_api(schema.config.fields)
router["/schema/config/entity"] = schema_api(schema.config.entity)

for name, field in pairs(schema.config.fields) do
  router["/schema/config/fields/" .. name] = schema_api(field)
end

router["/schema/rule"]          = schema_api(schema.rule)
router["/schema/rule/fields"]   = schema_api(schema.rule.fields)
router["/schema/rule/patch"]    = schema_api(schema.rule.patch)
router["/schema/rule/create"]   = schema_api(schema.rule.create)
router["/schema/rule/entity"]   = schema_api(schema.rule.entity)

for name, field in pairs(schema.rule.fields) do
  router["/schema/rule/fields/" .. name] = schema_api(field)
end


return routes

