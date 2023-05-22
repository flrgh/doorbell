local _M = {}

local http      = require "doorbell.http"
local util      = require "doorbell.util"
local request   = require "doorbell.request"


local get_json_body        = request.get_json_body
local get_post_args        = request.get_post_args
local get_request_header   = request.get_header
local send                 = http.send
local NULL                 = ngx.null
local lower                = string.lower

local type     = type
local tonumber = tonumber
local tostring = tostring


---@param value any
---@param s doorbell.schema
local function coerce_type(value, s)
  local stype = s and s.type

  if not stype then
    return value
  end

  local vtype = type(value)

  local is_bool   = vtype == "boolean"
  local is_nil    = value == nil
  local is_null   = value == NULL
  local is_number = vtype == "number"
  local is_string = vtype == "string"
  local is_table  = vtype == "table"

  local is_primitive = is_bool
                    or is_string
                    or is_number
                    or is_nil
                    or is_null

  if is_null then
    is_nil = true
    value = nil
  end

  if is_nil then
    return value
  end

  if stype == "number" or stype == "integer" then
    if not is_number then
      value = tonumber(value) or value
    end

  elseif stype == "string" and not is_string then
    if is_primitive then
      value = tostring(value)
    end

  elseif stype == "boolean" and not is_bool then
    if util.truthy(value) then
      value = true

    elseif util.falsy(value) then
      value = false
    end

  elseif stype == "array" then
    local arr

    if is_string then
      arr = util.split_at_comma(value)

    elseif is_table then
      arr = value
    end

    if arr then
      local n = 0
      for i = 1, #arr do
        local v = coerce_type(arr[i], s.items)
        if v ~= nil then
          n = n + 1
          arr[n] = v
        else
          arr[i] = nil
        end
      end
    end

    value = arr or value

  elseif stype == "object" then
    local obj

    if is_table then
      if s.properties then
        obj = {}
        for k, v in pairs(value) do
          obj[k] = coerce_type(v, s.properties[k])
        end
      else
        obj = value
      end
    end

    value = obj or value
  end

  return value
end


_M.coerce_type = coerce_type

_M.send = send

do
  local JSON = "json"
  local FORM = "form"

  local ctype_handler = {
    ["application/json"] = function(ctx, optional)
      return get_json_body(ctx, "table", optional), JSON
    end,

    ["application/x-www-form-urlencoded"] = function(ctx, optional)
      return get_post_args(ctx, optional), FORM
    end,
  }

  local E = "Unsupported Content-Type; expected one of "
            .. table.concat(util.table_keys(ctype_handler), ", ")


  --- Checks the request content type and either parses the body as JSON or
  --- as x-www-form-urlencoded input
  ---
  ---@param  ctx     doorbell.ctx
  ---@param  s       doorbell.schema
  ---@return table?
  ---@return string? content_type
  function _M.get_request_input(ctx, s)
    local ctype = get_request_header(ctx, "content-type")

    local handler

    if ctype then
      handler = ctype_handler[lower(ctype)]

    else
      ctype = ""
    end


    if not handler then
      return send(400, { error = E, ["content-type"] = ctype })
    end

    local body, typ = handler(ctx, false)

    if typ == FORM then
      body = coerce_type(body, s)
    end

    return body
  end
end



return _M
