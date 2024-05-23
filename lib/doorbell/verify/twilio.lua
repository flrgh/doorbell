---@class doorbell.verify.twilio
local _M = {}

local resty_http = require "resty.http"
local cjson = require "cjson.safe"
local shm = require "doorbell.shm"

local SHM = shm.with_namespace("twilio")
local log = require("doorbell.log").with_namespace("twilio")

local fmt = string.format
local ngx = ngx
local now = ngx.now
local encode_args = ngx.encode_args

local TASK_TTL = 60 * 60

---@class doorbell.verify.twilio.conf
---
---@field service_id  string
---@field auth_sid    string
---@field auth_secret string
---@field base_url?   string

---@class doorbell.verify.twilio.verification
---
---@field tel        string
---@field created_at number
---@field id         string?
---@field addr       string

---@type string
local SERVICE_ID

local BASE_URL = "https://verify.twilio.com/v2"
local ENABLED = false

---@type string
local AUTHORIZATION

---@param  path     string
---@param  params   resty.http.request_uri.params
---@return integer? status
---@return table?   json
---@return string?  error
local function twilio_request(path, params)
  local client, err = resty_http.new()
  if not client then
    return nil, nil, "failed constructing http client: " .. tostring(err)
  end

  if not params.headers then
    params.headers = {}
  end

  params.headers["Authorization"] = AUTHORIZATION
  params.headers["Accept"] = "application/json"

  local uri = BASE_URL .. path

  local res
  res, err = client:request_uri(uri, params)

  if not res then
    return nil, nil, "failed sending request: " .. tostring(err)
  end

  local status = res.status

  if not res.body then
    return status
  end

  local ct = res.headers["Content-Type"]
  local json

  if ct and ct:find("application/json") then
    json, err = cjson.decode(res.body)
    if err then
      return nil, nil, "failed decoding response: " .. tostring(err)
    end

  else
    log.warn("Twilio API response for ", params.method, " ", path,
             " did not return a JSON response body")
  end

  return status, json
end

---@param  path     string
---@param  args     table
---@return integer? status
---@return table?   json
---@return string?  error
local function twilio_post(path, args)
  return twilio_request(path, {
    method = "POST",
    body = encode_args(args),
    headers = {
      ["Content-Type"] = "application/x-www-form-urlencoded",
    },
  })
end


---@param context string
---@param status integer
---@param json? table
local function log_bad_response(context, status, json)
  local msg = "<empty response>"

  if json then
    msg = type(json.message) == "string"
      and json.message
       or cjson.encode(json)
  end

  log.notice("Twilio API returned ", status, " while ",
             context, ": ", msg)
end

---@param task doorbell.verify.twilio.verification
local function store_task(task)
  assert(SHM:add(task.tel, task, TASK_TTL))
end

---@param tel string
---@return doorbell.verify.twilio.verification?
local function get_task(tel)
  return SHM:get(tel)
end

---@param task doorbell.verify.twilio.verification
local function destroy_task(task)
  SHM:delete(task.tel)
end


---@param tel string # must be valid, E.164-formatted
---@param addr string # ip address
---@return doorbell.verify.twilio.verification? task
---@return string? error
function _M.new_verify_task(tel, addr)
  assert(ENABLED, "Twilio verification is not enabled")
  assert(type(tel) == "string")

  if SHM:get(tel) then
    return nil, "exists"
  end

  local path = fmt("/Services/%s/Verifications", SERVICE_ID)
  local status, json, err = twilio_post(path, {
    To = tel,
    Channel = "sms",
  })

  if err then
    return nil, "Twilio API http error: " .. tostring(err)

  elseif status ~= 201 then
    log_bad_response("generating a verification", status, json)
    return nil, "Twilio API error"
  end

  local sid = json and json.sid
  if type(sid) ~= "string" then
    log.warn("Twilio verification API did not return a valid SID")
    return nil, "Twilio API error"
  end

  ---@type doorbell.verify.twilio.verification
  local v = {
    tel = tel,
    created_at = now(),
    id = sid,
    addr = addr,
  }

  store_task(v)

  return v
end

---@param tel string
---@param code integer|string
---@return doorbell.verify.twilio.verification? task
---@return string? error
function _M.check_verify(tel, code)
  assert(ENABLED)

  local task = get_task(tel)
  if not task then
    return nil, "no pending verification task"
  end

  local path = fmt("/Services/%s/VerificationCheck", SERVICE_ID)
  local status, json, err = twilio_post(path, {
    VerificationSid = task.id,
    Code = code,
  })

  if err then
    return nil, "Twilio API http error: " .. tostring(err)

  elseif status ~= 200 then
    log_bad_response(fmt("verifying check %s for %s", task.id, tel), status, json)
    return nil, "Twilio API error"
  end

  local state = json
            and type(json.status) == "string"
            and json.status
             or "unknown"

  if state ~= "approved" then
    return nil, "status: " .. status
  end

  destroy_task(task)
  return task
end


---@param conf doorbell.verify.twilio.conf
function _M.init(conf)
  assert(type(conf) == "table"
         and type(conf.service_id) == "string"
         and type(conf.auth_sid) == "string"
         and type(conf.auth_secret) == "string")

  assert(conf.base_url == nil or type(conf.base_url) == "string")

  SERVICE_ID = conf.service_id
  BASE_URL = conf.base_url or BASE_URL
  BASE_URL = BASE_URL:gsub("/+$", "") -- trim trailing slash

  AUTHORIZATION = "Basic " .. ngx.encode_base64(conf.auth_sid .. ":" .. conf.auth_secret)
  ENABLED = true
end


---@return boolean
function _M.enabled()
  return ENABLED
end

return _M
