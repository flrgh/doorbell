---@class doorbell.users
local _M = {}


local type = type


--- strip hyphens, spaces, parens...
---@param tel string
---@return string
local function strip_tel_formatting(tel)
  return (tel:gsub("[() %-+]", ""))
end


---@param tel string
---@return string? formatted
---@return string? error
local function format_tel(tel)
  local typ = type(tel)

  if typ ~= "string" then
    return nil, "invalid type: " .. typ
  end

  tel = strip_tel_formatting(tel)

  if not tel:find("^%d+$") then
    return nil, "number contains non-digit characters"
  end

  local len = #tel

  if len < 10 then
    return nil, "number must have a 3 digit area code and 7 digit subscriber number"

  elseif len > 15 then
    -- not sure what the real limit is, but let's cut it of somewhere
    return nil, "invalid number"

  elseif len == 10 then
    tel = "1" .. tel -- US country code by default
  end

  return "+" .. tel
end



---@type table<string, doorbell.config.auth.user>
local by_email

---@type table<string, doorbell.config.auth.user>
local by_name

---@type table<string, doorbell.config.auth.user>
local by_apikey

---@type table<string, doorbell.config.auth.user>
local by_jwt_sub

---@type table<string, doorbell.config.auth.user>
local by_phone

---@param conf doorbell.config
function _M.init(conf)
  local users = conf.auth and conf.auth.users

  if not users then
    return
  end

  by_email = {}
  by_name = {}
  by_apikey = {}
  by_jwt_sub = {}
  by_phone = {}

  for _, user in ipairs(users) do
    assert(by_name[user.name] == nil, "duplicate username")

    for _, id in ipairs(user.identifiers) do
      if id.email then
        assert(by_email[id.email] == nil, "duplicate user email")
        by_email[id.email] = user
      end

      if id.apikey then
        assert(by_apikey[id.apikey] == nil, "duplicate user api key")
        by_apikey[id.apikey] = user
      end

      if id.sub then
        assert(by_jwt_sub[id.sub] == nil, "duplicate user JWT sub[ject]")
        by_jwt_sub[id.sub] = user
      end

      if id.tel then
        local tel = assert(format_tel(id.tel), "invalid user telephone number")
        assert(by_phone[tel] == nil, "duplicate user phone number")
        by_phone[tel] = user
      end
    end
  end
end


---@param email string
---@return doorbell.config.auth.user?
function _M.get_by_email(email)
  return by_email and by_email[email]
end


---@param apikey string
---@return doorbell.config.auth.user?
function _M.get_by_api_key(apikey)
  return by_apikey and by_apikey[apikey]
end


---@param name string
---@return doorbell.config.auth.user?
function _M.get_by_name(name)
  return by_name and by_name[name]
end


---@param sub string
---@return doorbell.config.auth.user?
function _M.get_by_jwt_sub(sub)
  return by_jwt_sub and by_jwt_sub[sub]
end

---@param tel string
---@return doorbell.config.auth.user?
function _M.get_by_phone_number(tel)
  tel = format_tel(tel)

  if not tel then
    -- possibly raise an error?
    return
  end

  return by_phone and by_phone[tel]
end

--- Validation helpers for user objects and identifiers
_M.validate = {}

--- Validate a telephone number.
---
--- This is a best-effort thing and might not be accurate outside of the US.
---
---@param tel string
---@return string? formatted
---@return string? error
function _M.validate.tel(tel)
  return format_tel(tel)
end

return _M
