local _M = {}

---@type table<string, doorbell.config.auth.user>
local by_email

---@type table<string, doorbell.config.auth.user>
local by_name

---@type table<string, doorbell.config.auth.user>
local by_apikey

---@type table<string, doorbell.config.auth.user>
local by_jwt_sub

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


return _M
