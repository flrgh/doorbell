local _M = {}

local users = require "doorbell.users"
local mail = require "resty.mail"


---@type doorbell.config.smtp
local smtp

local DEFAULT_TIMEOUT = 15000 -- 15s

---@param conf doorbell.config
function _M.init(conf)
  smtp = conf.smtp

  if not smtp or not smtp.host then
    return
  end

  if not smtp.domain then
    local pos = smtp.username:find("@")
    if pos then
      smtp.domain = smtp.username:sub(pos + 1)
    end
  end

  smtp.timeout_connect = smtp.timeout_connect or DEFAULT_TIMEOUT
  smtp.timeout_read    = smtp.timeout_read    or DEFAULT_TIMEOUT
  smtp.timeout_send    = smtp.timeout_send    or DEFAULT_TIMEOUT
end


---@param data resty.mail.mailer.send.data
---@return boolean? ok
---@return string? error
function _M.send(data)
  if not smtp then
    return nil, "SMTP is not enabled"
  end

  local mailer, err = mail.new(smtp)
  if not mailer or err then
    return nil, err
  end

  assert(data.to and type(data.to) == "table" and data.to[1],
         "missing/invalid `to` address(s) in email")

  for _, addr in ipairs(data.to) do
    assert(users.get_by_email(addr) or users.get_by_email(addr:lower()),
           "trying to send mail to an unregistered user")
  end

  data.from = data.from
           or smtp.from
           or smtp.username

  return mailer:send(data)
end


return _M
