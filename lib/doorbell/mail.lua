local _M = {}

local users = require "doorbell.users"
local mail = require "resty.mail"


---@type doorbell.config.smtp
local smtp


---@param conf doorbell.config
function _M.init(conf)
  smtp = conf.smtp

  if not smtp or not smtp.host then
    return
  end
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

  return mailer:send(data)
end


return _M
