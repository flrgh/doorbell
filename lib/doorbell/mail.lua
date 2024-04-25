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


---@param to string
---@param subject string
---@param html string
---@return boolean? ok
---@return string? error
function _M.send(to, subject, html)
  if not smtp then
    return nil, "SMTP is not enabled"
  end

  local mailer, err = mail.new(smtp)
  if not mailer or err then
    return nil, err
  end

  ---@type resty.mail.mailer.send.data
  local data = {
    from = smtp.username,
    to = { to },
    subject = subject,
    html = html,
  }

  return mailer:send(data)
end


return _M
