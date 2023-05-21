---@class doorbell.auth
---
---@field access doorbell.auth.access
local _M = {}



---@param conf doorbell.config
function _M.init(conf)
  _M.access = require("doorbell.auth.access")
  _M.access.init(conf)
end

return _M
