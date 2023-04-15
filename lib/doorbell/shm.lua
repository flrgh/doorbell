---@type table<string, ngx.shared.DICT>
local SHM = {}

SHM.doorbell  = assert(ngx.shared.doorbell, "ngx.shared.doorbell does not exist")
SHM.rules     = assert(ngx.shared.rules, "ngx.shared.rules does not exist")
SHM.stats     = assert(ngx.shared.stats, "ngx.shared.stats does not exist")
SHM.metrics   = assert(ngx.shared.metrics, "ngx.shared.metrics does not exist")
SHM.locks     = assert(ngx.shared.locks, "ngx.shared.locks does not exist")

setmetatable(SHM, {
  __index = function(_, name)
    error("trying to access unknown SHM dict: " .. tostring(name), 2)
  end,
})

return SHM
