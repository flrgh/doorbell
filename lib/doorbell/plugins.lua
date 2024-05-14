local tnew = require "table.new"
local nkeys = require "table.nkeys"
local log = require "doorbell.log"

---@class doorbell.plugins
local _M = {}

local function noop() end

---@class doorbell.plugin
---
---@field name string
---
---@field priority? integer
---
---@field init fun(conf:any)
---
---@field init_worker fun()


---@type doorbell.plugin[]
local plugins


---@param conf doorbell.config
function _M.init(conf)
  if not conf.plugins then
    plugins = nil
    return
  end

  plugins = tnew(nkeys(conf), 0)

  for name, cfg in pairs(conf.plugins) do
    log.debug("[plugins] init : ", name)

    ---@type doorbell.plugin
    local plugin = require("doorbell.plugins." .. name)

    plugin.init = plugin.init or noop
    plugin.init_worker = plugin.init_worker or noop

    plugin.init(cfg)

    table.insert(plugins, plugin)
  end

  table.sort(plugins, function(a, b)
    return (a.priority or 0) > (b.priority or 0)
  end)
end


function _M.init_worker()
  if not plugins then return end
  for _, plugin in ipairs(plugins) do
    plugin.init_worker()
  end
end


return _M
