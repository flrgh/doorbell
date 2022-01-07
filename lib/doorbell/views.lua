--- doorbell views
---@type table<string, doorbell.view>
local _M = {
  ---@type string
  _VERSION = require("doorbell.constants").version,
}

setmetatable(_M, {
  __index = function(_, name)
    error("unknown view: " .. tostring(name))
  end,
})

---@alias doorbell.view fun(ctx:doorbell.ctx)

---@module 'lfs'
local lfs = require "lfs_ffi"

---@param conf doorbell.config
function _M.init(conf)
  local path = conf.asset_path

  local resty_template = require("resty.template").new({
    root = path,
  })

  for item in lfs.dir(path) do
    if item:find("%.template%.html$") then
      local name = item:gsub("%.template%.html", "")

      local ok, mod = pcall(require, "doorbell.views." .. name)
      if not ok then
        error("failed loading view submodule " .. name .. ": " .. mod)
      end

      local tpl, err = resty_template.compile(item)
      if not tpl then
        error("failed loading " .. name .. " template: " .. err)
      end

      ---@type doorbell.view
      _M[name] = function(ctx)
        ctx.template = tpl
        return mod(ctx)
      end
    end
  end
end

return _M
