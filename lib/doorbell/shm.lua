local SHM = {}

local const = require "doorbell.constants"

SHM.approvals         = assert(ngx.shared.approvals,     "ngx.shared.approvals does not exist")
SHM.doorbell          = assert(ngx.shared.doorbell,      "ngx.shared.doorbell does not exist")
SHM.locks             = assert(ngx.shared.locks,         "ngx.shared.locks does not exist")
SHM.metrics           = assert(ngx.shared.metrics,       "ngx.shared.metrics does not exist")
SHM.mlcache_ipc       = assert(ngx.shared.mlcache_ipc,   "ngx.shared.cache does not exist")
SHM.mlcache_locks     = assert(ngx.shared.mlcache_locks, "ngx.shared.cache_locks does not exist")
SHM.mlcache_main      = assert(ngx.shared.mlcache_main,  "ngx.shared.cache does not exist")
SHM.mlcache_miss      = assert(ngx.shared.mlcache_miss,  "ngx.shared.cache_miss does not exist")
SHM.nginx             = assert(ngx.shared.nginx,         "ngx.shared.nginx does not exist")
SHM.pending           = assert(ngx.shared.pending,       "ngx.shared.pending does not exist")
SHM.rules             = assert(ngx.shared.rules,         "ngx.shared.rules does not exist")
SHM.stats             = assert(ngx.shared.stats,         "ngx.shared.stats does not exist")
SHM.plugins           = assert(ngx.shared.plugins,       "ngx.shared.plugins does not exist")

for _, name in pairs(const.shm) do
  assert(SHM[name], "missing " .. name .. " defined in doorbell.constants.shm")
end

---@param dict ngx.shared.DICT
---@param name string
---@return ngx.shared.DICT
function SHM.with_namespace(dict, name)
  assert(type(dict) == "table")
  assert(type(name) == "string" and #name > 0)

  local namespace = name .. "::"
  local shm = {}
  for _, fn in ipairs({
      "add",
      "delete",
      "expire",
      "get",
      "get_stale",
      "incr",
      "llen",
      "lpop",
      "lpush",
      "replace",
      "rpop",
      "rpush",
      "safe_add",
      "safe_set",
      "set",
      "ttl",
    }) do

    local dict_fn = dict[fn]
    assert(type(dict_fn) == "function")
    shm[fn] = function(_, key, ...)
      key = namespace .. key
      return dict_fn(dict, key, ...)
    end
  end

  return shm
end


setmetatable(SHM, {
  __index = function(_, name)
    error("trying to access unknown SHM dict: " .. tostring(name), 2)
  end,
})

return SHM
