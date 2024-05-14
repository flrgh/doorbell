---@type resty.mlcache
local cache

do
  local const = require "doorbell.constants"
  local mlcache = require "resty.mlcache"

  local err

  cache, err = mlcache.new("db", const.shm.mlcache_main, {
    ipc                 = nil,
    ipc_shm             = const.shm.mlcache_ipc,
    l1_serializer       = nil,
    lru                 = nil,
    lru_size            = 1000,
    neg_ttl             = 30,
    resty_lock_opts     = nil,
    resurrect_ttl       = nil,
    shm_locks           = const.shm.mlcache_locks,
    shm_miss            = const.shm.mlcache_miss,
    shm_set_tries       = nil,
    ttl                 = 3600,
  })

  if not cache then
    error("failed to create lua-resty-mlcache instance: " .. tostring(err or "unknown error"))
  end
end

return cache
