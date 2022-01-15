---@type doorbell.cache
local _M = {
  _VERSION = require("doorbell.constants").version,
}

---@class doorbell.cache
---@field lru resty.lrucache
---@field hit number
---@field miss number
---@field expire number
local cache = {}

local cache_mt = { __index = cache }
setmetatable(cache, cache_mt)

local metrics = require "doorbell.metrics"
local debugf = require("doorbell.log").debugf

local lrucache = require "resty.lrucache"

local tostring = tostring

---@type prometheus.counter
local cache_lookups

---@type prometheus.gauge
local cache_entries

---@type table<doorbell.cache, string>
local registry = {}

---@param ns string
---@param key string
---@return any
function cache:get(ns, key)
  local cache_key = ns .. "::" .. key

  local value, stale = self.lru:get(cache_key)

  if value ~= nil then
    debugf("cache HIT for %s => %q", cache_key, tostring(value))
    self.hit = self.hit + 1
  else
    if stale == nil then
      debugf("cache MISS for %s", cache_key)
      self.miss = self.miss + 1
    else
      debugf("cache EXPIRE for %s", cache_key)
      self.expire = self.expire + 1
    end
  end
  return value
end

---@param ns string
---@param key string
---@param value any
---@param ttl number
function cache:set(ns, key, value, ttl)
  if ttl == 0 then
    ttl = nil
  elseif ttl and ttl < 0 then
    debugf("not caching already-expired item %s:%s", ns, key)
    return
  end

  local cache_key = ns .. "::" .. key

  self.lru:set(cache_key, value, ttl)
end

function cache:count()
  return self.lru:count()
end

function cache:flush_all()
  self.lru:flush_all()
end

---@param name string
---@param size integer
---@return doorbell.cache
function _M.new(name, size)
  local self = setmetatable(
    {
      lru    = assert(lrucache.new(size or 1000)),
      hit    = 0,
      miss   = 0,
      expire = 0,
    },
    cache_mt
  )
  registry[self] = name
  return self
end

---@param opts doorbell.config
function _M.init(opts)
  _M.lru = assert(lrucache.new(opts.cache_size or 1000))
  setmetatable(_M, cache_mt)
  _M.hit, _M.miss, _M.expire = 0, 0, 0
  return _M
end

function _M.init_worker()
  if metrics.enabled() then
    cache_lookups = metrics.prometheus:counter(
      "cache_lookups",
      "LRU cache hit/miss counts",
      { "name", "status" }
    )

    cache_entries = metrics.prometheus:gauge(
      "cache_entries",
      "number of items in the LRU cache(s)",
      { "name" }
    )

    metrics.add_hook(function()
      if ngx.worker.id() == 0 then
        cache_entries:reset()
      end

      for c, name in pairs(registry) do
        local hit, miss, expire = c.hit, c.miss, c.expire
        c.hit, c.miss, c.expire = 0, 0, 0
        cache_lookups:inc(hit,    { name, "hit"    })
        cache_lookups:inc(miss,   { name, "miss"   })
        cache_lookups:inc(expire, { name, "expire" })
        cache_entries:inc(c.lru:count(), { name })
      end

      local hit, miss, expire = _M.hit, _M.miss, _M.expire
      _M.hit, _M.miss, _M.expire = 0, 0, 0
      cache_lookups:inc(hit,    { "main", "hit"    })
      cache_lookups:inc(miss,   { "main", "miss"   })
      cache_lookups:inc(expire, { "main", "expire" })
      cache_entries:inc(_M.lru:count(), { "main" })
    end)
  end
end

return _M
