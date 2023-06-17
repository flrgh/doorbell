---@type doorbell.cache
local _M = {
  _VERSION = require("doorbell.constants").version,
}

local SHM = require("doorbell.shm").doorbell
local metric_fmt = "cache:worker(%s):lru(%s):count"

---@class doorbell.cache
---@field name   string
---@field lru    resty.lrucache
---@field hit    number
---@field miss   number
---@field expire number
local cache = {}

local cache_mt = { __index = cache }
setmetatable(cache, cache_mt)

local metrics = require "doorbell.metrics"
local debugf = require("doorbell.log").debugf

local lrucache = require "resty.lrucache"

local tostring = tostring
local pairs = pairs

---@type PrometheusCounter|prometheus.counter
local cache_lookups

---@type PrometheusGauge|prometheus.gauge
local cache_entries

---@type table<doorbell.cache, string>
local registry = {}


---@param key string
---@return any
function cache:raw_get(key)
  local value, stale = self.lru:get(key)

  if value ~= nil then
    debugf("[%s] cache HIT for %s => %q", self.name, key, tostring(value))
    self.hit = self.hit + 1
  else
    if stale == nil then
      debugf("[%s] cache MISS for %s", self.name, key)
      self.miss = self.miss + 1
    else
      debugf("[%s] cache EXPIRE for %s", self.name, key)
      self.expire = self.expire + 1
    end
  end

  return value
end


---@param ns string
---@param key string
---@return any
function cache:get(ns, key)
  local cache_key = ns .. "::" .. key
  return self:raw_get(cache_key)
end

---@param key string
---@param value any
---@param ttl?  number
function cache:raw_set(key, value, ttl)
  if ttl == 0 then
    ttl = nil
  elseif ttl and ttl < 0 then
    debugf("[%s] not caching already-expired item ", self.name, key)
    return
  end

  self.lru:set(key, value, ttl)
end


---@param ns    string
---@param key   string
---@param value any
---@param ttl?  number
function cache:set(ns, key, value, ttl)
  local cache_key = ns .. "::" .. key
  self:raw_set(cache_key, value, ttl)
end

function cache:count()
  return self.lru:count()
end

function cache:flush_all()
  self.lru:flush_all()
end

function cache:metrics_handler()
  local hit, miss, expire = self.hit, self.miss, self.expire
  self.hit, self.miss, self.expire = 0, 0, 0
  local name = self.name

  cache_lookups:inc(hit,    { name, "hit"    })
  cache_lookups:inc(miss,   { name, "miss"   })
  cache_lookups:inc(expire, { name, "expire" })

  SHM:safe_set(metric_fmt:format(ngx.worker.id(), name), self.lru:count())
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
      name   = name,
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
  _M.name = "main"

  -- this needs no special ordering around its initialization logic, so its
  -- just here in case no other module initializes it during init_by_lua
  require("doorbell.cache.shared")

  return _M
end

function _M.init_worker()
  if metrics.enabled() then
    cache_lookups = metrics.registry.cache_lookups
    cache_entries = metrics.registry.cache_entries

    metrics.add_hook(function()
      for c in pairs(registry) do
        c:metrics_handler()
      end
      _M:metrics_handler()
    end)

    -- The cache entries metric is a sum of all worker counts. Workers don't
    -- set it directly--instead they record their individual count in shared
    -- memory, and a single worker sums them up and sets the actual prometheus
    -- metric.
    if ngx.worker.id() == 0 then
      local workers = ngx.worker.count()

      metrics.add_hook(function()
        for _, name in pairs(registry) do
          local count = 0
          for id = 0, workers - 1 do
            count = count + (SHM:get(metric_fmt:format(id, name)) or 0)
          end
          cache_entries:set(count, { name })
        end
      end)
    end

  end
end

return _M
