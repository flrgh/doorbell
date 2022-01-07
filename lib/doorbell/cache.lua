---@type doorbell.cache
local _M = {
  _VERSION = require("doorbell.constants").version,
}

---@class doorbell.cache
---@field lru resty.lrucache
local cache = {}

local cache_mt = { __index = cache }
setmetatable(cache, cache_mt)

local debugf = require("doorbell.log").debugf

local lrucache = require "resty.lrucache"

---@param ns string
---@param key string
---@return any
function cache:get(ns, key)
  local cache_key = ns .. ":" .. key
  local value, stale = self.lru:get(cache_key)

  if value ~= nil then
    debugf("cache HIT for %s => %q", cache_key, value)
  else
    if stale == nil then
      debugf("cache MISS for %s", cache_key)
    else
      debugf("cache EXPIRE for %s", cache_key)
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

  local cache_key = ns .. ":" .. key

  self.lru:set(cache_key, value, ttl)
end

function cache:count()
  return self.lru:count()
end

function cache:flush_all()
  self.lru:flush_all()
end

---@param size integer
---@return doorbell.cache
function _M.new(size)
  return setmetatable(
    {
      lru = assert(lrucache.new(size or 1000))
    },
    cache_mt
  )
end

---@param opts doorbell.init.opts
function _M.init(opts)
  _M.lru = assert(lrucache.new(opts.cache_size or 1000))
  setmetatable(_M, cache_mt)
end

return _M
