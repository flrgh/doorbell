local _M = {
  _VERSION = require("doorbell.constants").version,
}

local log = require "doorbell.log"

local sem      = require "ngx.semaphore"
local encode   = require("cjson.safe").new().encode
local open     = io.open
local fmt      = string.format
local concat   = table.concat
local timer_at = ngx.timer.at
local exiting  = ngx.worker.exiting

---@type ngx.semaphore
local SEM

local INTERVAL = 1
local QSIZE    = 5
local ROUNDS   = 100

---@type string
local PATH

---@type table[]
local ENTRIES

---@type string[]
local buf = { n = 0 }

---@type string[]
local errors = { n = 0 }

---@param t any[]
---@param value any
local function append(t, value)
  local n = t.n + 1
  t[n] = value
  t.n = n
end

---@param t any[]
local function clear(t)
  local n = t.n
  if n > 0 then
    for i = 1, n do
      t[i] = nil
    end
    t.n = 0
  end
end

---@param t any[]
---@param sep? string
---@param start? number
---@param stop? number
---@return string?
local function join(t, sep, start, stop)
  local n = t.n
  if n == 0 then
    return
  end
  local s = concat(t, sep, start or 1, stop or n)
  clear(t)
  return s
end

---@param fh? file*
---@return boolean ok
---@return string? error
---@return number  written
local function flush(fh)
  if ENTRIES == nil then
    return
  end

  local len = ENTRIES.n
  if len == 0 then
    return true, nil, 0
  end

  local entries = ENTRIES
  ENTRIES = { n = 0 }

  local need_close = false
  local err
  if fh then
    fh:seek("end")
  else
    need_close = true

    fh, err = open(PATH, "a+")
    if not fh then
      return nil, err, 0
    end
  end

  local n = 0
  for i = 1, len do
    local json, jerr = encode(entries[i])
    if jerr then
      append(errors, fmt("failed encoding entry #%s: %s", i, jerr))
    else
      n = n + 1
      append(buf, json)
      append(buf, "\n")
    end
  end

  if n > 0 then
    local ok, werr = fh:write(join(buf))
    if not ok then
      n = 0
      append(errors, fmt("failed writing to %s: %s", PATH, werr))
    end
  end

  if need_close then
    fh:close()
  end

  err = join(errors, "\n")

  if err then
    return nil, err, n
  end

  return true, err, n
end

---@param premature boolean
local function log_writer(premature)
  if premature or exiting() then
    log.info("NGINX is exiting: flushing remaining logs")
    flush()
    return
  end

  local fh, err = open(PATH, "a+")
  if not fh then
    log.alertf("failed opeaning log path (%s): %s", PATH, err)
    ENTRIES = nil
    return
  end

  for _ = 1, ROUNDS do
    if exiting() then
      log.info("NGINX is exiting: flushing remaining logs")
      flush(fh)
      break
    end

    if ENTRIES.n < QSIZE then
      SEM:wait(INTERVAL)
    end

    local expect = ENTRIES.n
    local ok, written
    ok, err, written = flush(fh)
    if not ok then
      local failed = expect - written
      log.alertf("failed writing %s/%s entries to the log: %s", failed, expect, err)
    elseif written > 0 then
      log.debugf("wrote %s entries to the log", written)
    end
  end

  fh:close()

  if not exiting() then
    assert(timer_at(INTERVAL, log_writer))
  end
end

---@param entry table
function _M.add(entry)
  if ENTRIES == nil then
    log.warn("logging is disabled")
    return
  end

  if not entry then
    log.warn("nil entry passed in")
    return
  end

  append(ENTRIES, entry)

  if SEM:count() < 0 then
    SEM:post(1)
  end
end

---@param conf doorbell.config
function _M.init(conf)
  PATH = conf.log_path
  ENTRIES = { n = 0 }
end

function _M.init_worker()
  SEM = assert(sem.new())
  assert(timer_at(0, log_writer))
end

return _M
