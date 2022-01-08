local _M = {}

local log = require "doorbell.log"

local sem = require "ngx.semaphore"
local encode = require("cjson.safe").new().encode
local open = io.open
local fmt = string.format
local insert = table.insert
local concat = table.concat
local timer_at = ngx.timer.at
local exiting = ngx.worker.exiting

---@type ngx.semaphore
local SEM

local INTERVAL = 1
local QSIZE    = 5
local ROUNDS   = 100

local PATH

local ENTRIES = { n = 0 }

local buf = { n = 0 }

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
  if fh then
    fh:seek("end")
  else
    need_close = true

    local err
    fh, err = open(PATH, "a+")
    if not fh then
      return nil, err, 0
    end
  end

  local n = 0
  local errors
  for i = 1, (entries.n or #entries) do
    local json
    json, err = encode(entries[i])
    if json ~= nil then
      n = n + 1
      buf[n] = json
    else
      errors = errors or {}
      insert(errors, fmt("failed encoding entry #%s: %s", i, err))
    end
  end

  if n > 0 then
    n = n + 1
    buf[n] = "\n"
    local ok
    ok, err = fh:write(concat(buf, "\n", 1, n))
    if not ok then
      err = fmt("failed writing to %s: %s", PATH, err)
      if errors then
        insert(errors, err)
      end
    end
  end

  if need_close then
    fh:close()
  end

  if errors then
    err = concat(errors, "\n")
  end

  if err then
    return nil, err, n
  end

  return true, err, n
end

---@param premature boolean
local function log_writer(premature)
  if premature then
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
    else
      log.debuf("wrote %s entries to the log", written)
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

  local n = ENTRIES.n + 1
  ENTRIES[n] = entry
  ENTRIES.n = n

  if SEM:count() < 0 then
    SEM:post(1)
  end
end

---@param conf doorbell.config
function _M.init(conf)
  PATH = conf.log_path
end

function _M.init_worker()
  SEM = assert(sem.new())
  assert(timer_at(0, log_writer))
end

return _M
