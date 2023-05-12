local _M = {}

local log = require "doorbell.log"
local util = require "doorbell.util"

local sem               = require "ngx.semaphore"
local timer_at          = ngx.timer.at
local exiting           = ngx.worker.exiting
local run_worker_thread = ngx.run_worker_thread
local now               = ngx.now
local update_time       = ngx.update_time
local new_tab           = require "table.new"
local min               = math.min

local flush_in_main_thread = require("doorbell.request.file-logger").write

---@type ngx.semaphore
local SEM

-- flush the log buffer when it reaches MAX_BUFFERED_ENTRIES
-- *or* when the last flush was FLUSH_INTERVAL seconds ago
local MAX_BUFFERED_ENTRIES = 100
local FLUSH_INTERVAL       = 1

-- how many timer loops to execute before re-scheduling a new timer
local TIMER_ITERATIONS = 1000


---@type string
local PATH       = nil
local ENABLED    = false


---@type table[]
local BUF     = new_tab(MAX_BUFFERED_ENTRIES, 0)
local BUF_LEN = 0

local NEXT_FLUSH = now()


---@return number
local function get_updated_time()
  update_time()
  return now()
end


---@param worker_exiting? boolean
local function flush(worker_exiting)
  if not ENABLED then
    return
  end

  if BUF_LEN == 0 then
    return
  end

  NEXT_FLUSH = now() + FLUSH_INTERVAL

  local entries = BUF
  local len = BUF_LEN

  -- Use the high water mark of the previous buffer to determine the size of
  -- the new buffer. This should cut down on the number of table resize
  -- operations needed when under high request throughput.
  local buf_size = min(MAX_BUFFERED_ENTRIES, len)
  BUF = new_tab(buf_size, 0)
  BUF_LEN = 0

  local ok, err, count

  local start = get_updated_time()
  if worker_exiting then
    log.debug("NGINX is exiting: flushing remaining logs in the main thread")

    ok, err, count = flush_in_main_thread(PATH, entries)

  else
    local tok, terr
    ok, tok, terr, count = run_worker_thread("doorbell.json.log",
                                             "doorbell.request.file-logger",
                                             "write",
                                             PATH,
                                             entries)
    if ok then
      ok = tok
      err = terr
    else
      err = tok
    end
  end


  local duration = get_updated_time() - start

  if count then
    log.debug("wrote ", count, "/", len, " logs to ", PATH, " in ", duration, "s")
  end

  if not ok then
    log.alertf("failed writing logs to file (%s): %s", PATH, err)
  end
end


---@param premature boolean
local function log_writer(premature)
  if premature or exiting() then
    flush(true)
    return
  end

  local remaining
  local need_flush = false

  for _ = 1, TIMER_ITERATIONS do
    if BUF_LEN == 0 then
      -- You might be tempted to drastically increase the timeout in this
      -- branch. However, semaphore:wait() is not guaranteed to wake up our
      -- thread when NGINX has been signaled to exit, so a long timeout could
      -- block the shutdown process.
      SEM:wait(FLUSH_INTERVAL)
    end


    if BUF_LEN >= MAX_BUFFERED_ENTRIES then
      need_flush = true

    elseif BUF_LEN > 0 then
      remaining = NEXT_FLUSH - now()

      if remaining < 0.001 then
        need_flush = true

      -- if semaphore:wait() returns falsy, that means we waited the entire
      -- `remaining` duration, so we should flush
      elseif not SEM:wait(remaining) then
        need_flush = true
      end

    elseif exiting() then
      break
    end


    if need_flush then
      need_flush = false
      flush()
    end
  end


  if exiting() then
    flush(true)

  else
    assert(timer_at(0, log_writer))
  end
end


---@param entry table
function _M.add(entry)
  if not ENABLED then
    return
  end

  if not entry then
    log.warn("nil entry passed in")
    return
  end

  BUF_LEN = BUF_LEN + 1
  BUF[BUF_LEN] = entry

  if SEM:count() < 0 then
    SEM:post(1)
  end
end


---@param conf doorbell.config
function _M.init(conf)
  PATH = util.join(conf.log_path, "doorbell.json.log")
  ENABLED = true
end


function _M.init_worker()
  SEM = assert(sem.new())
  assert(timer_at(0, log_writer))
end


return _M
