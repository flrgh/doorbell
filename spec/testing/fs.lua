local fs = {}

local pl_dir = require "pl.dir"
local pl_util = require "pl.utils"
local pl_path = require "pl.path"
local assert = require "luassert"
local cjson = require "cjson"

local fmt = string.format

function fs.mkdir(path)
  local ok, err = pl_dir.makepath(path)
  assert.truthy(ok, fmt("failed creating path (%s): %s", path, err))
end

function fs.file_contents(path)
  return assert(pl_util.readfile(path))
end

function fs.exists(path)
  return pl_path.exists(path)
end

function fs.write_json_file(path, data)
  assert(pl_util.writefile(path, cjson.encode(data)))
end

function fs.read_json_file(path)
  local content = fs.file_contents(path)
  return cjson.decode(content)
end

function fs.append_raw(path, data)
  local fh = assert(io.open(path, "a+"))
  assert(fh:write(data))
  fh:flush()
  fh:close()
end

function fs.append(path, line)
  fs.append_raw(path, line .. "\n")
end

function fs.append_json(path, data)
  fs.append_raw(path, cjson.encode(data) .. "\n")
end


fs.join = pl_path.join

function fs.rm(fname, if_exists)
  if if_exists and not fs.exists(fname) then
    return
  end

  assert(os.remove(fname))
end

function fs.rmdir(dir, if_exists)
  if if_exists and not fs.exists(dir) then
    return
  end

  assert(pl_dir.rmtree(dir))
end

function fs.reset_dir(dir)
  fs.rmdir(dir, true)
  fs.mkdir(dir)
end

local seeded = false

function fs.tmpdir()
  if not seeded then
    ngx.update_time()
    math.randomseed(ngx.now() + ngx.worker.pid())
    seeded = true
  end

  local tmp
  local tries = 1000

  for _ = 1, tries do
    local name = fmt("/tmp/doorbell-test-%s", math.random())
    if pl_path.mkdir(name) then
      tmp = name
      break
    end
  end

  assert(tmp ~= nil, "failed to create temp dir after " .. tries .. " tries")

  return tmp
end


function fs.not_empty(fname)
  return pl_path.isfile(fname) and pl_path.getsize(fname) > 0
end


function fs.truncate(fname)
  local fh = assert(io.open(fname, "w+"))
  fh:flush()
  fh:close()
end


---@param path string
---@return integer mtime
---@return string? error
function fs.mtime(path)
  local mtime, err = pl_path.getmtime(path)

  if mtime then
    return assert(tonumber(mtime))
  end

  return -1, err
end

---@param pat? string
---@return string[]
function fs.dir(path, pat)
  return pl_dir.getfiles(path, pat)
end

---@param path string
---@return string
function fs.basename(path)
  return pl_path.basename(path)
end


---@param fname string
---@return (fun():string)|nil
---@return string? error
function fs.lines(fname)
  local fh, err = io.open(fname, "r")
  if not fh then
    return nil, err
  end

  local iter = fh:lines()

  return function()
    local line = iter()
    if not line then fh:close() end
    return line
  end
end

return fs
