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
    local name = fmt("/tmp/doorbell-test-%x", math.random())
    if pl_path.mkdir(name) then
      tmp = name
      break
    end
  end

  assert(tmp ~= nil, "failed to create temp dir after " .. tries .. " tries")

  return tmp
end

return fs
