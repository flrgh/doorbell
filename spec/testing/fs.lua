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


return fs
