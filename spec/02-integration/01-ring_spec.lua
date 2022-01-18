local nginx = require "doorbell.nginx"
local util = require "doorbell.util"

local pl_dir = require "pl.dir"
local pl_util = require "pl.utils"
local http = require "resty.http"

local join = util.join
local fmt = string.format

local ROOT = os.getenv("PWD")

local function exec(cmd, ...)
  local args = pl_util.quote_arg({ ... })
  cmd = cmd .. " " .. args
  return pl_util.executeex(cmd)
end

---@param prefix string
---@param conf doorbell.config
local function prepare(prefix, conf)
  pl_dir.makepath(prefix)
  pl_dir.makepath(join(conf.log_path))
  pl_dir.makepath(join(conf.state_path))
  nginx.render(
    join(ROOT, "assets", "nginx.template.conf"),
    join(prefix, "nginx.conf"),
    {
       -- at the moment this populates the lua package path, so it needs to be
       -- relative to the repository root
      prefix = ROOT,
      daemon = "on",
    }
  )
  util.write_json_file(
    join(prefix, "config.json"),
    conf
  )
end

local function format_cmd_result(cmd, code, stdout, stderr)
  return fmt(
    "command: %q\ncode: %s\nstdout: %s\nstderr: %s\n",
    table.concat(cmd, " "),
    code,
    stdout,
    stderr
  )
end

local function exec_nginx(prefix, ...)
  local cmd = {
    "nginx",
    "-p", prefix,
    "-c", join(prefix, "nginx.conf"),
  }

  for i = 1, select("#", ...) do
    local elem = select(i, ...)
    table.insert(cmd, elem)
  end

  local ok, code, stdout, stderr = exec(unpack(cmd))
  assert.truthy(ok, format_cmd_result(cmd, code, stdout, stderr))
  assert.equals(0, code, format_cmd_result(cmd, code, stdout, stderr))
end

local function conf_test(prefix)
  return exec_nginx(prefix, "-t")
end

local function start(prefix)
  return exec_nginx(prefix)
end

local function stop(prefix)
  return exec_nginx(prefix, "-s", "stop")
end

local function restart(prefix)
  assert(stop(prefix))
  assert(start(prefix))
end

local function reload(prefix)
  return exec_nginx(prefix, "-s", "reload")
end

local function update_config(prefix, config)
  util.write_json_file(
    join(prefix, "config.json"),
    config
  )
  restart(prefix)
end

local headers_mt = {
  __index = function(self, name)
    name = name:lower():gsub("_", "-")
    return rawget(self, name)
  end,

  __newindex = function(self, name, value)
    name = name:lower():gsub("_", "-")
    return rawset(self, name, value)
  end,
}


describe("doorbell", function()
  local prefix = os.getenv("DOORBELL_PREFIX") or join(ROOT, "test")

  local client

  lazy_setup(function()
    prepare(prefix, {
      base_url = "http://127.0.0.1/",
      trusted = { "127.0.0.1/32" },
      asset_path = join(ROOT, "assets"),
      state_path = join(prefix, "state"),
      log_path   = join(prefix, "logs"),
      metrics    = {
        disable  = true,
      },
      allow      = {
        { ua     = "allow" },
      },
      deny       = {
        { ua     = "deny" },
      },
    })
    conf_test(prefix)
    start(prefix)

    client = assert(http.new())
  end)

  lazy_teardown(function()
    if client then
      client:close()
    end
    stop(prefix)
  end)

  describe("/ring", function()
    local headers, path, method, host
    local res, err
    local need_connect = true

    local function request()
      if need_connect then
        assert(client:connect({
          host   = "127.0.0.1",
          scheme = "http",
          port   = 9876,
        }))
      end

      need_connect = false

      local params = {
        path    = path,
        headers = headers,
        method  = method,
        host    = host,
      }
      --print(require("inspect")(params))
      res, err = client:request(params)
      if res and res.has_body then
        res.body, res.body_err = res:read_body()
      end
      --print(require("inspect")({ res = res, err = err }))

      if not res or (res.headers.connection == "close") then
        client:close()
        need_connect = true
      end
    end

    local function add_x_forwarded_headers(addr, meth, req)
      headers.x_forwarded_for = addr
      headers.x_forwarded_method = meth
      local parsed = assert(client:parse_uri(req, true))
      headers.x_forwarded_proto = parsed[1]
      headers.x_forwarded_host  = parsed[2]
      headers.x_forwarded_uri   = parsed[4]
    end

    before_each(function()
      headers = setmetatable({}, headers_mt)
      path = "/ring"
      method = "GET"
      host = "127.0.0.1"
    end)

    it("returns a 400 if any x-forwarded-(for|method|proto|host|uri) header is missing", function()
      request()
      assert.is_nil(err)
      assert.equals(400, res.status)

      headers.x_forwarded_for = "1.2.3.4."
      request()
      assert.is_nil(err)
      assert.equals(400, res.status)

      headers.x_forwarded_method = "GET"
      request()
      assert.is_nil(err)
      assert.equals(400, res.status)

      headers.x_forwarded_proto = "http"
      request()
      assert.is_nil(err)
      assert.equals(400, res.status)

      headers.x_forwarded_host = "test"
      request()
      assert.is_nil(err)
      assert.equals(400, res.status)

      -- finally we get a 401 after adding the last necessary header
      headers.x_forwarded_uri = "/"
      request()
      assert.is_nil(err)
      assert.equals(401, res.status)
    end)

    it("returns 200 when allowed by a matched rule", function()
      add_x_forwarded_headers("1.2.3.4", "GET", "http://test/")
      headers["user-agent"] = "allow"
      request()
      assert.is_nil(err)
      assert.equals(200, res.status)
    end)

    it("returns 403 when denied by a matched rule", function()
      add_x_forwarded_headers("1.2.3.4", "GET", "http://test/")
      headers["user-agent"] = "deny"
      request()
      assert.is_nil(err)
      assert.equals(403, res.status)
    end)
  end)
end)
