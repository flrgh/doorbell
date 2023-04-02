---@class doorbell.notify.strategy
local mock = {}

local fs = require "spec.testing.fs"

local fname

local function log(method, params)
  fs.append_json(fname, {
    method = method,
    params = params,
  })
end

function mock.init(config)
  ngx.log(ngx.DEBUG, "configuring mock notifier...")

  fname = config.file
end

function mock.ring(req, url)
  ngx.log(ngx.DEBUG, "mock notify ring()")
  log("ring", { req = req, url = url })

  return true
end

function mock.send(msg)
  ngx.log(ngx.DEBUG, "mock notify send()")

  log("send", { msg = msg })

  return true
end

return mock
