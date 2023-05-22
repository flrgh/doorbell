local _M = {}

local http    = require "doorbell.http"
local log     = require "doorbell.log"
local manager = require "doorbell.rules.manager"
local notify  = require "doorbell.notify"
local router  = require "doorbell.router"
local views   = require "doorbell.views"
local mw      = require "doorbell.middleware"
local request = require "doorbell.request"

local send = http.send

---@param modname string
local function add_submodule_routes(modname)
  ---@type table<string, doorbell.route>
  local mod = require(modname)

  for k, v in pairs(mod) do
    if type(k) == "string" and type(v) == "table" then
      v.content_type = v.content_type or "application/json"
      router.add(k, v)
    end
  end
end


---@param conf doorbell.config
function _M.init(conf)

  router["/ring"] = require("doorbell.auth.ring")

  router["/answer"] = {
    id              = "answer",
    description     = "who is it?",
    metrics_enabled = true,
    middleware      = {
      [mw.phase.PRE_HANDLER] = {
        request.middleware.enable_logging,
      },
    },
    GET             = views.answer,
    POST            = views.answer,
  }

  router["/reload"] = {
    id              = "reload",
    description     = "reload from disk",
    metrics_enabled = false,
    content_type    = "text/plain",
    POST = function()
      local ok, err = manager.load(conf.runtime_path)
      if ok then
        return send(201, "success")
      end
      log.err("failed reloading rules from disk: ", err)
      return send(500, "failure")
    end
  }

  router["/save"] = {
    id              = "save",
    description     = "save to disk",
    metrics_enabled = false,
    content_type    = "text/plain",
    POST            = function()
      local ok, err = manager.save()
      if not ok then
        log.err("failed saving rules to disk: ", err)
        return send(500, "failure")
      end
      return send(201, "success")
    end
  }

  router["/notify/test"] = {
    id              = "notify-test",
    description     = "send a test notification",
    metrics_enabled = false,
    content_type    = "application/json",
    middleware      = {
      [mw.phase.PRE_HANDLER] = {
        request.middleware.enable_logging,
      },
    },
    POST            = function()
      local req = {
        addr    = "178.45.6.125",
        ua      = "Mozilla/5.0 (X11; Ubuntu; Linux i686) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2830.76 Safari/537.36",
        host    = "prometheus.pancakes2.com",
        uri     = "/wikindex.php?f=/NmRtJOUjAdutReQj/scRjKUhleBpzmTyO.txt",
        scheme  = "https",
        country = "US",
        method  = "GET",
        path    = "/wikindex.php",
      }

      local token = "TEST"

      local ok, err, res = notify.ring(req, token)

      local response = {
        strategy = notify.strategy,
        status   = (ok and "OK") or "FAIL",
        error    = err,
        response = res,
      }

      send((ok and 200) or 500, response)
    end,
  }

  router["/rules.html"] = {
    id              = "rules-html-report",
    description     = "rules list, in html",
    metrics_enabled = false,
    allow_untrusted = false,
    content_type    = "text/html",
    GET             = views.rule_list,
    middleware      = {
      [mw.phase.PRE_HANDLER] = {
        request.middleware.enable_logging,
      },
    },
  }

  router["/favicon.ico"] = {
    id              = "favicon",
    description     = "stop asking me about this, browsers",
    metrics_enabled = false,
    middleware      = {
      [mw.phase.PRE_HANDLER] = {
        request.middleware.disable_logging,
      },
    },
    GET = function() return send(404) end,
  }


  add_submodule_routes("doorbell.api.access")
  add_submodule_routes("doorbell.api.schema")
  add_submodule_routes("doorbell.api.ip")
  add_submodule_routes("doorbell.api.rules")
end

return _M
