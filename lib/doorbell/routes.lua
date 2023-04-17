local _M = {
  _VERSION = require("doorbell.constants").version,
}

local const   = require "doorbell.constants"
local http    = require "doorbell.http"
local log     = require "doorbell.log"
local manager = require "doorbell.rules.manager"
local notify  = require "doorbell.notify"
local router  = require "doorbell.router"
local util    = require "doorbell.util"
local views   = require "doorbell.views"
local rules   = require "doorbell.rules.api"
local ip      = require "doorbell.ip"

local safe_decode = require("cjson.safe").decode

local send       = http.send
local shared     = ngx.shared


---@param config doorbell.config
function _M.init(config)

  router["/ring"] = require("doorbell.ring")

  router["/answer"] = {
    description     = "who is it?",
    log_enabled     = true,
    metrics_enabled = true,
    GET             = views.answer,
    POST            = views.answer,
  }

  router["/reload"] = {
    description     = "reload from disk",
    metrics_enabled = false,
    content_type    = "text/plain",
    POST = function()
      local ok, err = manager.load(config.runtime_dir)
      if ok then
        return send(201, "success")
      end
      log.err("failed reloading rules from disk: ", err)
      return send(500, "failure")
    end
  }

  router["/save"] = {
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

  router["/shm"] = {
    description = "shm zone list",
    metrics_enabled = false,
    content_type    = "application/json",
    GET = function()
      return send(200, util.table_keys(shared, true))
    end,
  }

  router["~^/shm/(?<name>[^/]+)/?$"] = {
    description = "shm key list",
    metrics_enabled = false,
    content_type    = "application/json",
    GET = function(_, match)
      local name = match.name
      local shm = shared[name]
      if not shm then
        return send(404, { error = "ngx.shared[" .. name .. "] not found" })
      end

      return send(200, shm:get_keys(0))
    end
  }

  router["~^/shm/(?<zone>[^/]+)?(/(?<key>.+))?"] = {
    description     = "shm key",
    metrics_enabled = false,
    allow_untrusted = false,
    content_type    = "application/json",
    GET = function(_, match)
      local zone, key = match.zone, match.key

      local shm = shared[zone]
      if not shm then
        return send(404, { error = "ngx.shared[" .. zone .. "] does not exist" })
      end

      local v = shm:get(key)
      if v == nil then
        return send(404, { error = "shm key " .. key .. "does not exist" })
      end

      local decoded = safe_decode(v)
      if not decoded then
        return send(200, v)
      end

      return send(200, decoded)
    end
  }

  router["/notify/test"] = {
    description     = "send a test notification",
    metrics_enabled = false,
    content_type    = "application/json",
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
    description     = "rules list, in html",
    metrics_enabled = false,
    allow_untrusted = false,
    content_type    = "text/html",
    GET             = views.rule_list,
  }

  router["/rules"] = {
    description     = "rules API",
    metrics_enabled = false,
    allow_untrusted = false,
    content_type    = "application/json",
    GET             = function()
      local list, err = rules.list()
      if not list then
        log.err("failed to list rules for API request: ", err)
        return send(500, { error = "internal server error" })
      end

      return send(200, { data = list })
    end,

    POST = function()
      local json = http.get_json_request_body()

      json.source = const.sources.api

      local rule, err, status = rules.insert(json)
      if not rule then
        local msg = { error = err }

        if status >= 500 then
          log.err("failed creating rule: ", err)
          msg.error = "internal server error"
        end

        return send(status, msg)
      end

      return send(201, rule)
    end
  }

  router["~^/rules/(?<hash_or_id>[a-z0-9-]+)$"] = {
    description     = "rules API",
    metrics_enabled = false,
    allow_untrusted = false,
    content_type    = "application/json",
    GET             = function(_, match)
      local rule = rules.get(match.hash_or_id)
      if rule then
        return send(200, rule)
      else
        return send(404, { error = "rule not found" })
      end
    end,

    PATCH          = function(_, match)
      local json = http.get_json_request_body()

      local updated, err, status = rules.patch(match.hash_or_id, json)

      if not updated then
        return send(status, { error = err } )
      end

      return send(200, updated)
    end,

    DELETE = function(_, match)
      local ok, err, status = rules.delete(match.hash_or_id)
      if not ok then
        local msg = { error = err }

        if status >= 500 then
          log.err("failed deleting rule: ", err)
          msg.error = "internal server error"
        end

        return send(status, msg)
      end


      return send(204)
    end
  }

  router["/favicon.ico"] = {
    description     = "stop asking me about this, browsers",
    metrics_enabled = false,
    log_enabled     = false,
    GET             = function() return send(404) end,
  }

  router["/ip/addr"] = {
    description = "returns the client IP address",
    metrics_enabled = true,
    log_enabled = false,
    allow_untrusted = true,
    GET = function()
      return send(200, ip.get_forwarded_ip())
    end,
  }

  router["/ip/info"] = {
    description = "returns IP address info",
    metrics_enabled = true,
    log_enabled = false,
    allow_untrusted = true,
    content_type = "application/json",
    GET = function()
      local addr = ip.get_forwarded_ip()
      return send(200, ip.get_ip_info(addr))
    end,
  }

  router["~^/ip/info/(?<addr>.+)"] = {
    description = "returns IP address info",
    metrics_enabled = true,
    log_enabled = false,
    allow_untrusted = false,
    content_type = "application/json",
    GET = function(_, match)
      local addr = match.addr

      if not ip.is_valid(addr) then
        return send(400, { addr = addr, error = "invalid IP address" })
      end

      return send(200, ip.get_ip_info(addr))
    end,
  }

end

return _M
