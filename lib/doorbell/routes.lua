local _M = {}

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
local stats   = require "doorbell.rules.stats"
local schema  = require "doorbell.schema"
local mw      = require "doorbell.middleware"
local request = require "doorbell.request"
local auth    = require "doorbell.auth"

local safe_decode = require("cjson.safe").decode
local get_json_body = request.get_json_body
local get_query_arg = request.get_query_arg
local set_response_header = http.response.set_header

local send       = http.send
local shared     = ngx.shared

---@param t any
---@return any
local function drop_functions(t)
  local typ = type(t)

  if typ == "table" then
    local new = {}
    for k, v in pairs(t) do
      new[k] = drop_functions(v)
    end
    t = new

  elseif typ == "function" then
    t = nil
  end

  return t
end

local IP_MIME_TYPES = { "text/plain", "application/json" }

---@param config doorbell.config
function _M.init(config)

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
      local ok, err = manager.load(config.runtime_path)
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

  router["/shm"] = {
    id              = "shm-list-zones",
    description = "shm zone list",
    metrics_enabled = false,
    content_type    = "application/json",
    middleware      = {
      [mw.phase.PRE_HANDLER] = {
        request.middleware.enable_logging,
      },
    },
    GET = function()
      return send(200, util.table_keys(shared))
    end,
  }

  router["~^/shm/(?<name>[^/]+)/?$"] = {
    id              = "shm-list-keys",
    description = "shm key list",
    metrics_enabled = false,
    content_type    = "application/json",
    middleware      = {
      [mw.phase.PRE_HANDLER] = {
        request.middleware.enable_logging,
      },
    },
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
    id              = "shm-get-key",
    description     = "shm key",
    metrics_enabled = false,
    allow_untrusted = false,
    content_type    = "application/json",
    middleware      = {
      [mw.phase.PRE_HANDLER] = {
        request.middleware.enable_logging,
      },
    },
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

  router["/rules"] = {
    id              = "rules-collection",
    description     = "rules API",
    metrics_enabled = false,
    allow_untrusted = false,
    content_type    = "application/json",
    middleware      = {
      [mw.phase.PRE_HANDLER] = {
        request.middleware.enable_logging,
      },
    },
    GET = function(ctx)
      local list, err = rules.list()
      if not list then
        log.err("failed to list rules for API request: ", err)
        return send(500, { error = "internal server error" })
      end

      if util.truthy(get_query_arg(ctx, "stats")) then
        stats.decorate_list(list)
      end

      return send(200, { data = list })
    end,

    POST = function(ctx)
      local json = get_json_body(ctx, "table")

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
    id              = "rules-single",
    description     = "rules API",
    metrics_enabled = false,
    allow_untrusted = false,
    content_type    = "application/json",
    middleware      = {
      [mw.phase.PRE_HANDLER] = {
        request.middleware.enable_logging,
      },
    },
    GET = function(ctx, match)
      local rule = rules.get(match.hash_or_id)

      if rule then
        if util.truthy(get_query_arg(ctx, "stats")) then
          stats.decorate(rule)
        end

        return send(200, rule)

      else
        return send(404, { error = "rule not found" })
      end
    end,

    PATCH = function(ctx, match)
      local json = get_json_body(ctx, "table")

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
    id              = "favicon",
    description     = "stop asking me about this, browsers",
    metrics_enabled = false,
    middleware      = {
      [mw.phase.PRE_HANDLER] = {
        request.middleware.disable_logging,
      },
    },
    GET             = function() return send(404) end,
  }

  router["/ip/addr"] = {
    id              = "get-forwarded-ip",
    description = "returns the client IP address",
    metrics_enabled = true,
    allow_untrusted = true,
    middleware      = {
      [mw.phase.PRE_HANDLER] = {
        request.middleware.disable_logging,
      },
    },
    ---@param ctx doorbell.ctx
    GET = function(ctx)
      local accept = request.get_headers(ctx).accept
      local mtype = http.get_mime_type(accept, IP_MIME_TYPES)

      set_response_header("Content-Type", mtype)

      if mtype == "application/json" then
        return send(200, { data = ctx.forwarded_addr })

      else
        return send(200, ctx.forwarded_addr)
      end
    end,
  }

  router["/ip/info"] = {
    id              = "get-forwarded-ip-info",
    description = "returns IP address info",
    metrics_enabled = true,
    allow_untrusted = true,
    content_type = "application/json",
    middleware      = {
      [mw.phase.PRE_HANDLER] = {
        request.middleware.enable_logging,
      },
    },
    ---@param ctx doorbell.ctx
    GET = function(ctx)
      local addr = ctx.forwarded_addr

      local info, err, status = ip.info_api(addr, ngx.var.arg_raw)

      if info then
        return send(200, info)

      else
        return send(status or 500, { message = err or "unknown error" })
      end
    end,
  }

  router["~^/ip/info/(?<addr>.+)"] = {
    id              = "get-ip-info",
    description = "returns IP address info",
    metrics_enabled = true,
    allow_untrusted = false,
    content_type = "application/json",
    middleware      = {
      [mw.phase.PRE_HANDLER] = {
        request.middleware.enable_logging,
      },
    },
    GET = function(_, match)
      local addr = match.addr
      local info, err, status = ip.info_api(addr, ngx.var.arg_raw)

      if info then
        return send(200, info)

      else
        return send(status or 500, { message = err or "unknown error" })
      end
    end,
  }


  ---@param obj table
  local function schema_api(obj)
    local serialized = drop_functions(obj)
    local api = {
      metrics_enabled = true,
      middleware      = {
        [mw.phase.PRE_HANDLER] = {
          request.middleware.enable_logging,
        },
      },
      allow_untrusted = true,
      content_type = "application/json",
      GET = function()
        return send(200, serialized)
      end,
    }

    if type(obj.validate) == "function" then
      api.PUT = function(ctx)
        local json = get_json_body(ctx, "table")

        local ok, err = obj.validate(json)

        if ok then
          send(200, json)
        else
          send(400, { message = err })
        end
      end
    end

    return api
  end

  router["/schema/config"]        = schema_api(schema.config)
  router["/schema/config/fields"] = schema_api(schema.config.fields)
  router["/schema/config/input"]  = schema_api(schema.config.fields)
  router["/schema/config/entity"] = schema_api(schema.config.entity)

  for name, field in pairs(schema.config.fields) do
    router["/schema/config/fields/" .. name] = schema_api(field)
  end

  router["/schema/rule"]          = schema_api(schema.rule)
  router["/schema/rule/fields"]   = schema_api(schema.rule.fields)
  router["/schema/rule/patch"]    = schema_api(schema.rule.patch)
  router["/schema/rule/create"]   = schema_api(schema.rule.create)
  router["/schema/rule/entity"]   = schema_api(schema.rule.entity)

  for name, field in pairs(schema.rule.fields) do
    router["/schema/rule/fields/" .. name] = schema_api(field)
  end

  router["/approvals"] = {
    id              = "approvals-collection",
    description = "list pending access requests",
    metrics_enabled = true,
    allow_untrusted = false,
    content_type = "application/json",
    middleware      = {
      [mw.phase.PRE_HANDLER] = {
        request.middleware.enable_logging,
      },
    },

    GET = function()
      local list = auth.list_approvals()
      return send(200, { data = list })
    end,

    POST = function(ctx)
      local json = get_json_body(ctx, "table")
      local status, err = auth.answer(json)
      if status >= 400 then
        return send(status, { error = err })
      end

      return send(status, { message = "OK" })
    end,

  }


end

return _M
