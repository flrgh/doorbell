package = "doorbell"
version = "dev-1"
rockspec_format = "3.0"

source = {
  url = "git+ssh://git@github.com/flrgh/doorbell.git"
}

description = {
  summary = "Rule-based forward auth server built on OpenResty",
  homepage = "https://github.com/flrgh/doorbell",
  license = "MIT",
  maintainer = "Michael Martin <flrgh@protonmail.com>"
}

build = {
  type = "builtin",
  modules = {
    ["doorbell"] = "lib/doorbell.lua",
    ["doorbell.auth"] = "lib/doorbell/auth.lua",
    ["doorbell.cache"] = "lib/doorbell/cache.lua",
    ["doorbell.config"] = "lib/doorbell/config.lua",
    ["doorbell.constants"] = "lib/doorbell/constants.lua",
    ["doorbell.http"] = "lib/doorbell/http.lua",
    ["doorbell.ip"] = "lib/doorbell/ip.lua",
    ["doorbell.ip.countries"] = "lib/doorbell/ip/countries.lua",
    ["doorbell.log"] = "lib/doorbell/log.lua",
    ["doorbell.log.request"] = "lib/doorbell/log/request.lua",
    ["doorbell.metrics"] = "lib/doorbell/metrics.lua",
    ["doorbell.middleware"] = "lib/doorbell/middleware.lua",
    ["doorbell.nginx"] = "lib/doorbell/nginx.lua",
    ["doorbell.nginx.defaults"] = "lib/doorbell/nginx/defaults.lua",
    ["doorbell.notify"] = "lib/doorbell/notify.lua",
    ["doorbell.notify.strategies.pushover"] = "lib/doorbell/notify/strategies/pushover.lua",
    ["doorbell.ota"] = "lib/doorbell/ota.lua",
    ["doorbell.request"] = "lib/doorbell/request.lua",
    ["doorbell.auth.ring"] = "lib/doorbell/auth/ring.lua",
    ["doorbell.auth.request"] = "lib/doorbell/auth/request.lua",
    ["doorbell.routes"] = "lib/doorbell/routes.lua",
    ["doorbell.router"] = "lib/doorbell/router.lua",
    ["doorbell.rules"] = "lib/doorbell/rules.lua",
    ["doorbell.rules.api"] = "lib/doorbell/rules/api.lua",
    ["doorbell.rules.manager"] = "lib/doorbell/rules/manager.lua",
    ["doorbell.rules.matcher"] = "lib/doorbell/rules/matcher.lua",
    ["doorbell.rules.shm"] = "lib/doorbell/rules/shm.lua",
    ["doorbell.rules.stats"] = "lib/doorbell/rules/stats.lua",
    ["doorbell.rules.storage"] = "lib/doorbell/rules/storage.lua",
    ["doorbell.rules.transaction"] = "lib/doorbell/rules/transaction.lua",
    ["doorbell.schema"] = "lib/doorbell/schema.lua",
    ["doorbell.shm"] = "lib/doorbell/shm.lua",
    ["doorbell.util"] = "lib/doorbell/util.lua",
    ["doorbell.views"] = "lib/doorbell/views.lua",
    ["doorbell.views.answer"] = "lib/doorbell/views/answer.lua",
    ["doorbell.views.rule_list"] = "lib/doorbell/views/rule_list.lua"
  },
  install = {
    bin = {
      "bin/render-nginx-template"
    }
  }
}

supported_platforms = { "linux" }

dependencies = {
  "lua-resty-ljsonschema == 1.1.3",
  "lua-cjson >= 2.1.0",
  "lua-resty-http >= 0.16.1-0",
  "lua-resty-ipmatcher == 0.6.1",
  "lua-resty-jit-uuid == 0.0.7",
  "lua-resty-pushover == 0.1.0",
  "lua-resty-template == 2.0",
  "luafilesystem-ffi == 0.3.0",
  "luajit-geoip == 2.1.0",
  "luasocket",
  "nginx-lua-prometheus == 0.20221218",
  "penlight >= 1.0.0",
}

test_dependencies = {
  "inspect",
  "luafilesystem",
  "busted >= 2.1.1",
  "busted-htest >= 1.0.0",
}

test = {
  type = "command",
  command = "./bin/busted",
}

-- vim: set ft=lua ts=2 sw=2 sts=2 et :
