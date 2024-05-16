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

    ["doorbell.api"] = "lib/doorbell/api.lua",
    ["doorbell.api.access"] = "lib/doorbell/api/access.lua",
    ["doorbell.api.auth-test"] = "lib/doorbell/api/auth-test.lua",
    ["doorbell.api.ip"] = "lib/doorbell/api/ip.lua",
    ["doorbell.api.nginx"] = "lib/doorbell/api/nginx.lua",
    ["doorbell.api.rules"] = "lib/doorbell/api/rules.lua",
    ["doorbell.api.schema"] = "lib/doorbell/api/schema.lua",

    ["doorbell.auth"] = "lib/doorbell/auth.lua",
    ["doorbell.auth.access"] = "lib/doorbell/auth/access.lua",
    ["doorbell.auth.api-key"] = "lib/doorbell/auth/api-key.lua",
    ["doorbell.auth.email"] = "lib/doorbell/auth/email.lua",
    ["doorbell.auth.forwarded-request"] = "lib/doorbell/auth/forwarded-request.lua",
    ["doorbell.auth.openid"] = "lib/doorbell/auth/openid.lua",
    ["doorbell.auth.ring"] = "lib/doorbell/auth/ring.lua",

    ["doorbell.cache"] = "lib/doorbell/cache.lua",
    ["doorbell.cache.shared"] = "lib/doorbell/cache/shared.lua",

    ["doorbell.config"] = "lib/doorbell/config.lua",

    ["doorbell.constants"] = "lib/doorbell/constants.lua",

    ["doorbell.http"] = "lib/doorbell/http.lua",

    ["doorbell.ip"] = "lib/doorbell/ip.lua",
    ["doorbell.ip.countries"] = "lib/doorbell/ip/countries.lua",

    ["doorbell.log"] = "lib/doorbell/log.lua",
    ["doorbell.log.request"] = "lib/doorbell/log/request.lua",

    ["doorbell.mail"] = "lib/doorbell/mail.lua",

    ["doorbell.metrics"] = "lib/doorbell/metrics.lua",

    ["doorbell.middleware"] = "lib/doorbell/middleware.lua",

    ["doorbell.nginx"] = "lib/doorbell/nginx.lua",
    ["doorbell.nginx.conf"] = "lib/doorbell/nginx/conf.lua",
    ["doorbell.nginx.conf.defaults"] = "lib/doorbell/nginx/conf/defaults.lua",

    ["doorbell.notify"] = "lib/doorbell/notify.lua",
    ["doorbell.notify.strategies.pushover"] = "lib/doorbell/notify/strategies/pushover.lua",

    ["doorbell.ota"] = "lib/doorbell/ota.lua",

    ["doorbell.plugins"] = "lib/doorbell/plugins.lua",
    ["doorbell.plugins.jellyfin"] = "lib/doorbell/plugins/jellyfin.lua",

    ["doorbell.policy"] = "lib/doorbell/policy.lua",
    ["doobrell.policy.redirect-for-approval"] = "lib/doorbell/policy/redirect-for-approval.lua",
    ["doobrell.policy.request-approval"] = "lib/doorbell/policy/request-approval.lua",
    ["doobrell.policy.return-401"] = "lib/doorbell/policy/return-401.lua",
    ["doobrell.policy.validate-email"] = "lib/doorbell/policy/validate-email.lua",

    ["doorbell.request"] = "lib/doorbell/request.lua",

    ["doorbell.router"] = "lib/doorbell/router.lua",

    ["doorbell.routes"] = "lib/doorbell/routes.lua",

    ["doorbell.rules"] = "lib/doorbell/rules.lua",
    ["doorbell.rules.api"] = "lib/doorbell/rules/api.lua",
    ["doorbell.rules.codec"] = "lib/doorbell/rules/codec.lua",
    ["doorbell.rules.manager"] = "lib/doorbell/rules/manager.lua",
    ["doorbell.rules.matcher"] = "lib/doorbell/rules/matcher.lua",
    ["doorbell.rules.shm"] = "lib/doorbell/rules/shm.lua",
    ["doorbell.rules.stats"] = "lib/doorbell/rules/stats.lua",
    ["doorbell.rules.storage"] = "lib/doorbell/rules/storage.lua",
    ["doorbell.rules.transaction"] = "lib/doorbell/rules/transaction.lua",

    ["doorbell.schema"] = "lib/doorbell/schema.lua",

    ["doorbell.shm"] = "lib/doorbell/shm.lua",

    ["doorbell.users"] = "lib/doorbell/users.lua",

    ["doorbell.util"] = "lib/doorbell/util.lua",
    ["doorbell.util.file"] = "lib/doorbell/util/file.lua",
    ["doorbell.util.timer"] = "lib/doorbell/util/timer.lua",

    ["doorbell.views"] = "lib/doorbell/views.lua",
    ["doorbell.views.answer"] = "lib/doorbell/views/answer.lua",
    ["doorbell.views.rule_list"] = "lib/doorbell/views/rule_list.lua",
    ["doobrell.views.validate_email"] = "lib/doorbell/views/validate_email.lua",
  },
  install = {
    bin = {
      "bin/render-nginx-template"
    }
  }
}

supported_platforms = { "linux" }

dependencies = {
  "inspect == 3.1.3",
  "lua_system_constants == 0.1.4",
  "lua-resty-ljsonschema == 1.1.6-2",
  "lua-resty-http == 0.17.1",
  "lua-resty-ipmatcher == 0.6.1",
  "lua-resty-jit-uuid == 0.0.7",
  "lua-resty-openidc == 1.7.6",
  "lua-resty-pushover == 0.1.0",
  "lua-resty-template == 2.0",
  "luafilesystem-ffi == 0.3.0",
  "luajit-geoip >= 2.1.0",
  "luasocket == 3.1.0",
  "nginx-lua-prometheus == 0.20230607",
  "penlight == 1.13.1",
  "api7-lua-resty-jwt == 0.2.5",
  "lua-resty-mlcache = 2.6.0",
  "lua-resty-mail = 1.1.0",
}

test_dependencies = {
  "luafilesystem >= 1.8.0",
  "busted >= 2.2.0",
  "busted-htest >= 1.0.0",
}

test = {
  type = "command",
  command = "./bin/busted",
}

-- vim: set ft=lua ts=2 sw=2 sts=2 et :
