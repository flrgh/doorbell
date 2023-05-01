local const = {}

local nginx = require("doorbell.nginx")
local join = require("spec.testing.fs").join

const.ROOT_DIR = os.getenv("PWD") or "."

const.RUNTIME_PATH = join(const.ROOT_DIR, "test")

const.ASSET_PATH = join(const.ROOT_DIR, "assets")

const.FIXTURES_PATH = join(const.ROOT_DIR, "spec", "fixtures")

const.MOCK_UPSTREAM_PORT = 8765

const.GEOIP_CITY_DB = join(const.ROOT_DIR, "geoip", "GeoLite2-City-Test.mmdb")

const.GEOIP_COUNTRY_DB = join(const.ROOT_DIR, "geoip", "GeoLite2-Country-Test.mmdb")

const.GEOIP_ASN_DB = join(const.ROOT_DIR, "geoip", "GeoLite2-ASN-Test.mmdb")

const.LUA_PATH = nginx.lua_path(
  const.ROOT_DIR,
  join(const.ROOT_DIR, "lib")
)

return const
