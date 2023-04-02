local const = {}

local join = require("spec.testing.fs").join

const.ROOT_DIR = os.getenv("PWD")

const.ASSET_DIR = join(const.ROOT_DIR, "assets")

const.FIXTURES_DIR = join(const.ROOT_DIR, "spec", "fixtures")

const.MOCK_UPSTREAM_PORT = 8765

return const
