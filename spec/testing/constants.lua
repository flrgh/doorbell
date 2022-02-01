local const = {}

local join = require("spec.testing.fs").join

const.ROOT_DIR = os.getenv("PWD")

const.ASSET_DIR = join(const.ROOT_DIR, "assets")

return const
