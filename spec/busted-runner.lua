setmetatable(_G, nil)

_G._TEST = true
package.path = "./lib/?.lua;" .. package.path
package.path = "./?.lua;" .. package.path

pcall(require, "luarocks.loader")

-- Busted command-line runner
require 'busted.runner'({ standalone = false })
