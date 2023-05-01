#!/usr/bin/env resty

local schema = require "doorbell.schema"
local util = require "doorbell.util"

local fmt = string.format
local function printf(f, ...)
  print(fmt(f, ...))
end

print("## configuration\n")
for _, name in ipairs(util.table_keys(schema.config.fields, true)) do
  local field = schema.config.fields[name]
  printf("### %s\n", name)
  printf("%s\n", field.description)

  if field.examples and #field.examples > 0 then
    printf("Examples:\n")
    for _, ex in ipairs(field.examples) do
      printf("  * %s\n", ex)
    end
  end
end
