#!/usr/bin/env resty

setmetatable(_G, nil)

local schema = require "doorbell.schema"
local util = require "doorbell.util"

local fmt = string.format
local function printf(f, ...)
  print(fmt(f, ...))
end

---@param name    string
---@param s       doorbell.schema
---@param parent? doorbell.schema
local function print_schema(name, s, parent, parent_name)
  if not s.description then
    return
  end

  if not parent_name and parent and parent.title then
    parent_name = parent.title
  end

  if parent_name then
    name = parent_name .. "." .. name
  end

  print("---\n")

  printf("### %s\n", name)
  printf("(%s) %s\n", s.type, s.description)

  if s.default ~= nil then
    printf("#### default\n\n```json\n%s\n```\n", util.pretty_json(s.default))
  end

  if s.examples then
    print("#### examples\n")
    for _, example in ipairs(s.examples) do

      if example.comment then
        printf("%s\n", example.comment)
      end

      assert(example.value ~= nil, "example with empty value?")

      printf("```json\n%s\n```\n", util.pretty_json(example.value))
    end
  end

  if s.type == "array" then
    print_schema(name .. "[]", s.items, s)

  elseif s.type == "object" then
    for _, prop in ipairs(util.table_keys(s.properties)) do
      local field = s.properties[prop]
      print_schema(prop, field, s, name)
    end
  end
end


print("## configuration\n")

for _, name in ipairs(util.table_keys(schema.config.fields)) do
  local field = schema.config.fields[name]
  print_schema(name, field, schema.config.entity, "config")
end

print("## rules\n")

for _, name in ipairs(util.table_keys(schema.rule.fields)) do
  local field = schema.rule.fields[name]
  print_schema(name, field, schema.rule.entity, "rule")
end
