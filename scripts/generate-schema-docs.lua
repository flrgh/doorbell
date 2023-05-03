#!/usr/bin/env resty

setmetatable(_G, nil)

local schema = require "doorbell.schema"
local util = require "doorbell.util"
local stdout = io.stdout

local function print(s)
  stdout:write(s)
end

local fmt = string.format

local function printf(f, ...)
  print(fmt(f, ...))
end

local function println(s)
  print(s)
  print("\n")
end

local function printfln(f, ...)
  printf(f, ...)
  print("\n")
end

---@generic K
---@generic V
---@param t table<K, V>
---@return fun():K, V
local function iter_kv(t)
  local keys = util.table_keys(t)
  local n = 0

  return function()
    n = n + 1

    local key = keys[n]

    if key ~= nil then
      return key, t[key]
    end
  end
end

---@param parent? string
---@param child?  string
---@param s     doorbell.schema
---@return string
local function slug(parent, child, s)
  local str
  if parent then
    str = parent .. "." .. child

  else
    str = child
  end

  return str
end


---@param object_name    string
---@param s       doorbell.schema.object
---@param parent? doorbell.schema
---@param parent_name? string
local function print_toc(object_name, s, parent, parent_name)
  println("#### fields")
  println("| name | type |")
  println("|------|------|")

  for name, field in iter_kv(s.properties) do
    printfln("| [%s](#%s) | %s |", name, slug(object_name, name), field.type)
  end
end


---@param name         string
---@param s            doorbell.schema
---@param parent?      doorbell.schema
---@param parent_name? string
local function print_schema(name, s, parent, parent_name)
  if not parent_name and parent and parent.title then
    parent_name = parent.title
  end

  if parent_name then
    name = parent_name .. "." .. name
  end

  printfln("<a name=%q></a>", slug(parent_name, name, s))
  printfln("### %s", name)
  printfln("(%s) %s\n", s.type, s.description)

  if s.type == "object" then
    print_toc(name, s, parent, parent_name)
  end

  if s.default ~= nil then
    printf("#### default\n\n```json\n%s\n```\n", util.pretty_json(s.default))
  end

  if s.examples then
    println("#### examples")
    for _, example in ipairs(s.examples) do

      if example.comment then
        println(example.comment)
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


println("# doorbell configuration")
print_schema("config", schema.config.input, nil, nil)

println("# doorbell rules\n")
print_schema("rule", schema.rule.entity, nil, nil)
