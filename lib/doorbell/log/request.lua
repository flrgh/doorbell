local _M = {}

local encode = require("cjson.safe").new().encode
local open = io.open
local fmt = string.format
local insert = table.insert
local concat = table.concat


local buf = {}

function _M.write(path, entries)
  local fh, err = open(path, "a+")
  if not fh then
    return nil, err
  end

  local n = 0
  local errors
  for i = 1, (entries.n or #entries) do
    local json
    json, err = encode(entries[i])
    if json ~= nil then
      n = n + 1
      buf[n] = json
    else
      errors = errors or {}
      insert(errors, fmt("failed encoding entry #%s: %s", i, err))
    end
  end

  if n > 0 then
    n = n + 1
    buf[n] = "\n"
    local ok
    ok, err = fh:write(concat(buf, "\n", 1, n))
    if not ok then
      err = fmt("failed writing to %s: %s", path, err)
      if errors then
        insert(errors, err)
      end
    end
  end

  fh:close()

  if errors then
    err = concat(errors, "\n")
  end

  if err then
    return nil, err
  end

  return true
end

return _M
