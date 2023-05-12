local _M = {}

local cjson    = require("cjson.safe").new()
local encode   = cjson.encode
local open     = io.open
local fmt      = string.format
local concat   = table.concat
local insert   = table.insert

cjson.encode_keep_buffer(true)
cjson.encode_number_precision(16)
cjson.encode_escape_forward_slash(false)

---@param path string
---@param entries table[]
---
---@return boolean? ok
---@return string?  error
---@return integer? written
function _M.write(path, entries)
  assert(type(path) == "string", "path must be a string")
  assert(type(entries) == "table", "entries must be a table")

  local fh, err = open(path, "a+")
  if not fh then
    return nil, err, 0
  end

  local n = #entries
  local c = 0
  local errors = {}
  local data, _

  for i = 1, n do
    local entry = entries[i]

    data, err = encode(entry)

    if data then
      _, err = fh:write(data .. "\n")
      if err then
        insert(errors, fmt("failed to write entry #%s: %s", i, err))

      else
        c = c + 1
      end

    else
      insert(errors, fmt("failed to JSON encode entry #%s: %s", i, err))
    end
  end

  fh:close()

  if #errors > 0 then
    return nil, concat(errors, "\n"), c
  end

  return true, nil, c
end


return _M
