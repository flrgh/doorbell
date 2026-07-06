---@class doorbell.util.uri
local _M = {}

local ada = require "resty.ada"

local string_find  = string.find
local string_gsub  = string.gsub
local string_byte  = string.byte
local string_char  = string.char
local string_sub   = string.sub
local string_upper = string.upper
local table_new    = require "table.new"
local tonumber     = tonumber
local ngx_re_gsub  = ngx.re.gsub

local SLASH = string_byte("/")
local DOT   = string_byte(".")

---@type table<integer, boolean>
local RESERVED = table_new(256, 0)
do
  -- Charset (RFC 3986 / WHATWG):
  --   reserved   = "!" / "*" / "'" / "(" / ")" / ";" / ":" / "@" / "&" / "="
  --              / "+" / "$" / "," / "/" / "?" / "%" / "#" / "[" / "]"
  --   unreserved = ALPHA / DIGIT / "-" / "." / "_" / "~"
  local reserved = "!*'();:@&=+$,/?%#[]"

  for i = 1, #reserved do
    RESERVED[string_byte(reserved, i)] = true
  end
end


---@param m table
---@return string
local function normalize_decode(m)
  local hex = m[1]
  local num = tonumber(hex, 16)

  return RESERVED[num]
    -- reserved: uppercase the triplet so all matchers see one canonical form
    and string_upper(m[0])
    -- decode unreserved (and anything else that is not reserved)
    or string_char(num)
end


---@param url string
---
---@return string? host
---@return string? path
---@return string? error
local function parse(url)
  local u, err = ada.parse(url)
  if not u then
    return nil, nil, err or "invalid url"
  end

  local host = u:get_hostname()
  local path = u:get_pathname()
  u:free()

  -- strip trailing dot from hostname
  -- ada already handled everything else
  if #host > 1 and string_byte(host, -1) == DOT then
    host = string_sub(host, 1, -2)
  end

  if #path > 0 and path ~= "/" then
    -- unreserved percent-decoding and triplet case-normalization
    if string_find(path, "%", 1, true) then
      path = ngx_re_gsub(path, "%([\\dA-Fa-f]{2})", normalize_decode, "jo")
    end

    -- %2F -> /  (policy: treat an encoded slash like a real slash)
    if string_find(path, "%2F", 1, true) then
      path = string_gsub(path, "%%2F", "/")
    end

    -- //+ -> /
    if string_find(path, "//", 1, true) then
      path = string_gsub(path, "//+", "/")
    end

    -- strip trailing /
    if #path > 1 and string_byte(path, -1) == SLASH then
      path = string_sub(path, 1, -2)
    end
  end

  return host, path
end


--- Normalize a (scheme, host, uri) triple
---
---@param  scheme string -- x-forwarded-proto
---@param  host   string -- x-forwarded-host
---@param  uri    string -- x-forwarded-uri
---@return string? host
---@return string? path
---@return string? err
function _M.normalize_forwarded(scheme, host, uri)
  if scheme ~= "http" and scheme ~= "https" then
    return nil, nil, "invalid scheme"
  end

  if type(uri) ~= "string" or string_byte(uri, 1) ~= SLASH then
    return nil, nil, "invalid uri"
  end

  local h, p, err = parse(scheme .. "://" .. host .. uri)
  if err then
    return nil, err
  end

  return h, p
end


---@param  host string
---@return string? host
---@return string? err
function _M.normalize_host(host)
  local norm, _, err = parse("http://" .. host)
  if err then
    return err
  end
  return norm
end


---@param  path string
---@return string? path
---@return string? err
function _M.normalize_path(path)
  if type(path) ~= "string" or string_byte(path, 1) ~= SLASH then
    return nil, "invalid path (must start with /)"
  end

  if path == "" or path == "/" then
    return path
  end

  local _, p, err = parse("http://x" .. path)
  if not p then
    return nil, err
  end

  return p
end


return _M
