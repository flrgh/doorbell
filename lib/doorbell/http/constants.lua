---@class doorbell.http.constants
local _M = {}

--- Well-known header constants
_M.headers = {}
_M.headers.CONTENT_TYPE = "Content-Type"
_M.headers.CONTENT_LENGTH = "Content-Length"
_M.headers.AUTHORIZATION = "Authorization"

--- Well-known content-type/mimetype values
_M.types = {}
_M.types.PLAINTEXT = "text/plain"
_M.types.HTML = "text/html"
_M.types.JSON = "application/json"
_M.types.FORM_URLENCODED = "application/x-www-form-urlencoded"

return _M
