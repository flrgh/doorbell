local test = require "spec.testing"
local const = require "doorbell.constants"
local cjson = require "cjson"

local REQUEST_ID = const.headers.request_id

local fs = test.fs

describe("json request log", function()
  ---@type spec.testing.nginx
  local nginx

  ---@type string
  local log_file

  lazy_setup(function()
    local conf = test.config()
    log_file = fs.join(conf.log_path, "doorbell.json.log")

    nginx = test.nginx(conf)
    nginx:conf_test()
    nginx:start()
  end)

  lazy_teardown(function()
    nginx:stop()
  end)

  it("writes to a file", function()
    local client = test.client()
    finally(function() client:close() end)

    client.headers["user-agent"] = "json-log"
    client.headers["x-my-special-header"] = "json-log"
    client.request.query = {
      foo = "bar",
    }

    ngx.update_time()
    local now = ngx.now()

    client:get("/rules")
    assert.is_nil(client.err)
    assert.same(200, client.response.status)

    local entry

    test.await.no_error(function()
      entry = fs.read_json_file(log_file)
      return true
    end, 3, 0.25)

    assert.is_table(entry)
    assert.table_shape({
      addr                 = "string",
      client_addr          = "string",
      connection           = "number",
      connection_requests  = "number",
      duration             = "number",
      is_trusted_proxy     = "boolean",
      log_time             = "number",
      request_headers      = "table",
      request_http_host    = "string",
      request_http_method  = "string",
      request_id           = "string",
      request_path         = "string",
      request_total_bytes  = "number",
      response_headers     = "table",
      response_total_bytes = "number",
      route_id             = "string",
      route_path           = "string",
      start_time           = "number",
      status               = "number",
      version              = "string",
      worker_id            = "number",
      worker_pid           = "number",
    }, entry)

    assert.same("json-log", entry.request_headers["user-agent"])
    assert.same("json-log", entry.request_headers["x-my-special-header"])

    local req_id = assert.response(client.response).has.header(REQUEST_ID)
    assert.same(req_id, entry.request_id)

    assert.near(now, entry.start_time, 0.5)


    local ignored_headers = {
      "date",
      "connection",
    }

    for _, header in ipairs(ignored_headers) do
      entry.response_headers[header] = nil
      client.response.headers[header] = nil
    end

    assert.same(client.response.headers, entry.response_headers)

    -- now let's make sure it keeps up with a bunch of requests

    fs.truncate(log_file)
    local count = 1000
    for i = 1, count do
      client.headers["x-count"] = tostring(i)
      client:get("/rules")
      assert.is_nil(client.err)
      assert.same(200, client.response.status)
    end

    test.await.no_error(function()
      local fh = assert(io.open(log_file, "r"))
      local found = 0

      local seen = {}

      for line in fh:lines() do
        local log = cjson.decode(line)
        assert.is_table(log)
        assert.is_table(log.request_headers)
        local c = assert.is_string(log.request_headers["x-count"])

        assert.is_nil(seen[c], "duplicate log entry found")
        seen[c] = true

        found = found + 1
      end

      fh:close()

      assert.same(count, found)
    end, 5, 0.5)
  end)
end)
