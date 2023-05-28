local test = require "spec.testing"
local const = require "doorbell.constants"
local splitlines = require("pl.stringx").splitlines
local split = require("ngx.re").split
local nkeys = require "table.nkeys"


---@param s string|nil
---@return string[]
local function parse_labels(s)
  if not s then return {} end

  -- {name="main",status="expire"}

  -- strip { } from ends
  assert(s:sub(1,1) == "{" and s:sub(-1, -1) == "}")
  s = s:sub(2, -2)

  local labels = {}
  for _, elem in ipairs(split(s, ", *") or {}) do
    local k, v = assert(elem:match([[([^=]+)="([^"]+)"]]))
    assert(labels[k] == nil)
    labels[k] = v
  end

  return labels
end

---@class spec.testing.prometheus.metrics
local metrics_mt = {
  ---@type spec.testing.prometheus.metric[]
  list = {},

  ---@type table<string, spec.testing.prometheus.metric[]>
  by_name = {},

  ---@type string[]
  names = {},
}
metrics_mt.__index = metrics_mt

---@param metric spec.testing.prometheus.metric
---@param labels? table<string, string>
local function match(metric, labels)
  local num_metric_labels = nkeys(metric.labels)

  local num_user_labels = (labels and nkeys(labels)) or 0

  if num_metric_labels == 0 then
    return num_user_labels == 0
  end

  assert(num_metric_labels > 0, "labels table was empty")

  for k, v in pairs(labels) do
    assert(metric.labels[k] ~= nil, "invalid label for " .. metric.name ..
                                    ": " .. k)

    if metric.labels[k] ~= v then
      return false
    end
  end

  return true
end

---@param name string
---@param labels table<string, string>
---@return number
function metrics_mt:get_value(name, labels)
  local list = self.by_name[name]
  assert.is_table(list, "no metrics found for '" .. name .. "'")

  ---@type spec.testing.prometheus.metric
  local found
  local count = nkeys(labels)

  for _, metric in ipairs(list) do
    assert.same(count, nkeys(metric.labels), "label count mismatch")

    if match(metric, labels) then
      found = metric
      break
    end
  end

  assert.not_nil(found, "no metric found with name '" .. name .. "' and "
                     .. "labels: " .. test.pretty_print(labels))

  return found.value
end

---@param name string
---@return boolean
function metrics_mt:have(name)
  return self.by_name[name] ~= nil
end


---@param name string
---@param labels? table<string, string>
---@return spec.testing.prometheus.metric[]
function metrics_mt:get(name, labels)
  local list = assert.is_table(self.by_name[name],
                               "unknown metric: " .. name)

  if not labels then
    return list
  end

  local found = {}

  for _, metric in ipairs(list) do
    if match(metric, labels) then
      table.insert(found, metric)
    end
  end

  return found
end



describe("prometheus metrics", function()
  ---@type spec.testing.client
  local client

  ---@type spec.testing.nginx
  local nginx

  ---@type doorbell.config
  local conf

  ---@type spec.testing.client
  local metrics_client

  ---@return spec.testing.prometheus.metrics
  local function get_metrics()
    metrics_client:get("/metrics")

    ---@class spec.testing.prometheus.metric : table
    ---
    ---@field name   string
    ---@field labels table<string, string>
    ---@field value  number

    ---@type spec.testing.prometheus.metrics
    local metrics = {
      ---@type spec.testing.prometheus.metric[]
      list = {},

      ---@type table<string, spec.testing.prometheus.metric[]>
      by_name = {},

      ---@type string[]
      names = {},
    }

    local names = {}

    for _, line in ipairs(splitlines(metrics_client.response.body)) do
      -- example:
      -- doorbell_cache_lookups{name="main",status="expire"} 0

      local m = ngx.re.match(line, [[
        ^
          (?<name>[a-zA-Z]+[a-zA-Z0-9_]*)

          (?<labels>\{[^}]+\})?

          \s

          (?<value>[0-9]+(\.[0-9]*)?)
        $
      ]], "ojx")

      if m then
        local name = assert(m.name)
        local labels = parse_labels(m.labels)
        local value = assert(tonumber(m.value))

        local metric = {
          name   = name,
          labels = labels,
          value  = value,
        }

        table.insert(metrics, metric)

        if not names[name] then
          names[name] = true
          table.insert(metrics.names, name)
        end

        metrics.by_name[name] = metrics.by_name[name] or {}
        table.insert(metrics.by_name[name], metric)
      end
    end

    setmetatable(metrics, metrics_mt)
    return metrics
  end

  local interval = 1

  lazy_setup(function()
    conf = test.config()
    conf.trusted = { "0.0.0.0/0" }
    conf.metrics = {
      interval = interval,
    }

    nginx = test.nginx(conf)

    nginx:start()

    metrics_client = nginx:add_client(test.client())
    metrics_client.assert_status.GET = { eq = 200 }

    client = nginx:add_client(test.client())

    client.assert_status.POST = { eq = 201 }
    client.assert_status.GET = { eq = 200 }
  end)

  lazy_teardown(function()
    nginx:stop()
  end)

  describe("doorbell_rules_total", function()
    local name = "doorbell_rules_total"

    lazy_setup(function()
      test.await.truthy(function()
        return get_metrics():have(name)
      end, interval, 0.1)
    end)

    it("measures the number of rule entities", function()
      local metrics = get_metrics()

      local labels = { action = "allow", source = "api" }
      local before = metrics:get_value(name, labels)

      client:post("/rules", {
        json = {
          action = "allow",
          addr = test.random_ipv4(),
          comment = "test for metrics",
        }
      })

      local id = assert.is_string(client.response.json.id)

      test.await.truthy(function()
        return get_metrics():get_value(name, labels) > before
      end, 5, 0.1)

      client:delete("/rules/" .. id)

      test.await.truthy(function()
        return get_metrics():get_value(name, labels) == before
      end, 5, 0.1)
    end)

    it("labels by rule.action", function()
      local metrics = get_metrics()

      for _, action in pairs(const.actions) do
        local list = metrics:get(name, { action  = action })
        assert.is_table(list)
        assert.is_true(#list > 0)
      end
    end)

    it("labels by rule.source", function()
      local metrics = get_metrics()

      for _, source in pairs(const.sources) do
        local list = metrics:get(name, { source  = source })
        assert.is_table(list)
        assert.is_true(#list > 0)
      end
    end)
  end)

  describe("doorbell_requests_total", function()
    local name = "doorbell_requests_total"

    lazy_setup(function()
      test.await.truthy(function()
        return get_metrics():have(name)
      end, interval, 0.1)
    end)

    it("is a counter representing the number of requests", function()
      local addr = test.random_ipv4()
      client:post("/rules", {
        json = {
          action = "allow",
          addr = addr,
          comment = "test for metrics",
        }
      })

      client:reset()
      client:add_x_forwarded_headers(addr, "GET", "http://foo.test/")
      client:get("/ring")

      local labels = { status = "200" }
      local before = get_metrics():get_value(name, labels)

      for _ = 1, 100 do
        client:get("/ring")
      end

      test.await.truthy(function()
        return (get_metrics():get_value(name, labels) - 100) >= before
      end, 5, 0.1)
    end)
  end)

end)


describe("prometheus metrics (disabled)", function()
  ---@type spec.testing.nginx
  local nginx

  ---@type spec.testing.client
  local metrics_client

  lazy_setup(function()
    local conf = test.config()
    conf.metrics = {
      disable = true,
    }

    nginx = test.nginx(conf)

    nginx:start()

    metrics_client = nginx:add_client(test.client())
  end)

  lazy_teardown(function()
    nginx:stop()
  end)

  it("/metrics returns 405", function()
    metrics_client:get("/metrics")
    assert.is_nil(metrics_client.err)
    assert.same(405, metrics_client.response.status)
  end)
end)
