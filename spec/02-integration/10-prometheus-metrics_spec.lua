local test = require "spec.testing"
local const = require "doorbell.constants"
local splitlines = require("pl.stringx").splitlines
local split = require("ngx.re").split
local nkeys = require "table.nkeys"
local signal = require "resty.signal"


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
---@return number?
function metrics_mt:get_value(name, labels)
  local list = self.by_name[name]
  if not list then
    return
  end

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

  return found and found.value
end

---@param name string
---@return boolean
function metrics_mt:have(name)
  return self.by_name[name] ~= nil
end


---@param name string
---@param labels? table<string, string>
---@return spec.testing.prometheus.metric[]|nil
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

  if #found == 0 then found = nil end
  return found
end



describe("prometheus metrics", function()
  local interval = 0.5

  ---@type spec.testing.client
  local client

  ---@type spec.testing.nginx
  local nginx

  ---@type spec.testing.client
  local api

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

  local await_timeout = interval * 5

  local await_metric = {
    ---@param name string
    ---@param labels? string[]
    ---@return spec.testing.prometheus.metric[]
    exists = function(name, labels)
      local metrics

      test.await.truthy(function()
        metrics = get_metrics():get(name, labels)
        return metrics and #metrics > 0
      end, await_timeout, 0.1)

      return metrics
    end,

    ---@param name string
    ---@param labels? string[]
    ---@param value number
    ---@return number
    gte = function(name, labels, value)
      assert.is_number(value)

      local new

      test.await.truthy(function()
        local metrics = get_metrics()
        new = metrics:get_value(name, labels)
        return new and new >= value
      end, await_timeout, 0.1)

      return new
    end,


    ---@param name string
    ---@param labels? string[]
    ---@param value number
    ---@return number
    gt = function(name, labels, value)
      assert.is_number(value)

      local new

      test.await.truthy(function()
        local metrics = get_metrics()
        new = metrics:get_value(name, labels)
        return new and new > value
      end, await_timeout, 0.1)

      return new
    end,

    ---@param name string
    ---@param labels? string[]
    ---@param value number
    eq = function(name, labels, value)
      assert.is_number(value)

      test.await.truthy(function()
        local metrics = get_metrics()
        local new = metrics:get_value(name, labels)
        return new and new == value
      end, await_timeout, 0.1)
    end,


    ---@param name string
    ---@param labels? string[]
    ---@return number
    value = function(name, labels)
      local value

      test.await.truthy(function()
        value = get_metrics():get_value(name, labels)
        return value
      end, await_timeout, 0.1)

      return value
    end,

    ---@param name string
    ---@param labels? string[]
    ---@param value number
    ---@return number
    lt = function(name, labels, value)
      assert.is_number(value)

      local new

      test.await.truthy(function()
        local metrics = get_metrics()
        new = metrics:get_value(name, labels)
        return new and new < value
      end, await_timeout, 0.1)

      return new
    end,

    ---@param name string
    ---@param labels? string[]
    ---@param value number
    ---@return number
    lte = function(name, labels, value)
      assert.is_number(value)

      local new

      test.await.truthy(function()
        local metrics = get_metrics()
        new = metrics:get_value(name, labels)
        return new and new <= value
      end, await_timeout, 0.1)

      return new
    end,
  }



  lazy_setup(function()
    conf = test.config()
    conf.trusted = { "0.0.0.0/0" }
    conf.unauthorized = "redirect-for-approval"

    conf.metrics = {
      interval = interval,
    }

    conf.network_tags = {
      default = "other",
      ["127.0.0.1"] = "localhost",
      ["10.0.0.0/8"] = "lan",
    }

    nginx = test.nginx(conf)

    nginx:start()

    metrics_client = nginx:add_client(test.client())
    metrics_client.reopen = true
    metrics_client.raise_on_connect_error = true
    metrics_client.assert_status.GET = { eq = 200 }

    client = nginx:add_client(test.client())
    api = nginx:add_client(test.client())
  end)

  before_each(function()
    client:reset()
    client.assert_status.POST = { eq = 201 }
    client.assert_status.GET = { eq = 200 }

    api:reset()
    api.assert_status.POST = { eq = 201 }
    api.assert_status.GET = { eq = 200 }
  end)

  lazy_teardown(function()
    nginx:stop()
  end)

  describe("doorbell_rules_total", function()
    local name = "doorbell_rules_total"

    it("measures the number of rule entities", function()
      local labels = { action = "allow", source = "api" }
      local before = await_metric.value(name, labels)

      client:post("/rules", {
        json = {
          action = "allow",
          addr = test.random_ipv4(),
          comment = "test for metrics",
        }
      })

      local id = assert.is_string(client.response.json.id)

      await_metric.gt(name, labels, before)

      client:delete("/rules/" .. id)

      await_metric.eq(name, labels, before)
    end)

    it("labels by rule.action", function()
      await_metric.exists(name)

      local metrics = get_metrics()

      for _, action in pairs(const.actions) do
        local list = metrics:get(name, { action  = action })
        assert.is_table(list)
        assert.is_true(#list > 0)
      end
    end)

    it("labels by rule.source", function()
      await_metric.exists(name)

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
      local before = await_metric.gte(name, labels, 1)

      for _ = 1, 100 do
        client:get("/ring")
      end

      await_metric.gte(name, labels, before + 100)
    end)
  end)

  describe("doorbell_requests_by_network", function()
    local name = "doorbell_requests_by_network"

    it("is a counter representing the number of requests from a network", function()
      local addrs = {
        localhost = "127.0.0.1",
        other = "1.2.3.4",
        lan = "10.0.11.12",
      }

      for tag, addr in pairs(addrs) do
        local labels = { network = tag }

        local path = "/" .. test.random_string(8)

        client:post("/rules", {
          json = {
            action = "allow",
            addr = addr,
            comment = "test for metrics",
            path = path,
          }
        })

        client:reset()
        client:add_x_forwarded_headers(addr, "GET", "http://foo.test" .. path)
        client:get("/ring")

        local before = await_metric.gte(name, labels, 1)

        for _ = 1, 100 do
          client:get("/ring")
        end

        await_metric.gte(name, labels, before + 100)
      end
    end)
  end)

  describe("doorbell_requests_by_route", function()
    local name = "doorbell_requests_by_route"

    it("measures the number of requests per route", function()
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

      local labels = { route = "ring" }
      local before = await_metric.gte(name, labels, 1)

      for _ = 1, 100 do
        client:get("/ring")
      end

      await_metric.gte(name, labels, before + 100)
    end)
  end)

  describe("doorbell_access_requests", function()
    local name = "doorbell_access_requests"

    it("measures pending access requests", function()
      local labels = { state = "pending" }

      client.assert_status.GET = { eq = 302 }

      local addr = test.random_ipv4()
      client:add_x_forwarded_headers(addr, "GET", "http://foo.test/")
      client:get("/ring")

      api:get("/access/pending")
      assert.is_table(api.response.json)
      assert.is_table(api.response.json.data)
      assert.is_table(api.response.json.data[1])

      local before = await_metric.gte(name, labels, 1)

      addr = test.random_ipv4()
      client:add_x_forwarded_headers(addr, "GET", "http://foo.test/")
      client:get("/ring")

      await_metric.gt(name, labels, before)

      api:get("/access/pending")
      assert.is_table(api.response.json)
      assert.is_table(api.response.json.data)

      for _, item in ipairs(api.response.json.data) do
        api:post("/access/intent", {
          json = {
            token = item.token,
            scope = "global",
            subject = "addr",
            ttl = 300,
            action = "deny",
          }
        })
      end

      await_metric.lt(name, labels, before)
    end)

    it("measures pre-approved access requests", function()
      local labels = { state = "pre-approved" }

      local addrs = {}

      local count = 3

      for i = 1, count do
        api:reset()

        local addr = test.random_ipv4()
        api.headers["x-forwarded-for"] = addr

        api:post("/access/pre-approval", {
          json = {
            subject = "addr",
            scope = "global",
            ttl = 300,
          },
        })

        addrs[i] = addr
      end

      local value = await_metric.gte(name, labels, count)

      for _, addr in ipairs(addrs) do
        client:reset()
        client:add_x_forwarded_headers(addr, "GET", "http://foo.test/")
        client:get("/ring")
      end

      await_metric.lte(name, labels, value - count)
    end)
  end)

  describe("nginx_timers", function()
    local name = "doorbell_nginx_timers"

    it("measures running/pending timers", function()
      await_metric.gte(name, { state = "pending" }, 1)
      await_metric.gte(name, { state = "running" }, 1)
    end)
  end)

  describe("nginx_worker_respawns", function()
    local name = "doorbell_nginx_worker_respawns"

    it("measures worker respawn counts", function()
      api:get("/nginx", { query = { block = 1 } })
      local info = api.response.json

      local agent_before = await_metric.value(name, { type = "agent" })
      local worker_before = await_metric.value(name, { type = "worker" })

      assert(signal.kill(info.agent.pid, 9))
      await_metric.gt(name, { type = "agent" }, agent_before)

      assert(signal.kill(info.workers[1].pid, 9))
      await_metric.gt(name, { type = "worker" }, worker_before)
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
