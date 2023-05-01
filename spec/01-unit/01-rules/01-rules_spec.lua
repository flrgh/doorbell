local rules = require "doorbell.rules"

describe("doorbell.rules", function()
  describe("new()", function()
    local new = rules.new

    local validation = {
      {
        desc = "ttl cannot be negative",
        input = {
          ttl = -1,
        },
        expect = "property ttl validation failed",
      },

      {
        desc = "ttl cannot be 0",
        input = {
          ttl = 0,
        },
        expect = "property ttl validation failed",
      },

      {
        desc = "ttl and expires are mutually-exclusive",
        input = {
          ttl = 10,
          expires = ngx.now() + 10,
        },
        expect = "",
        --expect = "only one of `ttl` and `expires` allowed",
      },

      {
        desc = "expires must be > ngx.now()",
        input = {
          expires = ngx.now() - 1,
        },
        expect = "",
        --expect = "property expires validation failed",
      },

      {
        desc = "expires cannot be negative",
        input = {
          expires = -1,
        },
        expect = "property expires validation failed",
      },

      {
        desc = "at least one condition is required",
        input = { action = "allow", source = "api" },
        expect = "",
        --expect = "at least one of .* required",
        fill_required_fields = false,
      },

      {
        desc = "action is required",
        input = { source = "api", ua = "" },
        expect = "property action is required",
        fill_required_fields = false,
      },

      {
        desc = "action cannot be empty",
        input = { action = "" },
        expect = "property action validation failed",
      },

      {
        desc = "source is required",
        input = { action = "allow", ua = "" },
        expect = "property source is required",
        fill_required_fields = false,
      },

      {
        desc = "source cannot be empty",
        input = { source = "" },
        expect = "property source validation failed",
      },

      {
        desc = "expires must be a number",
        input = { expires = false },
        expect = "property expires validation failed",
        plain  = true,
      },

      {
        desc = "ttl must be a number",
        input = { ttl = false },
        expect = "property ttl validation failed",
        plain  = true,
      },

      {
        desc = "addr must be a string",
        input = { addr = false },
        expect = "property addr validation failed",
        plain  = true,
      },

      {
        desc = "cidr must be a string",
        input = { cidr = false },
        expect = "property cidr validation failed",
        plain  = true,
      },

      {
        desc = "path must be a string",
        input = { path = false },
        expect = "property path validation failed",
        plain  = true,
      },

      {
        desc = "host must be a string",
        input = { host = false },
        expect = "property host validation failed",
        plain  = true,
      },

      {
        desc = "method must be a string",
        input = { method = false },
        expect = "property method validation failed",
        plain  = true,
      },

      {
        desc = "ua must be a string",
        input = { ua = false },
        expect = "property ua validation failed",
        plain  = true,
      },

      {
        desc = "country must be a string",
        input = { country = false },
        expect = "property country validation failed",
        plain  = true,
      },

      {
        desc = "deny_action must be a string",
        input = { deny_action = false },
        expect = "property deny_action validation failed",
        plain  = true,
      },

      {
        desc = "terminate must be a boolean",
        input = { terminate = "False" },
        expect = "property terminate validation failed",
        plain  = true,
      },

      {
        desc = "action must be one of deny/allow",
        input = { action = "nope" },
        expect = "property action validation failed",
        plain = true,
      },

      {
        desc = "source must be one of config/user/ota/api",
        input = { source = "nope" },
        expect = "property source validation failed",
        plain = true,
      },

      {
        desc = "deny_action must be one of exit/tarpit",
        input = { deny_action = "nope" },
        expect = "property deny_action validation failed",
        plain = true,
      },

      {
        desc = "deny_action is only allowed when action == `deny`",
        input = { action = "allow", deny_action = "tarpit" },
        expect = "",
        --expect = "`deny_action` cannot be used when `action` is 'allow'",
        plain = true,
      },

      {
        desc = "country must be a valid country code",
        input = { action = "allow", country = "XX" },
        expect = "property country validation failed",
        plain = true,
      },

      {
        desc = "asn must be a number",
        input = { asn = "NOPE" },
        expect = "property asn validation failed",
        plain = true,
      },

      {
        desc = "asn must be >= 0",
        input = { asn = -1 },
        expect = "property asn validation failed",
        plain = true,
      },

      {
        desc = "org must be a string",
        input = { org = false },
        expect = "property org validation failed",
        plain = true,
      },
    }

    for _, case in ipairs(validation) do
      it("validation: " .. case.desc, function()
        if case.fill_required_fields ~= false then
          if case.input.action == nil then
            case.input.action = "allow"
          end

          if case.input.source == nil then
            case.input.source = "api"
          end

          if rules.count_conditions(case.input) == 0 then
            case.input.ua = "test"
          end
        end

        local ok, err = new(case.input)
        assert.falsy(ok)
        assert.is_string(err)
        assert.matches(case.expect, err, 1, case.plain)
      end)
    end

    it("auto-generates the `conditions` field", function()
      local rule, err = new { ua = "test", addr = "1.2.3.4", path = "/test", action = "deny", source = "config" }
      assert.is_nil(err)
      assert.equals(3, rule.conditions)
    end)

    it("auto-generates the `created` field", function()
      local rule, err = new { ua = "test", action = "deny", source = "config" }
      assert.is_nil(err)
      assert.near(ngx.now(), rule.created, 1)
    end)

    it("auto-generates the `expires` field from ttl if given", function()
      local rule, err = new { ttl = 10, ua = "test", action = "deny", source = "config" }
      assert.is_nil(err)
      assert.near(ngx.now() + 10, rule.expires, 1)
    end)

    it("expires defaults to 0/never expires", function()
      local rule, err = new { ua = "test", action = "deny", source = "config" }
      assert.is_nil(err)
      assert.equals(0, rule.expires)
    end)

    it("auto-generates the `hash` field based on rule conditions", function()
      local rule, err = new { ua = "test", action = "deny", source = "config" }
      assert.is_nil(err)
      assert.same("8e195d0137c229447f423ffd83a1858b", rule.hash)

      local other = new { ua = "test", action = "allow", source = "user"}
      assert.equals(rule.hash, other.hash)

      other = new { ua = "test", path = "/foo", action = "allow", source = "user"}
      assert.not_equals(rule.hash, other.hash)

      other = new { ua = "notest", action = "allow", source = "user"}
      assert.not_equals(rule.hash, other.hash)
    end)

    it("deny_action defaults to `exit`", function()
      local rule, err = new { ua = "test", action = "deny", source = "config" }
      assert.is_nil(err)
      assert.equals("exit", rule.deny_action)
    end)
  end)

  describe("rule object", function()
    local new = rules.new

    describe("expired()", function()
      local rule

      before_each(function()
        rule = new { ua = "test", action = "deny", source = "config" }
      end)

      it("returns true if a rule is expired", function()
        rule.expires = ngx.now() - 5
        assert.truthy(rule:expired())
      end)

      it("returns false if a rule is not expired", function()
        rule.expires = ngx.now() + 5
        assert.falsy(rule:expired())
      end)

      it("returns the remaining ttl", function()
        rule.expires = ngx.now() + 5
        local exp, ttl = rule:expired()
        assert.falsy(exp)
        assert.near(5, ttl, 1)

        rule.expires = ngx.now() - 5
        exp, ttl = rule:expired()
        assert.truthy(exp)
        assert.near(-5, ttl, 1)
      end)

      it("can use a caller-supplied timestamp", function()
        local exp, ttl
        local now = ngx.now()

        rule.expires = now - 5
        exp, ttl = rule:expired(now - 15)
        assert.falsy(exp)
        assert.near(10, ttl, 1)

        rule.expires = now + 5
        exp, ttl = rule:expired(now + 15)
        assert.truthy(exp)
        assert.near(-10, ttl, 1)
      end)
    end)

    describe("remaining_ttl()", function()
      local rule

      before_each(function()
        rule = new { ua = "test", action = "deny", source = "config" }
      end)

      it("returns the ttl for a rule", function()
        rule.expires = ngx.now() + 5
        assert.near(5, rule:remaining_ttl(), 1)

        rule.expires = ngx.now() - 5
        assert.near(-5, rule:remaining_ttl(), 1)
      end)

      it("can use a caller-supplied timestamp", function()
        rule.expires = ngx.now() + 5
        assert.near(-5, rule:remaining_ttl(ngx.now() + 10), 1)

        rule.expires = ngx.now() - 5
        assert.near(5, rule:remaining_ttl(ngx.now() - 10), 1)
      end)

      it("returns -1 when ttl is >= 0 or < 1", function()
        local now = ngx.now()
        rule.expires = now + 10
        assert.equals(-1, rule:remaining_ttl(now + 9.99))
      end)
    end)
  end)

  describe("rule sorting", function()
    it("terminate = true is the highest priority", function()
      local r = {
        { terminate = false, action = "allow", conditions = 3, created = 1 },
        { terminate = true,  action = "allow", conditions = 3, created = 1 },
      }
      table.sort(r, rules.compare)

      assert.same(
        {
          { terminate = true,  action = "allow", conditions = 3, created = 1 },
          { terminate = false, action = "allow", conditions = 3, created = 1 },
        },
        r
      )
    end)

    it("deny > allow", function()
      local r = {
        { terminate = false, action = "allow", conditions = 3, created = 1 },
        { terminate = false, action = "deny",  conditions = 3, created = 1 },
      }
      table.sort(r, rules.compare)

      assert.same(
        {
          { terminate = false, action = "deny",  conditions = 3, created = 1 },
          { terminate = false, action = "allow", conditions = 3, created = 1 },
        },
        r
      )
    end)

    it("more conditions > fewer conditions", function()
      local r = {
        { terminate = false, action = "deny", conditions = 1, created = 1 },
        { terminate = false, action = "deny", conditions = 2, created = 1 },
      }
      table.sort(r, rules.compare)

      assert.same(
        {
          { terminate = false, action = "deny", conditions = 2, created = 1 },
          { terminate = false, action = "deny", conditions = 1, created = 1 },
        },
        r
      )
    end)

    it("newer creation time breaks all other ties", function()
      local r = {
        { terminate = false, action = "deny", conditions = 3, created = 10 },
        { terminate = false, action = "deny", conditions = 3, created = 11 },
      }
      table.sort(r, rules.compare)

      assert.same(
        {
          { terminate = false, action = "deny", conditions = 3, created = 11 },
          { terminate = false, action = "deny", conditions = 3, created = 10 },
        },
        r
      )
    end)

    it("all together", function()
      local r = {
        { terminate = false, action = "deny",  conditions = 3, created = 1 },
        { terminate = true,  action = "allow", conditions = 3, created = 5 },
        { terminate = true,  action = "deny",  conditions = 3, created = 4 },
        { terminate = false, action = "deny",  conditions = 1, created = 3 },
        { terminate = false, action = "allow", conditions = 3, created = 1 },
        { terminate = false, action = "deny",  conditions = 3, created = 3 },
        { terminate = true,  action = "allow", conditions = 1, created = 1 },
        { terminate = false, action = "deny",  conditions = 3, created = 2 },
      }
      table.sort(r, rules.compare)

      assert.same(
        {
          { terminate = true,  action = "deny",  conditions = 3, created = 4 },
          { terminate = true,  action = "allow", conditions = 3, created = 5 },
          { terminate = true,  action = "allow", conditions = 1, created = 1 },
          { terminate = false, action = "deny",  conditions = 3, created = 3 },
          { terminate = false, action = "deny",  conditions = 3, created = 2 },
          { terminate = false, action = "deny",  conditions = 3, created = 1 },
          { terminate = false, action = "allow", conditions = 3, created = 1 },
          { terminate = false, action = "deny",  conditions = 1, created = 3 },
        },
        r
      )
    end)
  end)
end)
