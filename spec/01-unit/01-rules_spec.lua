local rules = require "doorbell.rules"

describe("doorbell.rules", function()
  describe("new_rule", function()
    local new = rules._new_rule

    local validation = {
      {
        desc = "ttl cannot be negative",
        input = {
          ua = "test",
          ttl = -1,
        },
        expect = "`ttl` must be > 0",
      },

      {
        desc = "ttl and expires are mutually-exclusive",
        input = {
          ua = "test",
          ttl = 10,
          expires = ngx.now() + 10,
        },
        expect = "only one of `ttl` and `expires` allowed",
      },

      {
        desc = "expires must be > ngx.now()",
        input = {
          ua = "test",
          expires = ngx.now() - 1,
        },
        expect = "rule is already expired",
      },

      {
        desc = "expires cannot be negative",
        input = {
          ua = "test",
          expires = -1,
        },
        expect = "`expires` must be >= 0",
      },

      {
        desc = "at least one condition is required",
        input = {},
        expect = "at least one of .* required",
      },

      {
        desc = "action is required",
        input = {},
        expect = "`action` is required and cannot be empty",
      },

      {
        desc = "action cannot be empty",
        input = { action = "" },
        expect = "`action` cannot be empty",
      },

      {
        desc = "source is required",
        input = {},
        expect = "`source` is required and cannot be empty",
      },

      {
        desc = "source cannot be empty",
        input = { source = "" },
        expect = "`source` cannot be empty",
      },

      {
        desc = "expires must be a number",
        input = { expires = false },
        expect = "invalid `expires` (expected number, got: boolean)",
        plain  = true,
      },

      {
        desc = "ttl must be a number",
        input = { ttl = false },
        expect = "invalid `ttl` (expected number, got: boolean)",
        plain  = true,
      },

      {
        desc = "created must be a number",
        input = { created = false },
        expect = "invalid `created` (expected number, got: boolean)",
        plain  = true,
      },

      {
        desc = "created must be a number",
        input = { created = false },
        expect = "invalid `created` (expected number, got: boolean)",
        plain  = true,
      },

      {
        desc = "addr must be a string",
        input = { addr = false },
        expect = "invalid `addr` (expected string, got: boolean)",
        plain  = true,
      },

      {
        desc = "cidr must be a string",
        input = { cidr = false },
        expect = "invalid `cidr` (expected string, got: boolean)",
        plain  = true,
      },

      {
        desc = "path must be a string",
        input = { path = false },
        expect = "invalid `path` (expected string, got: boolean)",
        plain  = true,
      },

      {
        desc = "host must be a string",
        input = { host = false },
        expect = "invalid `host` (expected string, got: boolean)",
        plain  = true,
      },

      {
        desc = "method must be a string",
        input = { method = false },
        expect = "invalid `method` (expected string, got: boolean)",
        plain  = true,
      },

      {
        desc = "ua must be a string",
        input = { ua = false },
        expect = "invalid `ua` (expected string, got: boolean)",
        plain  = true,
      },

      {
        desc = "country must be a string",
        input = { country = false },
        expect = "invalid `country` (expected string, got: boolean)",
        plain  = true,
      },

      {
        desc = "deny_action must be a string",
        input = { deny_action = false },
        expect = "invalid `deny_action` (expected string, got: boolean)",
        plain  = true,
      },


      {
        desc = "terminate must be a boolean",
        input = { terminate = "False" },
        expect = "invalid `terminate` (expected boolean, got: string)",
        plain  = true,
      },

      {
        desc = "action must be one of deny/allow",
        input = { action = "nope" },
        expect = 'invalid `action` (expected: "allow"|"deny", got: "nope")',
        plain = true,
      },

      {
        desc = "source must be one of config/user",
        input = { source = "nope" },
        expect = 'invalid `source` (expected: "config"|"user", got: "nope")',
        plain = true,
      },

      {
        desc = "deny_action must be one of exit/tarpit",
        input = { deny_action = "nope" },
        expect = 'invalid `deny_action` (expected: "exit"|"tarpit", got: "nope")',
        plain = true,
      },

      {
        desc = "deny_action is only allowed when action == `deny`",
        input = { action = "allow", deny_action = "tarpit" },
        expect = "`deny_action` cannot be used when `action` is 'allow'",
        plain = true,
      },

    }

    for _, case in ipairs(validation) do
      it("validation: " .. case.desc, function()
        local ok, err = new(case.input)
        assert.is_nil(ok)
        assert.matches(case.expect, err, 1, case.plain)
      end)
    end

    it("auto-generates the `conditions` field", function()
      local rule, err = new { ua = "test", addr = "1.2.3.4", path = "/test", action = "deny", source = "config" }
      assert.is_nil(err)
      assert.equals(3, rule.conditions)
    end)

    it("auto-generates the `created` field if not supplied", function()
      local rule, err = new { ua = "test", action = "deny", source = "config" }
      assert.is_nil(err)
      assert.near(ngx.now(), rule.created, 1)

      local created = ngx.now() - 5
      rule, err = new { created = created, ua = "test", action = "deny", source = "config" }
      assert.is_nil(err)
      assert.equals(created, rule.created)
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
      assert.equals("c6327873a06d2806f4584678ff658a79", rule.hash)

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
    local new = rules._new_rule

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

    describe("ttl()", function()
      local rule

      before_each(function()
        rule = new { ua = "test", action = "deny", source = "config" }
      end)

      it("returns the ttl for a rule", function()
        rule.expires = ngx.now() + 5
        assert.near(5, rule:ttl(), 1)

        rule.expires = ngx.now() - 5
        assert.near(-5, rule:ttl(), 1)
      end)

      it("can use a caller-supplied timestamp", function()
        rule.expires = ngx.now() + 5
        assert.near(-5, rule:ttl(ngx.now() + 10), 1)

        rule.expires = ngx.now() - 5
        assert.near(5, rule:ttl(ngx.now() - 10), 1)
      end)

      it("returns -1 when ttl is >= 0 or < 1", function()
        local now = ngx.now()
        rule.expires = now + 10
        assert.equals(-1, rule:ttl(now + 9.99))
      end)
    end)
  end)

  describe("rule sorting", function()
    it("terminate = true is the highest priority", function()
      local r = {
        { terminate = false, action = "allow", conditions = 3, created = 1 },
        { terminate = true,  action = "allow", conditions = 3, created = 1 },
      }
      table.sort(r, rules._cmp_rule)

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
      table.sort(r, rules._cmp_rule)

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
      table.sort(r, rules._cmp_rule)

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
      table.sort(r, rules._cmp_rule)

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
      table.sort(r, rules._cmp_rule)

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

  describe("matching", function()
    local req
    local match

    local function add(rule_list)
      rules.reset()
      for _, r in ipairs(rule_list) do
        r.source = "user"
        r.action = r.action or "deny"

        rules.add(r)
      end
      match = rules._rebuild_matcher()
    end

    before_each(function()
      req = {
        addr    = "10.0.0.10",
        country = "US",
        method  = "GET",
        host    = "test.com",
        path    = "/wp-login.php",
        ua      = "user-agent",
      }
    end)

    it("matches requests", function()
      add {
        { comment = "a",   ua = "test",          created = 2     },
        { comment = "b", path = "/wp-login.php", created = 1     },
        { comment = "c", path = "/wp-login.php",  method = "GET" },
      }

      local rule = match(req)
      assert.equals("c", rule.comment)

      req.method = "POST"
      assert.equals("b", match(req).comment)

      req.ua = "test"
      assert.equals("a", match(req).comment)
    end)

    it("exits early when a rule with terminate=true has matched", function()
      add {
        { comment = "a",   ua = "test", host = "test.com", created = 10 },
        { comment = "b",   ua = "test", path = "/wp-login.php", created = 9},
        { comment = "c",   ua = "test", terminate = false },
      }

      req.ua = "test"
      assert.equals("a", match(req).comment)

      add {
        { comment = "a",   ua = "test", host = "test.com" },
        { comment = "b",   ua = "test", path = "/wp-login.php" },
        { comment = "c",   ua = "test", terminate = true },
      }

      assert.equals("c", match(req).comment)
    end)

    it("can match regex paths and user-agents", function()
      add {
        { comment = "a", ua = "~foo[0-9]+$" },
        { comment = "b", path = "~/test/.+" }
      }

      req.ua = "foo99"
      assert.equals("a", match(req).comment)

      req.ua = "foo123nope"
      assert.is_nil(match(req))

      req.ua = "no"
      req.path = "/test/test"
      assert.equals("b", match(req).comment)

      req.path = "/test/"
      assert.is_nil(match(req))
    end)

    it("plain string matches take precedence over regex when the number of conditions is equal", function()
      add {
        { comment = "a", path = "~/test/.+", host = "test", created = 20 },
        { comment = "b", path = "/test/foo", host = "test", created = 10 },
      }

      req.host = "test"
      req.path = "/test/foo"
      assert.equals("b", match(req).comment)


      -- ...but not when there exists a rule with a higher count of conditions.
      add {
        { comment = "a", path = "~/test/.+", host = "test", created = 20 },
        { comment = "b", path = "/test/foo", host = "test", created = 10 },
        { comment = "c", path = "no", host = "no", ua = "no" },
      }

      assert.equals("a", match(req).comment)
    end)

    it("can match based on CIDR", function()
      add {
        { comment = "a", cidr = "10.0.0.0/24" },
      }

      req.addr = "10.0.0.9"
      assert.equals("a", match(req).comment)

      req.addr = "10.0.1.9"
      assert.is_nil(match(req))
    end)
  end)
end)
