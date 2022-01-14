---local rules = require "doorbell.rules"
local manager = require "doorbell.rules.manager"
local matcher = require "doorbell.rules.matcher"

describe("matching", function()
  local req
  local match

  local function add(rule_list)
    manager.reset()
    for _, r in ipairs(rule_list) do
      r.source = "user"
      r.action = r.action or "deny"

      manager.add(r, true, true)
    end
    match = matcher.new(manager.list())
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
