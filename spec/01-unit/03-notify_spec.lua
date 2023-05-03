local notify = require "doorbell.notify"

describe("doorbell.notify", function()
  describe("schema", function()
    local schema = require "doorbell.schema"
    local validate = schema.config.fields.notify.validate

    local cases = {
      {
        desc = "accepts valid input (all empty)",
        valid = true,
        input = {
          strategy = nil,
          config   = nil,
          periods  = nil,
        },
      },

      {
        desc = "accepts valid input (empty config)",
        valid = true,
        input = {
          strategy = "spec.testing.mock-notify",
          config   = nil,
          periods  = nil,
        },
      },

      {
        desc = "accepts valid input (empty periods)",
        valid = true,
        input = {
          strategy = "spec.testing.mock-notify",
          config   = {},
          periods  = nil,
        },
      },

      {
        desc = "accepts valid input (arbitrary config)",
        valid = true,
        input = {
          strategy = "spec.testing.mock-notify",
          config   = {
            yes = "no",
            table = { a = 1, b = 2 },
          },
          periods  = nil,
        },
      },

      {
        desc = "accepts valid input (periods)",
        valid = true,
        input = {
          strategy = "spec.testing.mock-notify",
          config   = {
            yes = "no",
            table = { a = 1, b = 2 },
          },
          periods  = {
            { from = nil, to = 1   },
            { from = 1,   to = nil },
            { from = 1,   to = 0   },
          },
        },
      },

      {
        desc = "rejects invalid strategy (empty string)",
        valid = false,
        field = "strategy",
        input = {
          strategy = "",
        },
      },

      {
        desc = "rejects invalid strategy (bad type)",
        valid = false,
        field = "strategy",
        input = {
          strategy = -1,
        },
      },

      {
        desc = "rejects invalid config (bad type)",
        valid = false,
        field = "config",
        input = {
          strategy = "spec.testing.mock-notify",
          config = -1,
        },
      },

      {
        desc = "rejects invalid periods (bad type)",
        valid = false,
        field = "periods",
        input = {
          strategy = "spec.testing.mock-notify",
          periods = -1,
        },
      },

      {
        desc = "rejects invalid periods (empty array)",
        valid = false,
        field = "periods",
        input = {
          strategy = "spec.testing.mock-notify",
          periods = {},
        },
      },

      {
        desc = "rejects invalid periods (required fields)",
        valid = false,
        field = "periods",
        input = {
          strategy = "spec.testing.mock-notify",
          periods = {
            { },
          },
        },
      },

      {
        desc = "rejects invalid periods (extraneous fields)",
        valid = false,
        field = "periods",
        input = {
          strategy = "spec.testing.mock-notify",
          periods = {
            {
              to = 1,
              from = 3,
              extra = "nope",
            },
          },
        },
      },

      {
        desc = "rejects extraneous fields",
        valid = false,
        input = {
          extra = 123,
          strategy = "spec.testing.mock-notify",
          periods = {
            {
              to = 1,
              from = 3,
            },
          },
        },
      },


    }

    for _, case in ipairs(cases) do
      it(case.desc, function()
        local ok, err = validate(case.input)
        if case.valid then
          assert.is_nil(err)
          assert.truthy(ok)

        else
          assert.is_string(err)
          assert.is_nil(ok)
          if case.field then
            local e = string.format("property %s validation failed", case.field)
            assert.matches(e, err, nil, true)
          end
        end
      end)
    end
  end)

  describe("in_notify_period()", function()
    local in_notify_period = notify.in_notify_period

    it("returns true if no global notification periods are defined", function()
      notify.init({
        notify = {
          strategy = "spec.testing.mock-notify",
          config   = {},
          periods  = nil,
        }
      })

      assert.is_true(in_notify_period(nil, 0))
      assert.is_true(in_notify_period(nil, 23))
    end)

    it("returns true when inside a given time period", function()
      local periods = {
        { from = 0, to = 5 },
      }

      assert.is_true(in_notify_period(periods, 4))
    end)

    it("returns false when outside of a given time period", function()
      local periods = {
        { from = 0, to = 5 },
      }

      assert.is_false(in_notify_period(periods, 10))
    end)

    it("requires only one period to match", function()
      local periods = {
        { from = 0, to = 5 },
        { from = 9, to = 11 },
        { from = 14, to = 19},
      }

      assert.is_true(in_notify_period(periods, 10))
    end)

    it("when 'to' is 0, there is no upper bound", function()
      local periods = {
        { from = 18, to = 0 },
      }

      assert.is_true(in_notify_period(periods, 18))
      assert.is_true(in_notify_period(periods, 23))
    end)

    it("'to' defaults to 0", function()
      local periods = {
        { from = 18, to = nil },
      }

      assert.is_true(in_notify_period(periods, 19))
    end)

    it("'to' is exclusive", function()
      local periods = {
        { from = 1, to = 19 },
      }

      assert.is_true(in_notify_period(periods, 18))
      assert.is_false(in_notify_period(periods, 19))
    end)

    it("when 'from' is 0, there is no lower bound", function()
      local periods = {
        { from = 0, to = 11 },
      }

      assert.is_true(in_notify_period(periods, 0))
      assert.is_true(in_notify_period(periods, 1))
    end)

    it("'from' defaults to 0", function()
      local periods = {
        { from = nil, to = 10 },
      }

      assert.is_true(in_notify_period(periods, 0))
      assert.is_true(in_notify_period(periods, 1))
    end)

    it("'from' is inclusive", function()
      local periods = {
        { from = 1, to = 5 },
      }

      assert.is_false(in_notify_period(periods, 0))
      assert.is_true(in_notify_period(periods, 1))
    end)

    it("throws an error for invalid 'hour' input", function()
      local periods = { { from = 1, to = 23 } }

      assert.has_error(function()
        in_notify_period(periods, "foo")
      end)

      assert.has_error(function()
        in_notify_period(periods, {})
      end)

      assert.has_error(function()
        in_notify_period(periods, -1)
      end)

      assert.has_error(function()
        in_notify_period(periods, 24)
      end)
    end)
  end)
end)
