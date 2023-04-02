local config = require "doorbell.config"

describe("doorbell.config", function()
  describe("replace_env()", function()
    local env

    local function getenv(s)
      return env[s]
    end

    local getenv_original

    setup(function()
      getenv_original = config._set_getenv(getenv)
    end)

    teardown(function()
      config._set_getenv(getenv_original)
    end)

    before_each(function()
      env = {}
    end)

    it("replaces ${VAR} strings", function()
      env.TEST = "foo"
      local conf = config._replace_env({ test = "${TEST}" })
      assert.same({ test = "foo" }, conf)
    end)

    it("replaces ${VAR} mid-string", function()
      env.TEST = "foo"
      local conf = config._replace_env({ test = "((${TEST}))" })
      assert.same({ test = "((foo))" }, conf)
    end)

    it("handles whitespace (`${ MY_VAR }`)", function()
      env.TEST = "foo"
      local conf = config._replace_env({ test = "${  TEST }" })
      assert.same({ test = "foo" }, conf)
    end)

    it("replaces nested references", function()
      env.TEST = "foo"
      env.NESTED = "bar"
      local conf = config._replace_env(
        {
          test = "${TEST}",
          nested = {
            key = "value: ${NESTED}",
          },
          array = {
            "${TEST}",
            "${NESTED}",
          }
        }
      )

      assert.same(
        {
          test = "foo",
          nested = {
            key = "value: bar",
          },
          array = {
            "foo",
            "bar",
          }
        },
        conf
      )
    end)

    it("throws an error when it encounters an undefined env var", function()
      assert.error_matches(
        function() return config._replace_env({ test = "${UNDEFINED}" }) end,
        "UNDEFINED"
      )
    end)
  end)
end)
