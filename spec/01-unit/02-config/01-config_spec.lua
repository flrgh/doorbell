local config = require "doorbell.config"
local json = require("cjson").encode
local fs = require "spec.testing.fs"

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

  describe("init()", function()
    local env
    local tmp

    lazy_teardown(function()
      config._set_getenv(os.getenv)
    end)

    before_each(function()
      tmp = fs.tmpdir()

      env = {}
      config._set_getenv(function(var)
        return env[var]
      end)
    end)

    after_each(function()
      if tmp then
        fs.rmdir(tmp, true)
      end
    end)

    it("reads from DOORBELL_CONFIG_STRING", function()
      env.DOORBELL_CONFIG_STRING = json {
        base_url = "http://localhost/",
        cache_size = 1234,
        runtime_dir = tmp,
      }

      config.init()

      assert.same("http://localhost/", config.base_url)
      assert.same(1234, config.cache_size)
      assert.same(tmp, config.runtime_dir)
    end)

    it("reads from DOORBELL_CONFIG", function()
      fs.write_json_file(tmp .. "/config.json", {
        base_url = "http://from-file/",
        cache_size = 4321,
      })

      env.DOORBELL_CONFIG = tmp .. "/config.json"

      config.init()

      assert.same("http://from-file/", config.base_url)
      assert.same(4321, config.cache_size)
    end)

    describe(".base_url", function()
      it("is required", function()
        assert.error_matches(function()
          config.init()
        end, "base_url is required")
      end)

      it("must be a string", function()
        env.DOORBELL_CONFIG_STRING = json {
          base_url = 123,
        }

        assert.error_matches(function()
          config.init()
        end, [[invalid value for base_url ("123"): expected: string, got: number]], nil, true)
      end)

      it("must be able to be parsed", function()
        env.DOORBELL_CONFIG_STRING = json {
          base_url = "-n30",
        }

        assert.error_matches(function()
          config.init()
        end, [[failed to parse hostname from base_url]])
      end)

      it("is used to set config.host", function()
        env.DOORBELL_CONFIG_STRING = json {
          base_url = "https://my-hostname/",
        }
        config.init()
        assert.same("my-hostname", config.host)
      end)
    end)

    describe(".asset_dir", function()
      it("must be a string", function()
        env.DOORBELL_CONFIG_STRING = json {
          base_url = "http://localhost",
          asset_dir = 123,
        }

        assert.error_matches(function()
          config.init()
        end, [[invalid value for asset_dir ("123"): expected: string, got: number]], nil, true)
      end)

      it("must be a valid directory", function()
        env.DOORBELL_CONFIG_STRING = json {
          base_url = "http://localhost",
          asset_dir = tmp .. "/i-dont-exist",
        }

        assert.error_matches(function()
          config.init()
        end, [[does not exist]])

        fs.write_json_file(tmp .. "/test.json", {})

        env.DOORBELL_CONFIG_STRING = json {
          base_url = "http://localhost",
          asset_dir = tmp .. "/test.json",
        }

        assert.error_matches(function()
          config.init()
        end, [[is not a directory]])
      end)
    end)

    describe(".log_dir", function()
      it("must be a string", function()
        env.DOORBELL_CONFIG_STRING = json {
          base_url = "http://localhost",
          log_dir = 123,
        }

        assert.error_matches(function()
          config.init()
        end, [[invalid value for log_dir ("123"): expected: string, got: number]], nil, true)
      end)

      it("must be a valid directory", function()
        env.DOORBELL_CONFIG_STRING = json {
          base_url = "http://localhost",
          log_dir = tmp .. "/i-dont-exist",
        }

        assert.error_matches(function()
          config.init()
        end, [[does not exist]])

        fs.write_json_file(tmp .. "/test.json", {})

        env.DOORBELL_CONFIG_STRING = json {
          base_url = "http://localhost",
          log_dir = tmp .. "/test.json",
        }

        assert.error_matches(function()
          config.init()
        end, [[is not a directory]])
      end)
    end)

    describe(".runtime_dir", function()
      it("must be a string", function()
        env.DOORBELL_CONFIG_STRING = json {
          base_url = "http://localhost",
          runtime_dir = 123,
        }

        assert.error_matches(function()
          config.init()
        end, [[invalid value for runtime_dir ("123"): expected: string, got: number]], nil, true)
      end)

      it("must be a valid directory", function()
        env.DOORBELL_CONFIG_STRING = json {
          base_url = "http://localhost",
          runtime_dir = tmp .. "/i-dont-exist",
        }

        assert.error_matches(function()
          config.init()
        end, [[does not exist]])

        fs.write_json_file(tmp .. "/test.json", {})

        env.DOORBELL_CONFIG_STRING = json {
          base_url = "http://localhost",
          runtime_dir = tmp .. "/test.json",
        }

        assert.error_matches(function()
          config.init()
        end, [[is not a directory]])
      end)
    end)

    describe(".allow", function()
      it("must be a table", function()
        env.DOORBELL_CONFIG_STRING = json {
          base_url = "http://localhost",
          allow = 123,
        }

        assert.error_matches(function()
          config.init()
        end, [[invalid value for allow ("123"): expected: table, got: number]], nil, true)
      end)
    end)

    describe(".deny", function()
      it("must be a table", function()
        env.DOORBELL_CONFIG_STRING = json {
          base_url = "http://localhost",
          deny = 123,
        }

        assert.error_matches(function()
          config.init()
        end, [[invalid value for deny ("123"): expected: table, got: number]], nil, true)
      end)
    end)

    describe(".trusted", function()
      it("must be a table", function()
        env.DOORBELL_CONFIG_STRING = json {
          base_url = "http://localhost",
          trusted = 123,
        }

        assert.error_matches(function()
          config.init()
        end, [[invalid value for trusted ("123"): expected: table, got: number]], nil, true)
      end)

      it("can be sourced from DOORBELL_TRUSTED", function()
        env.DOORBELL_CONFIG_STRING = json {
          base_url = "http://localhost",
        }

        env.DOORBELL_TRUSTED = "10.11.0.0/16,  10.20.30.0/24"

        config.init()
        assert.same({ "10.11.0.0/16", "10.20.30.0/24" }, config.trusted)
      end)
    end)

    describe(".metrics", function()
      it("must be a table", function()
        env.DOORBELL_CONFIG_STRING = json {
          base_url = "http://localhost",
          metrics = 123,
        }

        assert.error_matches(function()
          config.init()
        end, [[invalid value for metrics ("123"): expected: table, got: number]], nil, true)
      end)
    end)

    describe(".ota", function()
      it("must be a table", function()
        env.DOORBELL_CONFIG_STRING = json {
          base_url = "http://localhost",
          ota = 123,
        }

        assert.error_matches(function()
          config.init()
        end, [[invalid value for ota ("123"): expected: table, got: number]], nil, true)
      end)
    end)

    describe(".notify", function()
      it("must be a table", function()
        env.DOORBELL_CONFIG_STRING = json {
          base_url = "http://localhost",
          notify = 123,
        }

        assert.error_matches(function()
          config.init()
        end, [[invalid value for notify ("123"): expected: table, got: number]], nil, true)
      end)
    end)
  end)
end)
