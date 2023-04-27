local config = require "doorbell.config"
local json = require("cjson").encode
local fs = require "spec.testing.fs"
local env = require "doorbell.env"

describe("doorbell.config", function()
  env.init()

  describe("init()", function()
    local tmp

    before_each(function()
      tmp = fs.tmpdir()
      env.CONFIG_STRING = nil
      env.CONFIG = nil
    end)

    after_each(function()
      if tmp then
        fs.rmdir(tmp, true)
      end
    end)

    it("reads from DOORBELL_CONFIG_STRING", function()
      env.CONFIG_STRING = json {
        base_url = "http://my-host",
        cache_size = 1234,
        runtime_path = tmp,
      }

      config.init()

      assert.same("http://my-host", config.base_url)
      assert.same("my-host", config.host)
      assert.same(1234, config.cache_size)
      assert.same(tmp, config.runtime_path)
    end)

    it("reads from DOORBELL_CONFIG", function()
      fs.write_json_file(tmp .. "/config.json", {
        base_url = "http://from-file/",
        cache_size = 4321,
      })

      env.CONFIG = tmp .. "/config.json"

      config.init()

      assert.same("http://from-file/", config.base_url)
      assert.same(4321, config.cache_size)
    end)

    describe(".base_url", function()
      it("must be a string", function()
        env.CONFIG_STRING = json {
          base_url = 123,
        }

        assert.error_matches(function()
          config.init()
        end, [[property base_url validation failed: wrong type: expected string, got number]], nil, true)
      end)

      it("must be able to be parsed", function()
        env.CONFIG_STRING = json {
          base_url = "-n30",
        }

        assert.error_matches(function()
          config.init()
        end, [[failed to parse hostname from base_url]])
      end)

      it("is used to set config.host", function()
        env.CONFIG_STRING = json {
          base_url = "https://my-hostname/",
        }
        config.init()
        assert.same("my-hostname", config.host)
      end)
    end)

    describe(".asset_path", function()
      it("must be a string", function()
        env.CONFIG_STRING = json {
          base_url = "http://localhost",
          asset_path = 123,
        }

        assert.error_matches(function()
          config.init()
        end, [[property asset_path validation failed: wrong type: expected string, got number]], nil, true)
      end)
    end)

    describe(".log_path", function()
      it("must be a string", function()
        env.CONFIG_STRING = json {
          base_url = "http://localhost",
          log_path = 123,
        }

        assert.error_matches(function()
          config.init()
        end, [[property log_path validation failed: wrong type: expected string, got number]], nil, true)
      end)
    end)

    describe(".runtime_path", function()
      it("must be a string", function()
        env.CONFIG_STRING = json {
          base_url = "http://localhost",
          runtime_path = 123,
        }

        assert.error_matches(function()
          config.init()
        end, [[property runtime_path validation failed: wrong type: expected string, got number]], nil, true)
      end)
    end)

    describe(".allow", function()
      it("must be a table", function()
        env.CONFIG_STRING = json {
          base_url = "http://localhost",
          allow = 123,
        }

        assert.error_matches(function()
          config.init()
        end, [[property allow validation failed: wrong type: expected array, got number]], nil, true)
      end)
    end)

    describe(".deny", function()
      it("must be a table", function()
        env.CONFIG_STRING = json {
          base_url = "http://localhost",
          deny = 123,
        }

        assert.error_matches(function()
          config.init()
        end, [[property deny validation failed: wrong type: expected array, got number]], nil, true)
      end)
    end)

    describe(".trusted", function()
      it("must be a table", function()
        env.CONFIG_STRING = json {
          base_url = "http://localhost",
          trusted = 123,
        }

        assert.error_matches(function()
          config.init()
        end, [[property trusted validation failed: wrong type: expected array, got number]], nil, true)
      end)

      it("can be sourced from DOORBELL_TRUSTED", function()
        env.CONFIG_STRING = json {
          base_url = "http://localhost",
        }

        env.TRUSTED = "10.11.0.0/16,  10.20.30.0/24"

        config.init()
        assert.same({ "10.11.0.0/16", "10.20.30.0/24" }, config.trusted)
      end)
    end)

    describe(".metrics", function()
      it("must be a table", function()
        env.CONFIG_STRING = json {
          base_url = "http://localhost",
          metrics = 123,
        }

        assert.error_matches(function()
          config.init()
        end, [[property metrics validation failed: wrong type: expected object, got number]], nil, true)
      end)
    end)

    describe(".ota", function()
      it("must be a table", function()
        env.CONFIG_STRING = json {
          base_url = "http://localhost",
          ota = 123,
        }

        assert.error_matches(function()
          config.init()
        end, [[property ota validation failed: wrong type: expected object, got number]], nil, true)
      end)
    end)

    describe(".notify", function()
      it("must be a table", function()
        env.CONFIG_STRING = json {
          base_url = "http://localhost",
          notify = 123,
        }

        assert.error_matches(function()
          config.init()
        end, [[property notify validation failed: wrong type: expected object, got number]], nil, true)
      end)
    end)
  end)
end)
