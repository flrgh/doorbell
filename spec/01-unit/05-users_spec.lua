local users = require "doorbell.users"

describe("doorbell.users", function()
  describe("validation", function()
    describe("telephone numbers", function()
      local validate = users.validate.tel

      it("allows extra formatting chars and whitespace", function()
        for _, tel in ipairs({
          "(123) 456 7890",
          "123 456 7890",
          "123-456-7890",
          "+1-123-456-7890",
        }) do
          assert.truthy(validate(tel), "expected " .. tel .. " to be valid")
        end
      end)

      it("normalizes to E.164 format", function()
        for _, tel in ipairs({
          "(123) 456 7890",
          "123 456 7890",
          "123-456-7890",
          "+1-123-456-7890",
        }) do
          local norm = assert.truthy(validate(tel), "expected " .. tel .. " to be valid")
          assert.equals("+11234567890", norm)
        end
      end)

      it("forbids non-digit inputs", function()
        assert.falsy(validate("123456abcd"))
      end)

      it("requires at least a 3 digit area code and 7 digit subscriber number", function()
        assert.truthy(validate("123 456 7890"))

        assert.falsy(validate("23 456 7890"))
        assert.falsy(validate( "3 456 7890"))
        assert.falsy(validate(  " 456 7890"))
        assert.falsy(validate(    "56 7890"))
        assert.falsy(validate(     "6 7890"))
        assert.falsy(validate(       "7890"))
        assert.falsy(validate(        "890"))
        assert.falsy(validate(         "90"))
        assert.falsy(validate(          "0"))
        assert.falsy(validate(           ""))
      end)

      it("country code is optional and defaults to US (1)", function()
        local tel = assert.truthy(validate("123 456 7890"))
        assert.equals("+11234567890", tel)

        tel = assert.truthy(validate("+999 123 456 7890"))
        assert.equals("+9991234567890", tel)
      end)
    end)
  end)
end)
