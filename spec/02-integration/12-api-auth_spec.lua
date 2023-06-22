local test = require "spec.testing"
local cjson = require "cjson"
local mu = require "spec.testing.mock-upstream"
local jwt = require "resty.jwt"
local util = require "doorbell.util"
local const = require "doorbell.constants"

local BASE_URL = "http://127.0.0.1:" .. test.constants.MOCK_UPSTREAM_PORT .. "/"

local USER = "my-test-user"
local SUB = "provider|my-test-user-sub"
local EMAIL = "my-test-user@email.test"
local API_KEY = test.random_string(36)

local function new_openid_conf()
  return {
    authorization_endpoint = BASE_URL .. "authorize",
    claims_supported = {
      "aud",
      "auth_time",
      "created_at",
      "email",
      "email_verified",
      "exp",
      "family_name",
      "given_name",
      "iat",
      "identities",
      "iss",
      "name",
      "nickname",
      "phone_number",
      "picture",
      "sub",
    },
    code_challenge_methods_supported = {
      "S256",
      "plain",
    },
    device_authorization_endpoint = BASE_URL .. "oauth/device/code",
    id_token_signing_alg_values_supported = {
      "HS256",
      "RS256",
    },
    issuer                          = BASE_URL,
    jwks_uri                        = BASE_URL .. ".well-known/jwks.json",
    mfa_challenge_endpoint          = BASE_URL .. "mfa/challenge",
    registration_endpoint           = BASE_URL .. "oidc/register",
    request_parameter_supported     = false,
    request_uri_parameter_supported = false,
    response_modes_supported = {
      "query",
      "fragment",
      "form_post",
    },
    response_types_supported = {
      "code",
      "token",
      "id_token",
      "code token",
      "code id_token",
      "token id_token",
      "code token id_token",
    },
    revocation_endpoint = BASE_URL .. "oauth/revoke",
    scopes_supported = {
      "openid",
      "profile",
      "offline_access",
      "name",
      "given_name",
      "family_name",
      "nickname",
      "email",
      "email_verified",
      "picture",
      "created_at",
      "identities",
      "phone",
      "address",
    },
    subject_types_supported = {
      "public",
    },
    token_endpoint = BASE_URL .. "oauth/token",
    token_endpoint_auth_methods_supported = {
      "client_secret_basic",
      "client_secret_post",
      "private_key_jwt",
    },
    token_endpoint_auth_signing_alg_values_supported = {
      "RS256",
      "RS384",
      "PS256",
    },
    userinfo_endpoint = BASE_URL .. "userinfo",
  }
end


local JWKS = test.fs.file_contents("./spec/fixtures/auth.jwks.json")
local PRIVATE_KEY  = test.fs.file_contents("./spec/fixtures/auth.private.pem")

local function new_jwks()
  return cjson.decode(JWKS)
end

local function setup_mocks()
  mu.mock.prepare({
    path = "/.well-known/openid-configuration",
    method = "GET",
    once = true,
    response = {
      status = 200,
      headers = { ["Content-Type"] = "application/json" },
      json = new_openid_conf(),
    },
  })

  mu.mock.prepare({
    path = "/.well-known/jwks.json",
    method = "GET",
    once = true,
    response = {
      status = 200,
      json = new_jwks(),
    }
  })
end

local function setup_userinfo(info)
  mu.mock.prepare({
    path = "/userinfo",
    method = "GET",
    once = true,
    response = {
      status = 200,
      json = info,
    },
  })
end



describe("API auth", function()
  for _, trusted_client_ip in ipairs({ true, false }) do
    local label = trusted_client_ip
              and "(trusted client IP)"
               or "(untrusted client IP)"

    describe(label, function()

      ---@type spec.testing.client
      local client

      ---@type spec.testing.nginx
      local nginx

      ---@type doorbell.config
      local conf

      lazy_setup(function()
        conf = test.config()
        conf.auth = {
          openid_issuer = BASE_URL,
          users = {
            {
              name = USER,
              identifiers = {
                { sub = SUB },
                { email = EMAIL },
                { apikey = util.sha256(API_KEY) },
              },
            },
          },
        }

        if trusted_client_ip then
          conf.trusted = { "0.0.0.0/0" }
        else
          conf.trusted = { "4.3.2.1/32" }
        end

        nginx = test.nginx(conf)
        nginx:conf_test()
        nginx:start()

        client = test.client()
        nginx:add_client(client)

        client.raise_on_connect_error = true
        client.reopen = true
      end)

      lazy_teardown(function()
        client:close()
        nginx:stop()
      end)

      before_each(function()
        client:reset()
        mu.mock.reset()
      end)

      ---@param res spec.testing.client.response
      local function await_user_log_entry(res)
        local entry
        test.await.truthy(function()
          entry = nginx:get_json_log_entry(res.id)
          return entry
        end, 5, 0.05, "waiting for authenticated_user in the JSON logs")

        assert.is_table(entry.authenticated_user)
        assert.is_string(entry.authenticated_user.name)
        assert.same(USER, entry.authenticated_user.name)
      end


      local function check_options(path)
        it("allows OPTIONS requests", function()
          client:options(path)
          assert.same(200, client.response.status)
        end)
      end

      local function check_allowed_ip_only(path)
        it("allows requests from trusted IP addresses", function()
          client:get(path)
          assert.same(200, client.response.status)
          if trusted_client_ip then
            assert.is_true(client.response.json.trusted_ip)
          end
        end)
      end

      local function check_denied_ip_only(path, status)
        it("denies requests from trusted IP addresses (with no token)", function()
          client:get(path)
          assert.same(status or 403, client.response.status)
          assert.is_string(client.response.json.error)
        end)
      end

      local function check_denied_valid_token(path)
        it("denies requests even with valid tokens", function()
          setup_mocks()
          setup_userinfo({
            email = EMAIL,
            email_verified = true,
          })

          local token = jwt:sign(PRIVATE_KEY, {
            header = {
              typ = "JWT",
              alg = "RS256",
            },
            payload = {
              sub = "my-user",
              iss = BASE_URL,
              exp = ngx.now() + 1000,
            },
          })

          client.headers.Authorization = "Bearer " .. token
          client:get(path)

          assert.is_true(client.response.status == 401
                      or client.response.status == 403)

          assert.is_string(client.response.json.error)

          -- need a sanity check just to make sure we _do_ have a valid token
          setup_mocks()
          setup_userinfo({
            email = EMAIL,
            email_verified = true,
          })

          client:get("/auth-test/token")

          assert.same(200, client.response.status)
          await_user_log_entry(client.response)
        end)
      end


      local function check_allowed_token(path)
        it("uses OpenID to validate Bearer tokens", function()
          setup_mocks()
          setup_userinfo({
            email = EMAIL,
            email_verified = true,
          })

          local token = jwt:sign(PRIVATE_KEY, {
            header = {
              typ = "JWT",
              alg = "RS256",
            },
            payload = {
              sub = "my-user",
              iss = BASE_URL,
              exp = ngx.now() + 1000,
            },
          })

          client.headers.Authorization = "Bearer " .. token
          client:get(path)

          assert.same(200, client.response.status)
        end)

        it("identifies users by email", function()
          setup_mocks()
          setup_userinfo({
            email = EMAIL,
            email_verified = true,
          })

          local token = jwt:sign(PRIVATE_KEY, {
            header = {
              typ = "JWT",
              alg = "RS256",
            },
            payload = {
              sub = test.random_string(12),
              iss = BASE_URL,
              exp = ngx.now() + 1000,
            },
          })

          client.headers.Authorization = "Bearer " .. token
          client:get(path)

          assert.same(200, client.response.status)

          await_user_log_entry(client.response)
        end)

        it("identifies users by sub", function()
          setup_mocks()

          local token = jwt:sign(PRIVATE_KEY, {
            header = {
              typ = "JWT",
              alg = "RS256",
            },
            payload = {
              sub = SUB,
              iss = BASE_URL,
              exp = ngx.now() + 1000,
            },
          })

          client.headers.Authorization = "Bearer " .. token
          client:get(path)

          assert.same(200, client.response.status)

          await_user_log_entry(client.response)
        end)
      end

      local function check_bad_token(path)
        it("returns 403 when a user cannot be identified", function()
          setup_mocks()
          setup_userinfo({
            email = test.random_string(12) .. "@email.test",
            email_verified = true,
          })

          local token = jwt:sign(PRIVATE_KEY, {
            header = {
              typ = "JWT",
              alg = "RS256",
            },
            payload = {
              sub = test.random_string(12),
              iss = BASE_URL,
              exp = ngx.now() + 1000,
            },
          })

          client.headers.Authorization = "Bearer " .. token
          client:get(path)

          assert.same(403, client.response.status)
          assert.is_string(client.response.json.error)
        end)


        it("returns 401 for requests without a valid auth header", function()
          client:get(path)
          assert.same(401, client.response.status)
          assert.is_string(client.response.json.error)

          client.headers.Authorization = "nope!"
          client:get(path)
          assert.same(401, client.response.status)
          assert.is_string(client.response.json.error)
        end)

        it("returns 403 if the issuer doesn't match", function()
          setup_mocks()

          local token = jwt:sign(PRIVATE_KEY, {
            header = {
              typ = "JWT",
              alg = "RS256",
            },
            payload = {
              sub = "my-user",
              iss = "nope!",
              exp = ngx.now() + 1000,
            },
          })

          client.headers.Authorization = "Bearer " .. token
          client:get(path)

          assert.same(403, client.response.status)
          assert.is_string(client.response.json.error)
        end)

        it("returns 401 if the token is expired", function()
          setup_mocks()

          local token = jwt:sign(PRIVATE_KEY, {
            header = {
              typ = "JWT",
              alg = "RS256",
            },
            payload = {
              sub = "my-user",
              iss = BASE_URL,
              exp = ngx.now() - 1000,
            },
          })

          client.headers.Authorization = "Bearer " .. token
          client:get(path)

          assert.same(401, client.response.status)
          assert.same("access token expired", client.response.json.error)
        end)
      end

      local function check_valid_api_key_allowed(path)
        it("allows requests with a proper API key", function()
          client.headers[const.headers.api_key] = API_KEY
          client:get(path)
          assert.same(200, client.response.status)
          await_user_log_entry(client.response)
        end)
      end

      local function check_no_api_key_allowed(path)
        it("allows requests without an API key", function()
          client.headers[const.headers.api_key] = nil
          client:get(path)
          assert.same(200, client.response.status)
        end)
      end

      local function check_no_api_key_denied(path)
        it("rejects requests without an API key", function()
          client.headers[const.headers.api_key] = nil
          client:get(path)
          assert.is_true(client.response.status == 401
                      or client.response.status == 403)

          assert.is_string(client.response.json.error)
        end)
      end


      local function check_valid_api_key_denied(path)
        it("denies requests with a valid API key", function()
          client.headers[const.headers.api_key] = API_KEY
          client:get(path)
          assert.is_true(client.response.status == 401
                      or client.response.status == 403)

          assert.is_string(client.response.json.error)
        end)
      end

      local function check_invalid_api_key_denied(path, status)
        it("denies requests with multiple API keys", function()
          client.headers[const.headers.api_key] = { API_KEY, "yep!" }
          client:get(path)
          assert.same(status or 400, client.response.status)
          assert.is_string(client.response.json.error)
        end)
      end


      describe("strategy => IP", function()
        local path = "/auth-test/trusted-ip"
        check_options(path)

        if trusted_client_ip then
          check_allowed_ip_only(path)
          check_allowed_token(path)
          check_valid_api_key_allowed(path)
          check_no_api_key_allowed(path)
        else
          check_denied_ip_only(path)
          check_denied_valid_token(path)
          check_no_api_key_denied(path)
          check_valid_api_key_denied(path)
        end
      end)

      describe("strategy => token", function()
        local path = "/auth-test/token"
        check_options(path)
        check_denied_ip_only(path, 401)
        check_allowed_token(path)
        check_bad_token(path)
      end)

      describe("strategy => any", function()
        local path = "/auth-test/any"
        check_options(path)
        check_allowed_token(path)

        if trusted_client_ip then
          check_allowed_ip_only(path)
          check_valid_api_key_allowed(path)
          check_no_api_key_allowed(path)
        else
          check_denied_ip_only(path, 401)
          check_valid_api_key_allowed(path)
          check_no_api_key_denied(path)
          check_invalid_api_key_denied(path, 401)
        end
      end)

      describe("strategy => IP+token", function()
        local path = "/auth-test/ip-and-token"
        check_options(path)
        check_denied_ip_only(path, 401)

        if trusted_client_ip then
          check_allowed_token(path)
          check_bad_token(path)
        else
          check_denied_valid_token(path)
        end
      end)

      describe("strategy => none", function()
        local path = "/auth-test/none"
        check_options(path)
        check_allowed_token(path)
        check_allowed_ip_only(path)
        check_valid_api_key_allowed(path)
        check_no_api_key_allowed(path)
      end)

      describe("strategy => api key", function()
        local path = "/auth-test/api-key"
        check_options(path)
        check_denied_ip_only(path, 401)
        check_valid_api_key_allowed(path)
        check_invalid_api_key_denied(path)
        check_no_api_key_denied(path)
      end)
    end)
  end
end)
