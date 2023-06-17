local test = require "spec.testing"
local cjson = require "cjson"
local mu = require "spec.testing.mock-upstream"
local jwt = require "resty.jwt"

local BASE_URL = "http://127.0.0.1:" .. test.constants.MOCK_UPSTREAM_PORT .. "/"

local USER = "my-test-user"
local SUB = "provider|my-test-user-sub"
local EMAIL = "my-test-user@email.test"

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
          },
        },
      },
    }

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
    end, 5, 0.1, "waiting for authenticated_user in the JSON logs")

    assert.is_table(entry.authenticated_user)
    assert.is_string(entry.authenticated_user.name)
    assert.same(USER, entry.authenticated_user.name)
  end

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
    client:get("/auth-test")

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
    client:get("/auth-test")

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
    client:get("/auth-test")

    assert.same(200, client.response.status)

    await_user_log_entry(client.response)
  end)

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
    client:get("/auth-test")

    assert.same(403, client.response.status)
  end)


  it("returns 401 for requests without a valid auth header", function()
    client:get("/auth-test")
    assert.same(401, client.response.status)

    client.headers.Authorization = "nope!"
    client:get("/auth-test")
    assert.same(401, client.response.status)
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
    client:get("/auth-test")

    assert.same(403, client.response.status)
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
    client:get("/auth-test")

    assert.same(401, client.response.status)
    assert.same("access token expired", client.response.json.error)
  end)

  it("does not require an auth token for CORS pre-flight/OPTIONS", function()
    client:options("/auth-test")
    assert.same(200, client.response.status)
  end)
end)