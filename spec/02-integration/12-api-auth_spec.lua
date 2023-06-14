local test = require "spec.testing"
local cjson = require "cjson"
local mu = require "spec.testing.mock-upstream"
local jwt = require "resty.jwt"

local BASE_URL = "http://127.0.0.1:" .. test.constants.MOCK_UPSTREAM_PORT .. "/"

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
  end)

  it("uses OpenID to validate Bearer tokens", function()
    setup_mocks()

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




end)
