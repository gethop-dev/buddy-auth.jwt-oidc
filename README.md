[![ci-cd](https://github.com/gethop-dev/buddy-auth.jwt-oidc/actions/workflows/ci-cd.yml/badge.svg)](https://github.com/gethop-dev/buddy-auth.jwt-oidc/actions/workflows/ci-cd.yml)
[![Clojars Project](https://img.shields.io/clojars/v/dev.gethop/buddy-auth.jwt-oidc.svg)](https://clojars.org/dev.gethop/buddy-auth.jwt-oidc)

# Duct buddy-auth.jwt-oidc

A [Duct](https://github.com/duct-framework/duct) library that provides
[Integrant](https://github.com/weavejester/integrant) keys and associated code implementing a
[:duct.middleware.buddy/authentication](https://github.com/duct-framework/middleware.buddy)
compatible JWT token validation function for [OpenID Connect ID
Tokens](https://openid.net/specs/openid-connect-basic-1_0.html#IDToken).

See [OpenID Connect Core 1.0
Terminology](https://openid.net/specs/openid-connect-core-1_0.html#Terminology)
for additional details on the meaning of the OpenID Connect terms used
below.

## Installation

[![Clojars Project](https://clojars.org/dev.gethop/buddy-auth.jwt-oidc/latest-version.svg)](https://clojars.org/dev.gethop/buddy-auth.jwt-oidc)

To use this library you also need to add the following dependency to
your project (use the most recent version of it):

    [duct/middleware.buddy "0.2.0"]

### Caching

The library caches both the OpenID Provider signing keys and a
configurable amount of ID Token validation results, to speed up
repeated token validation. The signing keys are cached for a
configurable amount of time (see below). The ID Token validation
results are cached until ID Token expiration time in case the token is
successfully validated, or for an hour if it is not valid.

### Caveat with respect to JWT signatures

The library only supports asymmetric signatures for ID Tokens, and
marks any ID Token signed with a symmetric signature as invalid
(regardless of its actual validity!). The rationale for this decision
is that regarding symmetric signatures [OpenID Connect Core 1.0
specification states
that](https://openid.net/specs/openid-connect-core-1_0.html#Signing).:

> "Symmetric signatures MUST NOT be used by public (non-confidential)
> Clients because of their inability to keep secrets."

Web applications are non-confidential by their very nature, so the
library refuses to validate symmetric signatures.

## Usage

The library currently supports a single Integrant key:
`:dev.gethop.buddy-auth/jwt-oidc`. To initialize it, the following keys
are mandatory and their values must not be `nil`:

* `:claims` key which is a map with the set of OpenID Connect claims
  that the ID Token should satisfy. At least the following mandatory
  keys should be specified:
    * `:iss` is the URL, using the https scheme with no query or
      fragment component, that the ID Token OpenID Provider (OP)
      asserts as its Issuer Identifier. This also must be identical to
      the `iss` Claim value in ID Tokens issued by this OP.
    * `:aud` are the audience(s) that ID Tokens issued by the
      `<issuer-identifier-url>` are intended for. It contains the
      OAuth 2.0 `client_id` of the Relying Party as an audience
      value. It may also contain identifiers for other audiences. In
      the general case, the `<aud-values>` value is an array of
      case-sensitive strings. In the common special case when there is
      just one audience, the aud value MAY be a single case-sensitive
	  string.
* Either one of (but only one):
    * `:well-known-url` is the URL of the OpenID Provider's
      Configuration Document (also known as the "well-known
      openid-configuration").  It must be a `string` or a
      `java.net.URL` value.
    * `:jwks-uri` is the URL of the OpenID Provider's JSON Web Key Set
      [JWK] document. This contains the signing key(s) the Relaying
      Party uses to validate signatures from the OpenID Provider. It
      must be a `string` or a `java.net.URL` value.


You can also use the following optional configuration keys:

* `:pubkeys-expire-in` which is the time to live for the cached OpenID
  Provider signing keys. It has to be specified in an integral number
  of seconds greater than zero. If not specified the default value is
  86400 (one day).
* `:max-cached-tokens` which is the maximum amount of cached ID Token
  validation results. It has to be an integer value greater than
  zero. If not specified, the default value is 50.
* `:well-known-retrieval-timeout` which specifies the connection
  timeout (in milli-seconds) for "well-known openid-configuration"
  retrieval. It has to be an integer value greater than zero. If not
  specified, the default value is 500 milli-seconds.
* `:well-known-retrieval-retries` which specifies the number of
  additional retries in case of connection failure for "well-known
  openid-configuration" retrieval. It has to be an integer value
  greater than zero. If not specified, the default value is 3 retries.
* `:jwks-retrieval-timeout` which specifies the connection timeout (in
  milli-seconds) for JWKS retrieval. It has to be an integer value
  greater than zero. If not specified, the default value is 500
  milli-seconds.
* `:jwks-retrieval-retries` which specifies the number of additional
  retries in case of connection failure for JWKS retrieval. It has to
  be an integer value greater than zero. If not specified, the default
  value is 3 retries.
* `:logger` a value that implements the `duct.logger/Logger`
  protocol. If not `nil`, the library will log any relevant issues
  that may prevent tokens from being validated (e.g., inability to get
  the JWKS URL, getting invalid keys in the JWKS document, etc.)

Examples (using all optional configuration keys with their default values):

```clojure
{:dev.gethop.buddy-auth/jwt-oidc
 {:claims {:iss #duct/env ["ISSUER_URL" Str]
           :aud #duct/env ["AUDIENCE" Str]}
  :well-known-url #duct/env ["WELL_KNOWN_URL" Str]
  :pubkeys-expire-in 86400
  :max-cached-tokens 50
  :well-known-retrieval-timeout 500
  :well-known-retrieval-retries 3
  :logger #ig/ref :duct/logger}}

{:dev.gethop.buddy-auth/jwt-oidc
 {:claims {:iss #duct/env ["ISSUER_URL" Str]
           :aud #duct/env ["AUDIENCE" Str]}
  :jwks-uri #duct/env ["JWKS_URI" Str]
  :pubkeys-expire-in 86400
  :max-cached-tokens 50
  :jwks-retrieval-timeout 500
  :jwks-retrieval-retries 3
  :logger #ig/ref :duct/logger}}
```

Initializing the key returns an `authfn` function that can be used in
conjunction with
[:duct.middleware.buddy/authentication](https://github.com/duct-framework/middleware.buddy).
Example:

```clojure
{:dev.gethop.buddy-auth/jwt-oidc
 {:claims {:iss #duct/env ["ISSUER_URL" Str]
           :aud #duct/env ["AUDIENCE" Str]}
  :jwks-uri #duct/env ["JWKS_URI" Str]
  :logger #ig/ref :duct/logger}

 :duct.middleware.buddy/authentication
 {:backend    :token
  :token-name "Bearer"
  :authfn     #ig/ref :dev.gethop.buddy-auth/jwt-oidc}}
```

The `authfn` function does all the [OpenID Connect ID Token validation
process](https://openid.net/specs/openid-connect-basic-1_0.html#IDTokenValidation)
and returns the value of the `sub` claim if the ID Token was
successfully validated. Otherwise, it returns `nil`. The function
throws `AssertionError` if any of the following conditions occur:

* `:jwks-uri` is not a `string` or a valid `java.net.URL` value.
* `:iss` is `nil`
* `:aud` is `nil`

## Testing

The library includes self-contained units tests, and an integration
test that depends on AWS Cognito User Pools. That test is named
`dev.gethop.buddy-auth.jwt-oidc-test.test-cognito-token-validation` and
has the `^:integration` metadata keyword associated to it, so you can
exclude it from your unit tests runs.

If you want to run the integration test, the following set of
environment variables are needed (the first three are the standard AWS
credentials environment variables):

* `AWS_ACCESS_KEY_ID`: The Access key ID of an AWS IAM user. That user
  must have permission to perform the `InitiateAuth` action, on the AWS
  `cognito-idp` resource that points to a particular AWS Cognito User
  Pool.
* `AWS_SECRET_ACCESS_KEY`: The Secret Access key associated to the
  previous Access key ID.
* `AWS_DEFAULT_REGION`: The region where the User Pool is located at.
* `COGNITO_TESTS_USER_POOL_CLIENT_ID`: The ID of an "App client" that
  is allowed to interact with the User Pool.
* `COGNITO_TESTS_ISSUER_URL`: The Issuer URL (`iss` claim, in OpenID
  Connect terminology) used by the User Pool when minting OpenID
  Connect ID Tokens. See [ID Token Payload](https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-tokens-with-identity-providers.html#user-pool-id-token-payload)
  for additional details.
* `COGNITO_TESTS_AUDIENCE`: This is the Audience (`aud`, in OpenID
  Connect terminology), that contains the User Pool `client_id` used
  for the user authenticated. See the previous link for additional
  details.
* `COGNITO_TESTS_JWKS_URI`: The URI of the JSON Web Key Set (JWKS)
  for the User Pool. See step 2.a in [Step 2: Validate the JWT
  Signature](https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-tokens-verifying-a-jwt.html#amazon-cognito-user-pools-using-tokens-step-2)
  for additional details.
* `COGNITO_TESTS_USERNAME`: The "sign in" value of an existing user in
  the User Pool (note that depending on the User Pool configuration,
  the "sign in" value can be a username, an email address, or other
  values).
* `COGNITO_TESTS_PASSWORD`: The password for the previous user name.
* `COGNITO_TESTS_SUB`: The subject value (`sub` claim, in OpenID
  Connect terminology) assigned to the previous user in the User Pool.

## License

Copyright (c) 2022 Magnet S. Coop

This Source Code Form is subject to the terms of the Mozilla Public License,
v. 2.0. If a copy of the MPL was not distributed with this file, You can obtain
one at https://mozilla.org/MPL/2.0/
