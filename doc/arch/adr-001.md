# ADR 1: Don't support ID Tokens signed by Symmetric Keys #

# Context #

The library currently assumes that the ID tokens are signed by a
public key (and the code unconditionally tries to build the actual
public key from the data we get from the ID Token issuer).

At the same time, the OpenID Connect Core 1.0 specification states
that:

> "Symmetric signatures MUST NOT be used by public (non-confidential)
> Clients because of their inability to keep secrets"

(see https://openid.net/specs/openid-connect-core-1_0.html#Signing).

As we don't expect to support confidential clients, it seems safe to
ignore Symmetric Keys when validating tokens.

# Decision #

Tokens signed with a Symmetric Key will always be marked as invalid
(whether they are actually valid or not).

# Status #

Accepted.

# Consequences #

Even if the ID Token issuer is configured to use Symmetric keys to
sign its tokens, and the library gets a perfectly valid token signed
using one of such keys, the library will always return that the token
is invalid.
