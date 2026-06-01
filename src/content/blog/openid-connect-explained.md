---
title: "What Is OpenID Connect? The Identity Layer OAuth 2.0 Was Missing"
description: "OpenID Connect adds authentication to OAuth 2.0's authorization framework. Learn how it works, what the ID token contains, how discovery and UserInfo fit in, and the validation mistakes that undermine it."
pubDate: 2026-06-01
author: "AuthLayer Team"
tags: ["oauth", "oidc", "security", "guide"]
featured: false
---

OAuth 2.0 solved delegation — letting applications act on a user's behalf without their password. But it never defined how to verify *who* that user is. OpenID Connect (OIDC) fills that gap. It's a thin identity layer on top of OAuth 2.0, and it's what powers "Sign in with Google", "Continue with Apple", and most enterprise SSO deployments today.

## Why OAuth 2.0 Alone Isn't Authentication

A common mistake: treating OAuth 2.0 access tokens as proof of identity.

An access token proves that *some* authorized party granted access to *some* resource. It says nothing about who the user is, whether they authenticated recently, or whether the token was issued to *your* application. Using it for login is like accepting someone's house key as proof of identity — it proves they have the key, not who they are.

OIDC defines a standard way to answer the authentication question: *"Is this who they say they are, and can I get verified information about them?"*

## What OIDC Adds to OAuth 2.0

OIDC extends OAuth 2.0 with three things:

1. **The ID token** — a signed JWT that asserts who the user is
2. **The UserInfo endpoint** — a protected endpoint for fetching additional claims
3. **Discovery** — a standardised metadata endpoint at `/.well-known/openid-configuration`

Everything else — the authorization code flow, PKCE, token endpoints, scopes — is unchanged OAuth 2.0. OIDC rides on top of it.

## The ID Token

The ID token is the centrepiece of OIDC. It's a JWT issued by the authorization server alongside (or instead of) the access token, and it's addressed to *your application*, not to an API.

A decoded ID token payload looks like this:

```json
{
  "iss": "https://accounts.google.com",
  "sub": "110169484474386276334",
  "aud": "812741506391.apps.googleusercontent.com",
  "iat": 1353601026,
  "exp": 1353604926,
  "email": "user@example.com",
  "email_verified": true,
  "nonce": "0394852-3190485-2490358",
  "name": "Jane Smith",
  "picture": "https://lh3.googleusercontent.com/a/..."
}
```

The standard claims you will always see:

| Claim | Meaning |
|---|---|
| `iss` | Issuer — the identity provider's URL |
| `sub` | Subject — the user's stable, unique identifier |
| `aud` | Audience — your application's `client_id` |
| `iat` | Issued at (Unix timestamp) |
| `exp` | Expiry (Unix timestamp) |
| `nonce` | Replay protection value you provided in the request |

The `sub` claim is the right identifier to use as a stable user key. Email addresses change. `sub` doesn't.

## Requesting an ID Token

To trigger OIDC, include `openid` in your scope. This is the minimum:

```
GET /authorize
  ?response_type=code
  &client_id=your_client_id
  &redirect_uri=https://your-app.example/callback
  &scope=openid
  &state=random_csrf_value
  &nonce=random_replay_value
```

With just `openid`, you get `iss`, `sub`, `aud`, `iat`, `exp`, and `nonce`. For more user data, add scopes:

| Scope | Claims returned |
|---|---|
| `openid` | `sub` (required) |
| `profile` | `name`, `given_name`, `family_name`, `picture`, `locale` |
| `email` | `email`, `email_verified` |
| `phone` | `phone_number`, `phone_number_verified` |
| `address` | `address` |

The token exchange is identical to OAuth 2.0. After the user authenticates and consents, the authorization server returns an authorization code. Your server exchanges it:

```
POST /token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code
&code=abc123
&redirect_uri=https://your-app.example/callback
&client_id=your_client_id
&client_secret=your_client_secret
```

The response now includes an `id_token` alongside the familiar `access_token`:

```json
{
  "access_token": "eyJhbGciOiJSUzI1NiJ9...",
  "id_token": "eyJhbGciOiJSUzI1NiJ9...",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

## Validating the ID Token

This is where most implementations go wrong. An ID token is only useful if you validate it properly. Required checks:

**1. Signature**
Verify the JWT signature using the identity provider's public keys. These are fetched from the `jwks_uri` in the discovery document. Never skip this.

**2. Issuer (`iss`)**
Must exactly match the identity provider URL you configured. A token from `https://evil.example.com` would otherwise pass signature validation if the attacker controls their own OIDC provider.

**3. Audience (`aud`)**
Must include your `client_id`. If it doesn't, the token was issued for a different application and must be rejected.

**4. Expiry (`exp`)**
Must be in the future. Allow a small clock skew (±60 seconds) for distributed systems.

**5. Nonce**
If you included a `nonce` in the authorization request, verify the same value appears in the token. This prevents replay attacks — an attacker capturing a valid token cannot reuse it in a different session.

```javascript
// Using jose (Node.js)
import { createRemoteJWKSet, jwtVerify } from 'jose';

const JWKS = createRemoteJWKSet(new URL('https://accounts.google.com/.well-known/openid-configuration'));

const { payload } = await jwtVerify(idToken, JWKS, {
  issuer: 'https://accounts.google.com',
  audience: process.env.CLIENT_ID,
});

if (payload.nonce !== sessionNonce) {
  throw new Error('Nonce mismatch');
}

const userId = payload.sub; // stable identifier
```

## The UserInfo Endpoint

If you need user profile data but don't want it embedded in every ID token, use the UserInfo endpoint. It accepts the access token and returns claims for the authenticated user:

```
GET /userinfo
Authorization: Bearer <access_token>
```

```json
{
  "sub": "110169484474386276334",
  "name": "Jane Smith",
  "email": "jane@example.com",
  "email_verified": true,
  "picture": "https://..."
}
```

One important rule: the `sub` in the UserInfo response must match the `sub` in the ID token. If they don't match, reject both — something is wrong.

## Discovery

OIDC providers publish a metadata document at a well-known URL:

```
GET https://accounts.google.com/.well-known/openid-configuration
```

The response tells your application everything it needs:

```json
{
  "issuer": "https://accounts.google.com",
  "authorization_endpoint": "https://accounts.google.com/o/oauth2/v2/auth",
  "token_endpoint": "https://oauth2.googleapis.com/token",
  "userinfo_endpoint": "https://openidconnect.googleapis.com/v1/userinfo",
  "jwks_uri": "https://www.googleapis.com/oauth2/v3/certs",
  "scopes_supported": ["openid", "email", "profile"],
  "response_types_supported": ["code", "token", "id_token"],
  "id_token_signing_alg_values_supported": ["RS256"]
}
```

Use the discovery document to configure your client dynamically rather than hardcoding endpoint URLs. The `jwks_uri` is particularly important — it's where you fetch the public keys to verify ID token signatures.

## OIDC vs SAML

SAML 2.0 solves the same problem — federated authentication — using XML assertions instead of JWTs. If you're building a new integration, OIDC is almost always the right choice:

| | OIDC | SAML 2.0 |
|---|---|---|
| Token format | JWT (JSON) | XML assertions |
| Transport | REST / JSON | HTTP POST / Redirect |
| Mobile support | Native | Awkward |
| Complexity | Moderate | High |
| Enterprise IdP support | Broad | Broad (legacy) |

SAML remains common in enterprise environments with legacy identity providers (ADFS, older Okta configurations). OIDC is the default for everything built after roughly 2015.

## Common Mistakes

**Using the access token as identity proof**
The access token is for resource access, not identity. Only the ID token — with full validation — proves identity.

**Not checking `aud`**
An ID token from the same issuer but intended for a different application is not valid for yours. Always check audience.

**Skipping the nonce**
The nonce protects against replay attacks in certain flows. Always generate a cryptographically random nonce, store it server-side, and verify it on callback.

**Using email as the primary key**
Email addresses are mutable and can be transferred between accounts. Use `sub` (combined with `iss` for multi-provider setups) as your stable user identifier.

**Not pinning the signing algorithm**
Auto-detecting the algorithm from the token header is dangerous — see the [JWT algorithm confusion attack](/blog/jwt-security-best-practices). Explicitly configure `RS256` (or whatever the provider uses) and reject anything else.

## Further Reading

- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html) — the specification
- [RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749) — OAuth 2.0 (the foundation)
- [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html) — the `.well-known` spec
- [OAuth 2.0 Explained](/blog/oauth2-explained) — the AuthLayer OAuth 2.0 guide
