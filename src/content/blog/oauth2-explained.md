---
title: "OAuth 2.0 Explained: Flows, Tokens, and Common Mistakes"
description: "A developer-focused breakdown of OAuth 2.0 — authorization code flow, PKCE, token types, and the security pitfalls that trip up even experienced engineers."
pubDate: 2026-01-15
author: "AuthLayer Team"
tags: ["oauth", "security", "guide"]
image: "/images/og/oauth2.jpg"
featured: true
---

OAuth 2.0 is the authorization framework behind "Sign in with Google", API access delegation, and most modern identity systems. Yet it's frequently misunderstood, misconfigured, and misused. This guide cuts through the RFC and gives you the practical understanding you need.

## What OAuth 2.0 Actually Does

OAuth 2.0 is an **authorization** framework — not an authentication one. It answers the question: *"Can this application access this resource on behalf of this user?"* It does not answer: *"Is this the user they claim to be?"* (That's OpenID Connect's job, built on top of OAuth 2.0.)

The core actors:

- **Resource Owner** — the user who owns the data
- **Client** — the application requesting access
- **Authorization Server** — issues tokens (e.g. Okta, Auth0, Cognito)
- **Resource Server** — the API holding the protected data

## The Authorization Code Flow (the one you should use)

For web and mobile apps, the authorization code flow is the correct choice. Here's the sequence:

1. Client redirects user to the authorization server with `response_type=code`
2. User authenticates and consents
3. Authorization server redirects back with a short-lived `code`
4. Client exchanges the code (server-side) for tokens
5. Client receives `access_token`, `refresh_token`, `id_token`

```
Client → Auth Server: /authorize?response_type=code&client_id=...&redirect_uri=...
Auth Server → Client: /callback?code=abc123
Client → Auth Server: POST /token { code: abc123, client_secret: ... }
Auth Server → Client: { access_token, refresh_token, expires_in }
```

The key security property: the `access_token` is never exposed to the browser.

## PKCE — Required for Public Clients

If your client can't keep a secret (single-page apps, mobile apps, CLIs), use **PKCE** (Proof Key for Code Exchange).

Instead of a `client_secret`, the client generates:

```javascript
const codeVerifier = crypto.randomBytes(32).toString('base64url');
const codeChallenge = crypto.createHash('sha256').update(codeVerifier).digest('base64url');
```

The `code_challenge` goes in the authorization request. The `code_verifier` goes in the token exchange. An intercepted authorization code is useless without the original verifier.

**Rule:** Always use PKCE for public clients. Use it for confidential clients too — there's no downside.

## Token Types

| Token | Purpose | Lifetime |
|---|---|---|
| Access Token | Proves authorization to the resource server | Short (5–60 min) |
| Refresh Token | Gets new access tokens without re-auth | Long (hours–days) |
| ID Token | Proves user identity (OIDC, JWT format) | Short |

Access tokens should be **opaque to the client**. Treat them as black boxes — don't parse or rely on their contents unless you're the resource server.

## Common Mistakes

**1. Using the implicit flow**
The implicit flow (`response_type=token`) returns tokens directly in the URL fragment. It was deprecated in OAuth 2.1 — never use it. Use authorization code + PKCE instead.

**2. Missing state parameter**
The `state` parameter prevents CSRF attacks on the redirect. Generate a random value, store it in session, and verify it matches when the callback arrives.

**3. Overly broad scopes**
Request only the scopes your application actually needs. `scope=read:profile` is better than `scope=admin`. Apply least privilege to token requests.

**4. Storing tokens in localStorage**
Access tokens in `localStorage` are readable by any JavaScript on your page — including injected scripts. Use `httpOnly` cookies or in-memory storage. Refresh tokens should never go near the browser.

**5. Not validating redirect URIs**
An exact-match redirect URI allowlist is your first line of defence against authorization code interception. Wildcards are dangerous.

## What OAuth 2.0 Is Not

OAuth 2.0 does not define:
- How to authenticate users (use OpenID Connect for that)
- Token format (JWTs are common but not required)
- How to revoke tokens (see RFC 7009)
- How to introspect tokens (see RFC 7662)

Understanding the boundaries of the spec helps you know which extension RFC to reach for when you hit a gap.

## Further Reading

- [RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749) — The OAuth 2.0 specification
- [RFC 7636](https://datatracker.ietf.org/doc/html/rfc7636) — PKCE
- [OAuth 2.1 draft](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1) — The simplified successor
