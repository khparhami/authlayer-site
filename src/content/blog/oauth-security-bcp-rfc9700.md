---
title: "OAuth Is Changing the Rules: What RFC 9700 Requires You to Fix"
description: "The OAuth 2.0 Security Best Current Practice is now an RFC. It prohibits the implicit flow, mandates PKCE for all clients, requires exact redirect URI matching, and closes a mix-up attack vector that's been open since 2012. Here's what it means for your implementation."
pubDate: 2026-09-24
author: "Khashayar Parhami"
tags: ["oauth", "security", "identity", "developer-security"]
image: "/images/og/oauth-security-bcp.jpg"
featured: false
---

OAuth 2.0 was published in 2012. The specification was deliberately flexible — it described a framework, not a fixed protocol, and left many security decisions as optional or implementation-defined. That flexibility made OAuth adaptable. It also meant that a significant proportion of OAuth implementations, even carefully written ones, have made choices that are now known to be insecure.

RFC 9700, published in early 2025, is the IETF's attempt to fix this systematically. It's the OAuth 2.0 Security Best Current Practice — a document that's been in draft form since 2019, built on accumulated research into real-world OAuth attacks, and revised through six years of working group feedback. It is now normative. It obsoletes several recommendations in the original spec.

Most teams haven't read it. Most OAuth libraries don't enforce all of it by default. And some of the things it requires fixing are in deployments that have been running for years.

---

## What changed from the original spec

### Implicit flow: prohibited

The OAuth 2.0 implicit flow — `response_type=token` — was designed for browser-based JavaScript apps before PKCE existed. It issues the access token directly in the URL fragment after the authorization redirect. The token appears in the browser's address bar, in server logs, in `Referer` headers sent to third-party resources loaded on the page, and potentially in the browser history.

RFC 9700 prohibits the implicit flow. Not discourages — prohibits. There is no scenario in which it's acceptable.

If your app still uses it, the migration path is straightforward: Authorization Code with PKCE. The access token never appears in the URL. The code appears in the URL but is single-use and short-lived, so a leak in a log doesn't automatically translate to a compromised token.

```
IMPLICIT FLOW (prohibited)
──────────────────────────
GET /authorize?response_type=token&...
                                          ↓
redirect_uri#access_token=eyJhb...&token_type=Bearer

Token is in the URL. It gets logged everywhere.

AUTHORIZATION CODE + PKCE (required)
─────────────────────────────────────
GET /authorize?response_type=code&code_challenge=X...
                                          ↓
redirect_uri?code=abc123

Exchange code for token server-to-server (or from the client
using code_verifier). Token never appears in a URL.
```

### PKCE: required for all clients, not just public ones

PKCE (Proof Key for Code Exchange) was introduced as a defense against authorization code interception attacks — specifically for mobile apps where the redirect URI could be intercepted by a malicious app registered to the same custom scheme.

RFC 9700 extends the requirement to confidential clients as well. Even server-side applications that authenticate with a client secret are required to use PKCE.

The reason: PKCE defends against a different attack than client authentication does. A stolen authorization code can't be exchanged by an attacker who doesn't also have the code verifier — even if that attacker somehow obtained the client secret. These are complementary defenses, not alternatives.

```
WITHOUT PKCE:
Client generates auth URL → user authenticates →
auth server redirects with code →
if attacker intercepts code AND has client_secret:
    POST /token { code: stolen_code, client_secret: known_value } → token issued ✓ (bad)

WITH PKCE:
Client generates code_verifier → derives code_challenge →
includes challenge in auth URL → user authenticates →
auth server stores challenge → client includes verifier in token request →
POST /token { code: stolen_code, code_verifier: ??? } → token rejected ✓ (good)
```

Generating PKCE is straightforward:

```javascript
// Generate 32 random bytes → base64url-encode → code_verifier
const array = crypto.getRandomValues(new Uint8Array(32));
const codeVerifier = btoa(String.fromCharCode(...array))
  .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');

// SHA-256(verifier) → base64url-encode → code_challenge
const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(codeVerifier));
const codeChallenge = btoa(String.fromCharCode(...new Uint8Array(digest)))
  .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');

// In authorization request:
// code_challenge=<value>&code_challenge_method=S256

// In token request:
// code_verifier=<original>
```

### Redirect URI: exact match only

RFC 9700 requires authorization servers to perform exact string matching on redirect URIs. No prefix matching. No pattern matching. No wildcard subdomain matching. Exact match.

This closes the open redirect class of OAuth attacks. If a client is registered with `https://app.example.com/callback`, then `https://app.example.com/callback?extra=param` should be rejected — the path and query must match exactly.

The attack this prevents:

```
REGISTERED:  https://app.example.com/callback
ATTACKER SENDS IN AUTHZ REQUEST: https://app.example.com/callback/../attacker-page

(With prefix matching, this could be accepted)
(With exact matching, this is rejected)
```

Some authorization servers still do prefix or pattern matching for "flexibility". This is no longer a reasonable trade-off. Every relaxation of redirect URI matching is a potential open redirect. Open redirects in OAuth flows can redirect authorization codes to attacker-controlled servers.

### Authorization Server Mix-Up: the `iss` parameter

This is the one that surprises most developers when they first encounter it.

Imagine an application that uses two identity providers — a social login IdP and a corporate IdP. The user initiates login with the corporate IdP. An attacker, through a variety of mechanisms, tricks the authorization server into issuing an authorization code that gets sent to the redirect URI. The client receives this code and doesn't know which IdP issued it. It sends the code to the corporate IdP's token endpoint. The corporate IdP rejects it because the code came from the social IdP. No harm so far.

But now flip it: what if the client, confused about which server responded, sends a code intended for the corporate IdP to the social IdP's token endpoint? If the social IdP accepts codes it didn't issue (a misconfigured or malicious server), the attacker may be able to exchange the code for a token issued by the social IdP representing the attacker's account, but with the client thinking it received a corporate token.

This is the authorization server mix-up attack. It has been known since 2016 (Fett, Küsters, Schmitz). RFC 9700 mandates the fix: the `iss` authorization response parameter.

When the authorization server redirects back, it includes:
```
https://app.example.com/callback?code=abc123&state=xyz&iss=https%3A%2F%2Fidp.example.com
```

The client verifies that `iss` matches the expected authorization server before proceeding. Mix-up attack closed.

This requires authorization server support. Clients should verify it where present and reject flows where it's absent — or at minimum ensure their architecture doesn't use multiple authorization servers in a way that creates mix-up risk.

---

## What RFC 9700 recommends but doesn't prohibit

### Token lifetimes

Access tokens should be short-lived. RFC 9700 stops short of mandating a maximum, but the guidance is clear: shorter is better. The practical target for most applications is 15–60 minutes for access tokens.

Refresh tokens should be sender-constrained or rotation-based. Refresh token rotation means issuing a new refresh token on every use and invalidating the old one. If a stolen refresh token is used, the legitimate client's next rotation attempt will fail, signalling the compromise.

### nonce for OpenID Connect

In OIDC flows, the `nonce` parameter ties an ID token to a specific authorization request, preventing replay. A client generates a random nonce, includes it in the authorization request, stores it locally, and verifies it appears in the ID token's `nonce` claim.

RFC 9700 requires `nonce` when using the implicit flow — which is now prohibited anyway — but strongly recommends it for all OIDC flows. It's a cheap defence against ID token replay.

### `state` for CSRF protection

`state` has been recommended since the original spec, but implementations vary. RFC 9700 is explicit: the `state` parameter must be validated on the callback. A valid authorization response without the expected `state` value must be rejected.

PKCE closes the authorization code interception vector. `state` closes the CSRF vector. Both are required.

---

## Practical audit for your implementation

Before treating your OAuth implementation as compliant with RFC 9700, work through this:

```
CHECK                                          HOW TO VERIFY
─────────────────────────────────────────────────────────────────────────────
No response_type=token usage                   Search codebase and auth URLs
PKCE implemented for all flows                 Check authorization request for
                                               code_challenge param
PKCE method is S256 (not plain)               Check code_challenge_method param
Redirect URIs stored as exact strings          Check authz server config/docs
Redirect URI validated on each request         Attempt redirect with extra param
state generated and validated                  Check callback handler
state is unpredictable (cryptographic random)  Check state generation
nonce used in OIDC flows                       Check ID token validation
iss checked in authorization response          Check callback handler
Authorization codes are single-use             Attempt to replay a code
Token endpoint requires code_verifier          Check rejection on missing verifier
```

### The tests that matter most

**1. Replay the authorization code**

After a successful login, capture the authorization code from the callback URL. Attempt to use it again in a token request. A correctly implemented authorization server rejects the second use immediately. Many do not.

**2. Omit the code_verifier**

Send a token request with a valid authorization code but without the `code_verifier`. The token endpoint must reject it, even if the client_secret is present. If it succeeds, PKCE is not being enforced.

**3. Modify the redirect_uri**

Add a trailing slash, a query parameter, or a path segment to the registered redirect URI and include it in an authorization request. The server must reject it. If it accepts, the URI validation is prefix-based.

**4. Use a mismatched state**

Initiate an authorization flow, capture the callback URL, and replay it with a different `state` value. The client must reject it. If it proceeds to the token exchange, CSRF protection is absent.

---

## Why now

The implicit flow has been known insecure for years. Exact redirect URI matching has been recommended for years. PKCE has been available since 2015. The reason RFC 9700 matters even for teams who already knew this is what it does to the ecosystem.

Authorization server vendors who want to be RFC 9700-compliant must enforce these controls, not just support them. Library authors who target RFC 9700 compliance can reject insecure configurations by default. Audit frameworks can cite RFC 9700 as the compliance baseline.

The transition won't be instant. Some deployed systems still use the implicit flow because the migration was never prioritised. Some authorization servers still accept loose redirect URI matching to avoid breaking existing clients. RFC 9700 gives security teams the normative reference to argue for fixing them.

If you're building a new application today, these requirements should be the baseline from day one. The flexibility that created the implicit flow was a mistake. PKCE is three API calls. Exact redirect URI matching is a configuration string. None of this is hard.

---

## Further reading

- [RFC 9700 — OAuth 2.0 Security Best Current Practice](https://www.rfc-editor.org/rfc/rfc9700) — the full specification
- [Authorization Code Flow vs PKCE](/blog/authorization-code-flow-vs-pkce) — visual walkthrough of why PKCE matters
- [OAuth 2.0 Explained](/blog/oauth2-explained) — flows, tokens, and common implementation mistakes
- [DPoP: Sender-Constrained Tokens](/blog/dpop-sender-constrained-tokens) — going further: binding tokens to the client key
