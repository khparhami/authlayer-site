---
title: "Authorization Code Flow vs PKCE: A Visual Comparison"
description: "Side-by-side walkthrough of OAuth 2.0's authorization code flow and PKCE with sequence diagrams — when each applies and how PKCE blocks code interception attacks."
pubDate: 2026-05-06
author: "Khashayar Parhami"
tags: ["oauth", "pkce", "security", "guide"]
image: "/images/og/pkce.jpg"
---

OAuth 2.0 has two variants of the authorization code flow: the classic flow with a `client_secret`, and PKCE (Proof Key for Code Exchange, RFC 7636). They look similar on the surface but exist for different client types and close different attacks. This guide walks through both with sequence diagrams.

## Why Two Flows Exist

The distinction comes down to **confidential** vs **public** clients.

A **confidential client** runs server-side code. Its `client_secret` never leaves the server, so it can authenticate with the authorization server. The secret stays secret.

A **public client** — a single-page app, mobile app, or CLI tool — runs on user-controlled hardware or inside the browser. There is no safe place to embed a `client_secret`. Anything in a compiled APK or a JavaScript bundle can be extracted. The secret is no longer secret.

PKCE was designed for public clients. It replaces the static `client_secret` with a per-request cryptographic challenge that proves the token request came from the same party that initiated the authorization — without requiring a pre-shared secret.

---

## Authorization Code Flow (Confidential Client)

Used when your app has a backend that can hold a `client_secret` securely.

```
 Browser              Auth Server         App Backend
    │                      │                   │
    │── GET /login ──────────────────────────>│
    │                      │                   │
    │<── 302 redirect ────────────────────────│
    │    /authorize?response_type=code         │
    │    &client_id=ID &state=RAND             │
    │                      │                   │
    │── GET /authorize ───>│                   │
    │                      │                   │
    │<── login page ───────│                   │
    │                      │                   │
    │── credentials ──────>│                   │
    │                      │                   │
    │<── 302 redirect ─────│                   │
    │    /callback?code=CODE &state=RAND       │
    │                      │                   │
    │── GET /callback?code=CODE ─────────────>│
    │                      │                   │
    │                      │<── POST /token ───│
    │                      │  code             │
    │                      │  + client_secret  │
    │                      │                   │
    │                      │── tokens ────────>│
    │                      │                   │
    │<── session cookie ──────────────────────│
```

### What makes this secure

The critical step is the token exchange in the bottom section. The `POST /token` call goes directly from your backend to the authorization server — the browser never touches the tokens. The `code` that travels through the browser is short-lived (typically 60 seconds) and single-use, and on its own is useless without the `client_secret`.

The `state` parameter ties the redirect to the session that started it, blocking CSRF attacks on the callback endpoint.

---

## PKCE Flow (Public Client)

Used for SPAs, mobile apps, and CLIs — any client that cannot safely store a `client_secret`.

Before the redirect, the client generates two values locally:

```javascript
// 1. Random high-entropy string (43–128 chars)
const codeVerifier = crypto.randomBytes(32).toString('base64url');

// 2. SHA-256 hash of the verifier
const codeChallenge = crypto.createHash('sha256')
  .update(codeVerifier)
  .digest('base64url');
```

Only `codeChallenge` (the hash) is sent to the authorization server. `codeVerifier` stays in memory.

```
 Browser / SPA                         Auth Server
    │                                      │
    │  generate code_verifier              │
    │  code_challenge = SHA256(verifier)   │
    │                                      │
    │── GET /authorize ───────────────────>│
    │    ?response_type=code               │
    │    &code_challenge=HASH              │
    │    &code_challenge_method=S256       │
    │    &client_id=ID &state=RAND         │
    │                                      │
    │<── login page ───────────────────────│
    │                                      │
    │── credentials ──────────────────────>│
    │                                      │  stores code_challenge
    │<── 302 redirect ─────────────────────│
    │    ?code=CODE &state=RAND            │
    │                                      │
    │── POST /token ──────────────────────>│
    │    code=CODE                         │
    │    code_verifier=ORIGINAL            │
    │                                      │  SHA256(verifier) == stored challenge?
    │<── { access_token, refresh_token } ──│
```

### What makes this secure

If an attacker intercepts `code` — via a malicious browser extension, a URL leak, or a compromised redirect URI — they still cannot exchange it for tokens. The token request requires `code_verifier`, the original random string, which was never transmitted to the authorization server. Without it, the request is rejected.

The server stores only the **hash** (`code_challenge`). SHA-256 is one-way, so even a breach of the authorization server's session store doesn't expose the verifier. Only the original client that generated the pair can complete the exchange.

---

## Side-by-Side Comparison

| Property | Auth Code (classic) | Auth Code + PKCE |
|---|---|---|
| Client type | Confidential (has backend) | Public (SPA, mobile, CLI) |
| Proof of identity | `client_secret` | `code_verifier` / `code_challenge` |
| Secret lifetime | Long-lived, static | Single request, ephemeral |
| Token exchange caller | App backend | Client directly |
| Code interception blocked by | `client_secret` | `code_verifier` |
| Requires a backend | Yes | No |

---

## Which One to Use

**Use authorization code + `client_secret` when:**
- You have a server-side backend (Node.js, Python, Go, etc.)
- The `client_secret` never leaves your server environment
- You want tokens handled entirely server-side, away from the browser

**Use authorization code + PKCE when:**
- You're building a SPA or mobile app with no confidential backend
- You need to defend against authorization code interception

**Use PKCE on both:** OAuth 2.1 — the in-progress successor to RFC 6749 — makes PKCE mandatory for all clients, including confidential ones. It adds a layer of defense at zero cost. There is no reason not to use PKCE alongside a `client_secret`; just use it everywhere.

## The Implicit Flow Is Not an Option

The implicit flow (`response_type=token`) returns tokens directly in the URL fragment. It was deprecated in OAuth 2.1 because tokens in URLs leak through browser history, referrer headers, and server logs. PKCE replaces it entirely — use that instead.

## Further Reading

- [RFC 7636](https://datatracker.ietf.org/doc/html/rfc7636) — the PKCE specification
- [RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749) — the OAuth 2.0 specification
- [OAuth 2.1 draft](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1) — mandates PKCE for all clients
