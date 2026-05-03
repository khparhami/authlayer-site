---
title: "JWT Security Best Practices: What Can Go Wrong and How to Fix It"
description: "JWTs are everywhere — and so are JWT vulnerabilities. Learn the algorithm confusion attacks, none algorithm bypass, weak secret issues, and validation mistakes that lead to authentication bypasses."
pubDate: 2026-02-03
author: "AuthLayer Team"
tags: ["jwt", "security", "vulnerabilities"]
image: "/images/og/jwt.jpg"
---

JSON Web Tokens are used in virtually every modern web application. They're also one of the most frequently misconfigured pieces of auth infrastructure. This guide covers the real-world attacks and the defences that work.

## JWT Structure Refresher

A JWT is three base64url-encoded segments joined by dots:

```
header.payload.signature
```

```json
// Header
{ "alg": "RS256", "typ": "JWT" }

// Payload
{ "sub": "user_123", "role": "admin", "exp": 1735689600, "iat": 1735603200 }

// Signature
RSASHA256(base64(header) + "." + base64(payload), privateKey)
```

The signature is what makes the token tamper-evident — but only if you verify it correctly.

## Attack: The `alg: none` Bypass

The JWT spec allows `"alg": "none"` to mean "unsigned token". Some early libraries accepted this at face value.

An attacker could take a valid token, decode it, modify the payload (`"role": "admin"`), re-encode with `"alg": "none"`, and submit a token with no signature — which the server would accept.

**Fix:** Explicitly specify which algorithms are acceptable. Never accept `none`.

```javascript
// Bad
jwt.verify(token, secret);

// Good
jwt.verify(token, secret, { algorithms: ['HS256'] });
```

## Attack: Algorithm Confusion (RS256 → HS256)

This is subtler and more dangerous. RS256 uses an asymmetric key pair — the server signs with a private key and verifies with the public key. HS256 uses a single symmetric secret for both.

If a library accepts both RS256 and HS256, an attacker can:
1. Obtain the server's **public key** (often available at `/.well-known/jwks.json`)
2. Create a new token signed with HS256, using the **public key as the HS256 secret**
3. The server, if it auto-detects algorithm from the token header, will verify HS256 using its public key — and accept the forged token

**Fix:** Pin the expected algorithm server-side. Do not auto-detect from the token header.

```javascript
// Pin the algorithm — never read it from the incoming token
const decoded = jwt.verify(token, publicKey, { algorithms: ['RS256'] });
```

## Attack: Weak HS256 Secrets

HS256 tokens can be cracked offline if the secret is weak. An attacker who obtains a valid token can run dictionary attacks against the signature using tools like `hashcat`.

**Fix:**
- Use a minimum 256-bit (32-byte) random secret for HS256
- Prefer RS256 or ES256 in production — asymmetric keys are harder to mishandle
- Rotate secrets on a schedule

```bash
# Generate a strong secret
openssl rand -base64 32
```

## Validation Checklist

Every JWT consumer must validate all of these:

| Claim | Check | Why |
|---|---|---|
| `alg` | Matches expected algorithm | Algorithm confusion |
| `exp` | Greater than current time | Expired token reuse |
| `nbf` | Less than current time (if present) | Not-yet-valid token |
| `iss` | Matches expected issuer | Cross-tenant forgery |
| `aud` | Matches your service | Token substitution attack |
| Signature | Valid for the expected key | Tamper detection |

Missing **any** of these opens an attack surface.

## Token Substitution Attack

If you don't validate `aud` (audience), a token issued for Service A can be replayed against Service B — if both services trust the same issuer.

```json
// Token intended for api.payments.com replayed against api.admin.com
{ "sub": "user_123", "iss": "auth.example.com", "aud": "api.payments.com" }
```

**Fix:** Always validate that `aud` matches the identifier of your service.

## Don't Store Sensitive Data in JWT Payloads

JWT payloads are **base64url encoded, not encrypted**. Anyone with the token can decode and read the payload — they just can't modify it without invalidating the signature.

Never put in a JWT:
- Passwords or password hashes
- PII beyond what's necessary (full credit card numbers, SSNs)
- Internal system details that aid enumeration

If you need confidentiality, use **JWE** (JSON Web Encryption) instead of plain JWT.

## Short Expiry + Refresh Tokens

JWTs are stateless — you can't invalidate them before they expire. This makes long-lived access tokens dangerous.

**Best practice:**
- Access tokens: 5–15 minutes
- Refresh tokens: stored server-side with revocation capability
- On logout: revoke the refresh token, let access tokens expire naturally

## Library Recommendations

Use well-maintained, audited libraries:

| Language | Library |
|---|---|
| Node.js | `jose` (preferred) or `jsonwebtoken` |
| Python | `python-jose` or `PyJWT` |
| Go | `golang-jwt/jwt` |
| Java | `nimbus-jose-jwt` |

Always check the library's CVE history before adopting it for auth.
