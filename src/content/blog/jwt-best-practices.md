---
title: "JWT Best Practices for Production Applications"
description: "A practical guide to issuing, storing, and managing JWTs correctly — algorithm selection, key rotation, refresh token patterns, revocation strategies, and the storage debate settled."
pubDate: 2026-06-01
author: "AuthLayer Team"
tags: ["jwt", "security", "guide"]
featured: false
---

JWTs are easy to adopt and easy to get wrong. Most guides focus on attack scenarios — and you should read those too. This one focuses on the implementation decisions that determine whether your JWT-based auth is production-ready: algorithm selection, what to put in tokens, where to store them, how to handle expiry, and how to build revocation into a stateless system.

For attack-specific content (algorithm confusion, `alg: none`, token substitution) see [JWT Security Best Practices](/blog/jwt-security-best-practices).

## Choose the Right Signing Algorithm

The first decision shapes everything else.

### HS256 — Symmetric HMAC

Both signing and verification use the same secret key. Simple to implement, but every service that verifies tokens must hold the secret. If you have a single backend service, HS256 is acceptable. If multiple services need to verify tokens, every one of them becomes a secret-holding attack surface.

```javascript
// HS256 — same secret signs and verifies
jwt.sign(payload, process.env.JWT_SECRET, { algorithm: 'HS256' });
jwt.verify(token, process.env.JWT_SECRET, { algorithms: ['HS256'] });
```

The secret must be at least 256 bits (32 bytes) of cryptographically random data:

```bash
openssl rand -base64 32
```

### RS256 / ES256 — Asymmetric

A private key signs; a public key verifies. Services that only need to verify tokens never touch the private key. The public key can be published at `/.well-known/jwks.json` for automatic discovery.

**RS256** (RSA + SHA-256) is the most common choice for OIDC and enterprise systems. Use a 2048-bit key minimum; 4096-bit for high-assurance contexts.

**ES256** (ECDSA + P-256) produces much smaller signatures than RS256 for equivalent security. Prefer it for bandwidth-sensitive contexts.

### The rule

| Scenario | Algorithm |
|---|---|
| Single service, simple setup | HS256 with a strong random secret |
| Multiple verifying services | RS256 or ES256 |
| OIDC / identity tokens | RS256 (required by most providers) |
| Never | `none`, HS256 with a weak or static secret |

Always pin the algorithm server-side. Never read it from the incoming token header — that's the root cause of algorithm confusion attacks.

## Design Your Claims Carefully

### Include only what you need

Every claim that goes in a token is broadcast to every service that receives it. Start minimal:

```json
{
  "sub": "usr_01hx4k2n3p",
  "iss": "https://auth.example.com",
  "aud": "https://api.example.com",
  "iat": 1717200000,
  "exp": 1717200900,
  "jti": "01hx4k8r7q"
}
```

Add claims as requirements emerge. Don't pre-populate tokens with data you might need someday.

### The `jti` claim — token ID

`jti` (JWT ID) is a unique identifier for each token. It enables revocation — you can maintain a blocklist of `jti` values for tokens that should no longer be accepted. It also aids debugging and audit logging. Always include it.

```javascript
import { randomBytes } from 'crypto';

const payload = {
  sub: userId,
  iss: 'https://auth.example.com',
  aud: 'https://api.example.com',
  iat: Math.floor(Date.now() / 1000),
  exp: Math.floor(Date.now() / 1000) + 900,
  jti: randomBytes(16).toString('hex'),
};
```

### What not to put in tokens

JWT payloads are base64url-encoded, not encrypted. Anyone who intercepts or stores a token can read the payload without a key.

Avoid:
- Passwords or hashes
- Sensitive PII (credit card numbers, government IDs, full addresses)
- Internal system details that aid enumeration
- Mutable data that changes frequently (roles that update mid-session will be stale)

If you need confidentiality for claims, use JWE (JSON Web Encryption) or store sensitive data server-side and reference it by ID in the token.

### `aud` — one token, one audience

The audience claim ties a token to a specific service. Without it, a token issued for your payments API can be replayed against your admin API if both trust the same issuer. Set `aud` to the specific service identifier, and verify it server-side on every request.

```javascript
// Issuing — set the audience
{ aud: 'https://api.payments.example.com' }

// Verifying — check the audience
jwt.verify(token, publicKey, {
  algorithms: ['RS256'],
  audience: 'https://api.payments.example.com',
  issuer: 'https://auth.example.com',
});
```

## Set Token Lifetimes Deliberately

JWTs are stateless — once issued, they cannot be invalidated before they expire without additional infrastructure. Short-lived tokens limit the blast radius of a stolen token.

| Token type | Recommended lifetime |
|---|---|
| Access token | 5–15 minutes |
| ID token | 5–15 minutes |
| Refresh token | 1–30 days (with rotation) |

A 15-minute access token window means a stolen token is useless within 15 minutes. Pair it with a rotation-based refresh token strategy and the exposure window shrinks further.

## The Storage Debate: Cookies vs localStorage vs Memory

Where you store tokens in the browser has direct security consequences.

### localStorage — convenient, insecure for tokens

Accessible by any JavaScript on your page. An XSS vulnerability on any part of your site — your code, a CDN script, a third-party widget — can read and exfiltrate every token in localStorage. This is not a theoretical risk.

**Do not store access tokens or refresh tokens in localStorage.**

### Memory (JavaScript variable)

Tokens held in a variable are inaccessible to other scripts and don't survive page refresh, which limits exposure. The downside: the user must re-authenticate on every fresh page load. This is the correct tradeoff for high-security contexts.

### HttpOnly cookies

Tokens stored in `HttpOnly; Secure; SameSite=Strict` cookies are not accessible to JavaScript at all — only the browser sends them to the server. This eliminates the XSS token theft vector.

The tradeoff is CSRF exposure: requests from other origins automatically include cookies. `SameSite=Strict` mitigates most cross-site request forgery without needing a CSRF token, but you should understand the implications for your cookie domain configuration.

```
Set-Cookie: access_token=eyJ...; HttpOnly; Secure; SameSite=Strict; Path=/api; Max-Age=900
```

### The rule

| Context | Storage |
|---|---|
| Refresh tokens | HttpOnly cookie only |
| Access tokens | Memory (preferred) or HttpOnly cookie |
| Never | localStorage or sessionStorage |

## Refresh Token Rotation

Refresh tokens are long-lived and must be treated with care. Rotation ensures that each refresh token is single-use: when a client uses a refresh token to get a new access token, the server issues a new refresh token and invalidates the old one.

```
Client → Server: POST /token { grant_type: refresh_token, refresh_token: "rt_abc" }
Server → Client: { access_token: "new_at", refresh_token: "rt_xyz" }  // rt_abc is now invalid
```

If the server detects a refresh token being used more than once (a reuse signal), it should revoke the entire token family — because the original token was likely stolen and used by an attacker before the legitimate client could.

```javascript
async function rotateRefreshToken(oldToken) {
  const stored = await db.refreshTokens.findUnique({ where: { token: hash(oldToken) } });

  if (!stored) throw new Error('Invalid refresh token');

  if (stored.used) {
    // Reuse detected — revoke the entire family
    await db.refreshTokens.updateMany({
      where: { family: stored.family },
      data: { revoked: true },
    });
    throw new Error('Refresh token reuse detected — session revoked');
  }

  await db.refreshTokens.update({
    where: { id: stored.id },
    data: { used: true },
  });

  const newToken = generateRefreshToken();
  await db.refreshTokens.create({
    data: { token: hash(newToken), family: stored.family, userId: stored.userId },
  });

  return newToken;
}
```

## Revocation

Stateless JWTs cannot be revoked mid-lifetime — that's a feature (no server-side state) and a liability (you can't force-expire a token). The main strategies:

### Short expiry

The simplest approach: keep access token lifetimes short enough that revocation matters less. 5–15 minutes is usually acceptable. On logout, revoke the refresh token and let access tokens expire naturally.

### Token blocklist

Maintain a set of revoked `jti` values (in Redis or a database). On every request, check whether the incoming token's `jti` is in the blocklist. The blocklist entry only needs to persist until the token would have expired anyway.

```javascript
async function isRevoked(jti, exp) {
  const revoked = await redis.get(`revoked:${jti}`);
  return revoked !== null;
}

// On logout or forced revocation
async function revokeToken(jti, exp) {
  const ttl = exp - Math.floor(Date.now() / 1000);
  if (ttl > 0) await redis.setex(`revoked:${jti}`, ttl, '1');
}
```

This re-introduces server-side state but only for the blocklist, not for every request under normal conditions.

### Reference tokens

Some systems use opaque access tokens that require a server-side lookup for every request. This gives full revocation control at the cost of a database hit per request. JWTs and opaque tokens can coexist: use JWTs internally and issue opaque tokens externally.

## Key Rotation

Signing keys must be rotated periodically. For asymmetric keys, publish all active public keys in your JWKS endpoint:

```json
{
  "keys": [
    { "kid": "key-2026-06", "alg": "RS256", "use": "sig", ... },
    { "kid": "key-2026-03", "alg": "RS256", "use": "sig", ... }
  ]
}
```

Include a `kid` (key ID) claim in your JWT header. Verifiers use it to select the correct key from the JWKS. The rotation process:

1. Generate new key pair
2. Add new public key to JWKS (both keys are now active)
3. Switch signing to the new private key
4. Wait for all tokens signed with the old key to expire
5. Remove old public key from JWKS

Never remove a public key before all tokens signed with the corresponding private key have expired.

## Implementation Checklist

Before shipping JWT-based auth to production:

- [ ] Algorithm pinned server-side — never read from token header
- [ ] `exp` validated on every request
- [ ] `iss` and `aud` validated on every request
- [ ] `jti` included in every token
- [ ] Access token lifetime ≤ 15 minutes
- [ ] Refresh tokens stored in HttpOnly cookies
- [ ] Refresh token rotation implemented with reuse detection
- [ ] Revocation strategy defined (blocklist or short expiry)
- [ ] JWKS endpoint published (for RS256/ES256)
- [ ] Key rotation process documented and tested
- [ ] No sensitive data in token payload
- [ ] Signing keys in a secrets manager, not in source code

## Further Reading

- [JWT Security Best Practices](/blog/jwt-security-best-practices) — attack scenarios and how to defeat them
- [What Is OpenID Connect?](/blog/openid-connect-explained) — how ID tokens extend OAuth 2.0
- [RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519) — the JWT specification
- [RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517) — JSON Web Key (JWK)
- [RFC 7518](https://datatracker.ietf.org/doc/html/rfc7518) — JSON Web Algorithms (JWA)
