---
title: "API Security Checklist: 30 Controls Every API Should Have"
description: "A practical security checklist for REST APIs covering authentication, authorisation, input validation, rate limiting, transport security, logging, and common vulnerability patterns — with implementation guidance for each."
pubDate: 2026-06-02
author: "Khashayar Parhami"
tags: ["api-security", "security", "guide"]
image: "/images/og/api-security-checklist.png"
featured: false
---

APIs are the attack surface of modern software. They're where authentication can be bypassed, where data can be exfiltrated, where business logic can be abused. Unlike web UIs, APIs rarely have a human in the loop — which means a single misconfiguration can be exploited at machine speed.

This checklist covers the controls that matter most in production. Each section includes the "why" and a concrete implementation note, not just a label to tick.

---

## Authentication

### 1. Never roll your own authentication

Custom auth implementations introduce subtle bugs — timing vulnerabilities, nonce reuse, broken state machines. Use a well-audited library or identity provider.

### 2. Use short-lived tokens for API access

Access tokens should expire in 5–15 minutes. Long-lived tokens turn every theft into a prolonged incident.

```http
Authorization: Bearer eyJhbGciOiJSUzI1NiJ9...
```

### 3. Validate tokens on every request — server-side

Check the signature, expiry (`exp`), issuer (`iss`), and audience (`aud`) on every request. Never trust claims without verification.

```javascript
jwt.verify(token, publicKey, {
  algorithms: ['RS256'],
  issuer: 'https://auth.example.com',
  audience: 'https://api.example.com',
});
```

### 4. Pin the JWT algorithm server-side

Never read the algorithm from the token header. Hardcode the expected algorithm in your verification config. Reading `alg` from the token enables algorithm confusion attacks.

### 5. Reject requests with no authentication on protected routes

Return `401 Unauthorized`, not `403 Forbidden`, when credentials are missing entirely. Reserve `403` for authenticated requests that lack permission.

### 6. Implement refresh token rotation

Each use of a refresh token should issue a new one and invalidate the previous. Detect reuse (a used token being presented again) and revoke the entire token family.

---

## Authorisation

### 7. Enforce authorisation at the resource level, not just the route level

Checking that a user is logged in is not enough. Check that *this* user can access *this specific resource*.

```javascript
// Wrong — only checks authentication
app.get('/orders/:id', requireAuth, getOrder);

// Right — checks ownership
app.get('/orders/:id', requireAuth, async (req, res) => {
  const order = await Order.findById(req.params.id);
  if (order.userId !== req.user.id) return res.status(403).json({ error: 'Forbidden' });
  res.json(order);
});
```

This class of bug — where authenticated users can access each other's data by changing an ID — is OWASP's top API vulnerability: **Broken Object Level Authorisation (BOLA)**.

### 8. Use allow-lists for what users can access, not block-lists

It's easier to miss something in a block-list than an allow-list. Start from "denied" and explicitly grant access.

### 9. Never expose internal IDs directly

Sequential integers (`/orders/1042`) allow enumeration. Use UUIDs or opaque tokens for resource identifiers to make guessing impractical.

### 10. Apply least-privilege to service accounts and API keys

API keys used by third-party integrations or background services should have only the permissions they need — not admin-level access.

### 11. Validate function-level authorisation

Some endpoints should only be accessible to specific roles (admin, internal service). A regular user should not be able to reach `/admin/users` by knowing the URL.

---

## Input Validation

### 12. Validate all input — shape, type, length, range

Reject requests that don't match expected schema before they touch business logic. Use a validation library; don't write ad hoc checks.

```javascript
// Using zod
const createOrderSchema = z.object({
  productId: z.string().uuid(),
  quantity: z.number().int().min(1).max(1000),
  shippingAddress: z.string().max(500),
});

const result = createOrderSchema.safeParse(req.body);
if (!result.success) return res.status(400).json({ errors: result.error.issues });
```

### 13. Never pass user input directly to a database query

Use parameterised queries or an ORM. String concatenation into SQL is how SQL injection happens.

```javascript
// Wrong
db.query(`SELECT * FROM users WHERE email = '${email}'`);

// Right
db.query('SELECT * FROM users WHERE email = $1', [email]);
```

### 14. Sanitise input that will be stored and rendered

If user-supplied content is ever returned in an API response that a browser might render, sanitise it to prevent stored XSS.

### 15. Validate Content-Type headers

Reject requests whose `Content-Type` doesn't match what your endpoint expects. A JSON endpoint receiving `multipart/form-data` should return `415 Unsupported Media Type`.

### 16. Limit request body size

Large payloads can exhaust memory and enable denial-of-service. Set a reasonable body size limit at your server or API gateway.

```javascript
app.use(express.json({ limit: '100kb' }));
```

---

## Rate Limiting and Abuse Prevention

### 17. Rate limit all public endpoints

Apply rate limits per IP, per user, or per API key — ideally all three. Unauthenticated endpoints are particularly exposed.

```
429 Too Many Requests
Retry-After: 60
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 0
X-RateLimit-Reset: 1717202400
```

### 18. Apply stricter limits to authentication endpoints

Login, password reset, OTP verification, and token issuance endpoints are the most valuable targets for brute force. Apply aggressive rate limits and consider CAPTCHA for repeated failures.

### 19. Implement resource quotas, not just request quotas

Counting requests prevents brute force but not expensive operations. A request that generates a 50MB report, sends 1,000 emails, or runs a complex query should count differently than a simple read.

### 20. Detect and block credential stuffing patterns

Distributed login attempts — many IPs, low rate per IP — won't trigger per-IP rate limits. Use velocity checks across accounts, not just per-source-IP.

---

## Transport Security

### 21. Enforce HTTPS everywhere — redirect or reject HTTP

No API should accept credentials or sensitive data over plain HTTP. Redirect HTTP to HTTPS at the load balancer and return `301 Moved Permanently`.

### 22. Set HSTS with a long max-age

```http
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```

This prevents protocol downgrade attacks for returning clients.

### 23. Use TLS 1.2 minimum — disable older versions

TLS 1.0 and 1.1 are deprecated and have known vulnerabilities. Most cloud providers enforce TLS 1.2+ by default; verify your configuration explicitly.

### 24. Validate certificates on outbound requests

If your API makes HTTP requests to third-party services, verify their TLS certificates. Disabling certificate verification in SDKs or HTTP clients is a common development shortcut that makes it to production.

---

## Response and Error Handling

### 25. Never leak internal details in error responses

Stack traces, database error messages, file paths, and internal service names should never appear in API responses. Log them internally; return a generic error to the client.

```json
// Wrong
{ "error": "ERROR: column 'pasword' does not exist in table 'users' (PostgreSQL 14)" }

// Right
{ "error": "An unexpected error occurred.", "requestId": "req_01hx4k" }
```

### 26. Use consistent, meaningful HTTP status codes

| Scenario | Status |
|---|---|
| Missing credentials | 401 |
| Valid credentials, no permission | 403 |
| Resource not found | 404 |
| Validation failure | 400 |
| Rate limited | 429 |
| Downstream service error | 502 / 503 |

Don't return `200 OK` with an error in the body — it breaks monitoring and client error handling.

### 27. Strip sensitive fields from responses

Review every response schema. Fields like `passwordHash`, `internalId`, `secretKey`, or `adminNotes` should never be serialised into API responses, even if they're present on the underlying data model.

---

## Security Headers

### 28. Set security headers on all responses

```http
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Cache-Control: no-store
Content-Security-Policy: default-src 'none'
```

For APIs (not browser-rendered content), the most important is `Cache-Control: no-store` on any response containing credentials or personal data.

---

## Logging and Observability

### 29. Log authentication events with enough context to investigate

Log successful and failed authentications, token issuance, and privilege escalation events. Include timestamp, user ID (if available), IP address, user agent, and request ID. Do not log passwords, tokens, or secrets.

```json
{
  "event": "auth.login.failed",
  "timestamp": "2026-06-02T04:12:00Z",
  "ip": "203.0.113.45",
  "userAgent": "Mozilla/5.0...",
  "email": "user@example.com",
  "reason": "invalid_password",
  "requestId": "req_01hx4k"
}
```

### 30. Alert on anomalous patterns, not just individual events

A single failed login is noise. Ten thousand failed logins across different accounts in 60 seconds is a credential stuffing attack. Build detection on rate, pattern, and cross-account signals — not just per-event thresholds.

---

## Quick Reference

| Category | Controls |
|---|---|
| Authentication | 1–6 |
| Authorisation | 7–11 |
| Input Validation | 12–16 |
| Rate Limiting | 17–20 |
| Transport | 21–24 |
| Responses & Errors | 25–27 |
| Headers | 28 |
| Logging | 29–30 |

---

## Further Reading

- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/) — the canonical API vulnerability taxonomy
- [JWT Best Practices for Production Applications](/blog/jwt-best-practices) — deep dive on token handling
- [Session vs Token Authentication](/blog/session-vs-token-authentication) — choosing the right auth model for your API
- [OAuth 2.0 Explained](/blog/oauth2-explained) — delegated authorisation for API access
