---
title: "OAuth's Non-Happy Path: The Account Takeover Chains That Pass Code Review"
description: "The attacks landing on OAuth implementations in 2024-2025 don't break the cryptography. They exploit what happens when the flow goes slightly wrong: error handlers that leak redirect URLs, subdomain cookies that bypass SameSite, and CDN cache rules that don't understand OAuth callbacks."
pubDate: 2026-09-24
author: "Khashayar Parhami"
tags: ["oauth", "security", "identity", "oidc", "vulnerabilities"]
image: "/images/og/oauth-non-happy-path.jpg"
featured: false
---

Your OAuth implementation is probably correct — in the sense that the PKCE is configured, state parameters are validated, tokens expire, and you're on HTTPS. That's the happy path, and most implementations get it right.

The account takeover chains documented in 2024 don't go through the happy path. They go through the Referer header your app reads during error recovery. Through the subdomain that stopped doing anything important two years ago but can still set cookies on your root domain. Through the CDN cache rule that thinks a URL ending in `.js` must be a static file.

None of these require breaking SHA-256 or forging a JWT. They require finding the code path that runs when something goes slightly off-script, and then making sure it goes off-script.

---

## The Non-Happy Path: Error Flows as Attack Surface

Security researcher Oxrz's 2024 work — building on Frans Rosén's earlier "Dirty Dancing in OAuth" research — maps the attack surface that opens up in OAuth implementations specifically when the flow deviates from the expected sequence.

The happy path is the one your authorization server documentation describes. The non-happy path is everything else: the user hits the back button, the session expires mid-flow, the user declines consent, the code is used twice, the state parameter doesn't match.

Applications have to handle all of these. The handlers are usually written after the core flow and tested less carefully. That's where the attack surface lives.

### The Referer redirect trap

One specific pattern appears frequently in applications that want to send users back where they came from after authentication:

```
  User visits protected page
         │
         ▼
  App saves return destination ── using Referer header
         │                         or ?next= parameter
         ▼
  Redirect to OAuth provider
         │
         ▼
  User authenticates
         │
         ▼
  Callback received ──────────── code + state valid ✓
         │
         ▼
  Redirect to saved destination ← HERE is the problem
```

If the application uses the `Referer` header (or a `?next=` query parameter) to store the post-authentication destination, and doesn't rigorously validate that destination against an allowlist, the redirect after authentication can be pointed anywhere.

The attack looks like this:

```
  1. Attacker hosts page at:
     https://attacker.com/harvest

  2. That page issues a request to:
     https://victim.com/login
     [Referer: https://attacker.com/harvest]

  3. victim.com stores the Referer as the post-login destination

  4. Victim authenticates legitimately through the OAuth flow

  5. Post-login redirect sends browser to:
     https://attacker.com/harvest?next_token=...
     or includes session state in the URL fragment
```

The OAuth code and tokens stay on the server — nothing cryptographic is compromised. But the user's post-authentication state (session cookie, internal redirect token, sometimes even query parameters the app appended) goes to the attacker.

In practice this becomes account takeover when the application redirects with any session-identifying information in the URL, or when the attacker's page can make a credentialed request back to the victim app using the victim's fresh session.

**The fix is narrow and specific.** Post-authentication redirects must validate against an explicit allowlist of paths. The Referer header must never be used as a redirect destination. `?next=` parameters must be validated against the same origin before use.

```
  ACCEPTABLE post-auth redirect check:
  ─────────────────────────────────────────────────────────
  const allowed = ['/dashboard', '/settings', '/reports'];
  const destination = ALLOWLIST.includes(parsed.pathname)
    ? parsed.pathname
    : '/dashboard';  // default, never the Referer

  NOT acceptable:
  ─────────────────────────────────────────────────────────
  const destination = req.headers.referer ?? '/dashboard';
  const destination = req.query.next ?? '/dashboard';
  const destination = req.query.redirect_uri;
```

---

## Cookie Tossing: Subdomain XSS Defeats SameSite in OAuth Flows

Elliot Ward's 2024 research on cookie tossing showed how subdomain access — even limited, read-only subdomain XSS — completely breaks `SameSite` protection in OAuth flows.

### How SameSite protects OAuth (and how it doesn't)

OAuth CSRF protection depends on the `state` parameter. The application generates a random value, stores it (usually in a cookie), and then validates that the callback carries the same value. `SameSite=Lax` on that cookie ensures it isn't sent from a different site — so a cross-site attacker can't trick the user's browser into completing a callback with an attacker-chosen state.

That protection is real and it works. But "same site" in the browser's definition is based on the registrable domain (eTLD+1), not the full hostname. `app.example.com` and `uploads.example.com` are the same site. A script running on either one can set cookies that apply to the other.

```
  SAME SITE (SameSite= checks pass between these):
  ──────────────────────────────────────────────────────
  app.example.com  ←→  uploads.example.com
  app.example.com  ←→  legacy.example.com
  app.example.com  ←→  static-cdn.example.com

  DIFFERENT SITE (SameSite= cookies blocked):
  ──────────────────────────────────────────────────────
  app.example.com  ←→  attacker.com
  app.example.com  ←→  example.net
```

If an attacker has any script execution on any subdomain — a user-uploaded file, a forgotten staging environment, a deprecated marketing microsite — they can set cookies on the parent domain.

### The attack chain

```
  1. Attacker finds script execution on:
     uploads.example.com (e.g., stored XSS in file preview)

  2. From uploads.example.com, attacker plants cookie:
     document.cookie =
       "oauth_state=attacker_known_value; " +
       "domain=.example.com; " +
       "path=/auth/callback; " +
       "SameSite=Lax";

  3. Attacker initiates a real OAuth flow with the provider,
     using state=attacker_known_value:
     https://provider.com/authorize?
       client_id=victim_app&
       state=attacker_known_value&
       redirect_uri=https://example.com/auth/callback

  4. Provider redirects victim to:
     https://example.com/auth/callback?
       code=legitimate_auth_code&
       state=attacker_known_value

  5. App reads the state cookie:
     oauth_state = attacker_known_value  ← attacker planted this
     Incoming state = attacker_known_value  ← matches ✓

  6. App exchanges code for tokens using the legitimate code

  7. Victim's session is now tied to the attacker's OAuth
     authorization — attacker logs in as the victim
```

The state validation passes because the attacker controlled both sides: they planted the cookie AND they know the value in the callback URL.

The session fixation variant is particularly insidious. The attacker doesn't steal the victim's credentials — they get the victim to complete an OAuth flow that ends up creating a session the attacker can use. The victim successfully authenticates. Everything looks normal. The attacker's session also becomes valid.

### Defense: `__Host-` cookie prefix

The cleanest fix is the `__Host-` cookie prefix. Cookies named with this prefix can only be set by the exact origin — not by subdomains — and must be `Secure`, on the root path, without a `Domain` attribute.

```
  Set-Cookie: __Host-oauth_state=random_value;
              Secure; Path=/; SameSite=Lax

  Attacker's subdomain cannot set __Host- cookies.
  Planting the state via cookie tossing becomes impossible.
```

If `__Host-` isn't viable (some frameworks make it awkward), validating state in server-side session storage instead of a cookie removes the attack surface entirely — the state value never touches the browser.

---

## Web Cache Deception: When CDNs Don't Understand OAuth Callbacks

The third attack class was demonstrated in a 2024 account takeover against ChatGPT's OAuth implementation. The technique — web cache deception applied to OAuth paths — shows how infrastructure built for performance can undermine authentication security when cache rules are configured without security in mind.

### How CDN caching creates the problem

CDNs make caching decisions based on URL patterns. A common heuristic: URLs ending in `.js`, `.css`, or `/static/...` are cacheable static assets. URLs with query parameters or at paths like `/api/...` are dynamic and should not be cached.

OAuth callback URLs don't fit neatly into either category. They have query parameters (`code`, `state`) and sit at paths that could look like either static or dynamic resources depending on how the CDN rule is written.

Web cache deception exploits this ambiguity using path traversal:

```
  REAL callback URL (not cached):
  https://app.example.com/oauth/callback?code=ABC&state=XYZ

  ATTACKER-CRAFTED URL (may be cached as static asset):
  https://app.example.com/oauth/callback/../static/app.js
  ?code=ABC&state=XYZ

  What the backend sees after path resolution:
  /oauth/callback?code=ABC&state=XYZ  ← processes the OAuth callback

  What the CDN's cache key looks like:
  /oauth/callback/../static/app.js?code=ABC&state=XYZ
  or (after CDN normalization):
  /static/app.js  ← cached as a static JavaScript file
```

The backend processes the OAuth callback normally and returns a response that includes session data (a `Set-Cookie` header, or a body containing a token). The CDN, seeing what it thinks is a static asset, caches that response. Any other user who visits that URL receives the cached response — and inherits the victim's session.

### The ChatGPT attack chain

The 2024 attack on ChatGPT's OpenAI OAuth integration worked as follows:

```
  1. Researcher discovers:
     /api/auth/callback/openid-connect/../_next/static/...
     resolves to the OAuth callback on the backend

  2. Backend processes the OAuth callback for the code+state
     in the query string — issues session token in response

  3. CDN caches the response because the resolved URL
     matches the /_next/static/ caching rule

  4. Any attacker who can obtain a valid code+state pair
     (e.g., through a Referer leak) can craft this URL

  5. Once cached: anyone who fetches the URL receives
     the victim's session data

  6. Full account takeover without any cryptographic
     compromise
```

The session data was exfiltrated through the CDN's own infrastructure — a caching layer that exists to make the application faster.

### The fix

OAuth callback handlers must set explicit no-cache headers:

```http
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
```

At the CDN layer, OAuth paths need an explicit rule that overrides any static-asset heuristics:

```
  CDN configuration:
  /oauth/*           → bypass cache, never store
  /api/auth/*        → bypass cache, never store
  /callback*         → bypass cache, never store
  /__next/static/*   → cache (30 days) — but this rule
                       must not match traversal variants
```

Path traversal normalization at the CDN edge prevents the technique entirely: normalize all paths before applying cache rules, and treat any URL containing `..` as the traversal-resolved path, not the raw string.

---

## The Common Thread

Three different attack classes. Three different failure modes. One pattern: none of them break OAuth's cryptography. They break the infrastructure around it.

```
  ATTACK CLASS          BROKEN ASSUMPTION
  ────────────────────────────────────────────────────────────
  Referer redirect      Post-auth destinations are validated
  Cookie tossing        SameSite is same-hostname, not same-eTLD
  Web cache deception   CDN cache rules understand OAuth paths
```

OAuth 2.0 was designed to protect the authorization grant and token lifecycle. The redirect URI registry, state parameter, PKCE, and token binding all work as intended in these attacks. What fails is the code that connects the OAuth protocol to a real application — the error handlers, the redirect logic, the cookie configuration, the infrastructure rules.

Security reviews that focus on protocol compliance ("is PKCE implemented?") won't catch any of these. They require testing the non-happy paths: what happens when a redirect URL is malformed, what happens when a subdomain sets a state cookie, what happens when the callback URL has a path segment appended to it.

---

## What to Actually Check

The practical checklist for OAuth implementations:

**Redirect URI handling**
- Validate all post-authentication redirects against an explicit allowlist of paths, not prefixes
- Never use the `Referer` header as a return URL
- Never use unsanitized `?next=` or `?return=` parameters
- Open redirectors anywhere in the application become OAuth vulnerabilities

**Cookie security**
- Use the `__Host-` prefix for OAuth state cookies: `Set-Cookie: __Host-oauth_state=...`
- If `__Host-` isn't available, store OAuth state server-side and use a session ID
- Audit all subdomains — a forgotten staging server or user-content subdomain is a cookie tossing vector
- `SameSite=Strict` on session cookies (more restrictive than `Lax`; breaks some flows but eliminates more vectors)

**CDN and caching**
- Explicit `Cache-Control: no-store` on all OAuth endpoints: `/authorize`, `/callback`, `/token`
- CDN cache rules that explicitly exclude OAuth paths and don't rely on heuristics about file extensions
- Path normalization at the CDN edge before cache rule evaluation
- Test your CDN rules with path traversal variants of your callback URLs

**Error paths**
- OAuth error responses (`?error=access_denied`) should not include the original redirect URI in a way that can be manipulated
- Error pages should not forward query parameters to external URLs
- Test what happens when the state parameter is missing, malformed, or repeated

The attacks described here were all demonstrated against production systems by researchers with responsible disclosure practices. The techniques are now documented and understood. What distinguishes systems that get compromised from systems that don't is whether the non-happy path code received the same scrutiny as the happy path.
