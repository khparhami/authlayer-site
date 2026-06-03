---
title: "Designing OAuth Scopes for Your API"
description: "Scopes are OAuth's mechanism for expressing what an application is allowed to do. Learn how to define them, name them, set granularity correctly, avoid scope sprawl, design consent screens users can understand, and version scopes without breaking clients."
pubDate: 2026-06-03
author: "Khashayar Parhami"
tags: ["oauth", "api-security", "guide"]
image: "/images/og/designing-oauth-scopes.png"
featured: false
---

Scopes are the mechanism OAuth uses to express what an application is permitted to do on a user's behalf. They're the words that appear on the consent screen — "This app wants to: read your profile, access your files" — and they're the claims your resource server checks to decide whether to honour a request.

Most OAuth guides explain how scopes work mechanically. Far fewer explain how to design them well. A poorly designed scope system is either too coarse (everything under one scope, no meaningful least privilege) or too fine-grained (dozens of scopes that no developer can remember, and users presented with an incomprehensible consent wall). This guide covers the design decisions that lead to a scope system that's secure, maintainable, and usable.

---

## What Scopes Actually Are

In OAuth 2.0, scopes are strings that appear in the authorization request and, if granted, in the resulting access token. The resource server validates the token and checks that it contains the scope required for the operation being requested.

```
Client → Auth Server: GET /authorize?scope=read:profile write:posts&...
Auth Server → Client: access_token containing { scope: "read:profile write:posts" }
Client → Resource Server: GET /profile
                          Authorization: Bearer eyJ...
Resource Server: verify token → check scope includes "read:profile" → allow
```

Scopes are about **delegation**: what has the user consented to let this application do? They are not the same as roles or permissions — those are about what the user themselves is allowed to do. A scope is a ceiling on what the application can do, bounded by what the user themselves could do.

```
User can: read:profile, write:posts, delete:account
App requests: read:profile, write:posts
Granted scopes: read:profile, write:posts

App cannot delete the account even if it tries — it was never granted that scope.
Even if the user can delete their own account, the app cannot do it on their behalf.
```

---

## Naming Conventions

There is no mandated format for scope names — they're just strings. But consistency matters for developer experience and maintainability. Three common patterns:

### resource:action

```
profile:read
profile:write
posts:read
posts:write
posts:delete
billing:read
billing:write
admin:users:read
admin:users:write
```

Clear, predictable, and easy to enumerate. The `resource:action` pattern reads naturally in code and consent screens. The namespace separator (`:`) can also be `.` or `/` — pick one and stick to it.

### Tiered scopes (GitHub-style)

```
repo          // full repository access (read + write)
repo:status   // commit status only
repo:read     // read-only repository access
read:user     // read user profile
user:email    // access email address only
```

Useful when some combinations are much more common than individual fine-grained scopes. The top-level scope implies broader access; sub-scopes are narrower.

### Resource-URL style (Google-style)

```
https://www.googleapis.com/auth/gmail.readonly
https://www.googleapis.com/auth/gmail.send
https://www.googleapis.com/auth/drive.file
```

Fully qualified and unambiguous, but verbose. Useful for large public platforms where scope names from different APIs must not collide.

**Pick `resource:action` for most APIs.** It's the most readable pattern for developers integrating your API, and it maps cleanly to both code and consent screen copy.

---

## Getting Granularity Right

The hardest design decision. Too coarse and you can't express meaningful least privilege; too fine and you've built a system nobody will use correctly.

### Too coarse — the single-scope trap

```
api:access  // grants everything
```

This is effectively no scope system. Every client that wants any access requests the same scope. There's no way for a user to grant a read-only third-party app access without also granting write access. Useless for least privilege.

### Too fine — scope explosion

```
posts:create
posts:read:own
posts:read:public
posts:read:draft
posts:update:own
posts:update:any
posts:delete:own
posts:delete:any
posts:publish:own
posts:publish:any
posts:archive
posts:restore
```

Twelve scopes for one resource. Developers won't remember them all. The consent screen becomes a wall of text. Token requests balloon in size. Admins can't reason about what access a client actually has.

### The right level: action-on-resource, with read/write as the primary split

Start with two scopes per resource: read and write. Add finer scopes only when there's a real product requirement for a client that needs one but not the other.

```
// Start here — covers 90% of use cases
posts:read
posts:write

// Add these only when a client specifically needs them
posts:publish   // a scheduling tool needs to publish but not edit
posts:delete    // a moderation tool needs delete but not write
```

**Rule of thumb:** if you can't name a real client that would request scope A but not scope B, don't split them.

### Sensitive operations deserve their own scope

Some operations are sensitive enough to warrant isolation regardless of YAGNI:

```
billing:read      // view invoices — safe for analytics tools
billing:write     // modify payment methods — should require explicit consent
account:delete    // destructive — should require explicit consent
admin:*           // elevated privileges — should never be in user-delegated tokens
```

Isolating sensitive operations lets users grant routine access to third-party apps without exposing critical operations.

---

## Resource Scopes vs Action Scopes

Two models for structuring scopes:

**Action-first:** the action (read/write) is the primary axis.

```
read:profile     read:posts     read:billing
write:profile    write:posts    write:billing
```

**Resource-first:** the resource is the primary axis.

```
profile:read     posts:read     billing:read
profile:write    posts:write    billing:write
```

Resource-first is generally more intuitive. Developers searching for "what scopes does posts need?" can filter by prefix. Consent screens group naturally by resource. Stick with `resource:action`.

---

## Mapping Scopes to API Endpoints

Document and enforce the scope-to-endpoint mapping explicitly. Don't rely on developers remembering which scope covers which endpoint.

```javascript
// Define the mapping centrally
const ENDPOINT_SCOPES = {
  'GET /users/me':          ['profile:read'],
  'PUT /users/me':          ['profile:write'],
  'GET /posts':             ['posts:read'],
  'POST /posts':            ['posts:write'],
  'DELETE /posts/:id':      ['posts:delete'],
  'POST /posts/:id/publish':['posts:publish'],
  'GET /billing/invoices':  ['billing:read'],
  'POST /billing/payment-method': ['billing:write'],
};

// Middleware that enforces it
function requireScopes(...requiredScopes) {
  return (req, res, next) => {
    const tokenScopes = req.auth.scope?.split(' ') ?? [];
    const hasAll = requiredScopes.every(s => tokenScopes.includes(s));
    if (!hasAll) {
      return res.status(403).json({
        error: 'insufficient_scope',
        required: requiredScopes,
      });
    }
    next();
  };
}

// Applied to routes
app.get('/posts', requireScopes('posts:read'), getPosts);
app.post('/posts', requireScopes('posts:write'), createPost);
app.delete('/posts/:id', requireScopes('posts:delete'), deletePost);
```

Return `403` with `error: insufficient_scope` (not `401`) when a token is valid but lacks the required scope. This tells clients exactly what they're missing.

---

## Scope Hierarchies and Inheritance

Some scope systems implement hierarchy, where a broader scope implies narrower ones:

```
// write implies read
posts:write → includes posts:read
billing:write → includes billing:read

// admin implies everything
admin → includes posts:read, posts:write, posts:delete, ...
```

Hierarchies reduce the number of scopes clients need to request but complicate reasoning about what a token can do. If you implement hierarchy, document it explicitly and enforce it in your token validation logic:

```javascript
function hasScope(tokenScopes, requiredScope) {
  if (tokenScopes.includes(requiredScope)) return true;

  // Write implies read
  const writeEquivalent = requiredScope.replace(':read', ':write');
  if (requiredScope.endsWith(':read') && tokenScopes.includes(writeEquivalent)) return true;

  // Admin implies everything
  if (tokenScopes.includes('admin')) return true;

  return false;
}
```

Keep hierarchies shallow. Deep inheritance chains are hard to audit and easy to exploit by finding an unexpected implication.

---

## Avoiding Scope Sprawl

Scope sprawl happens when scopes are added ad hoc over years, with no deprecation, resulting in a scope catalogue that nobody fully understands.

Preventions:
- **Require a product justification for every new scope.** "We might need it" is not sufficient.
- **Audit scope usage periodically.** Which scopes are requested by zero active clients? Candidates for deprecation.
- **Don't create scopes for internal use.** Service-to-service tokens use client credentials with roles, not user-delegated scopes.
- **Group related fine-grained scopes under a broader one** when all clients request them together anyway.

```javascript
// Audit: find scopes requested by no active client
const activeScopes = await db.query(`
  SELECT DISTINCT unnest(string_to_array(scope, ' ')) as scope
  FROM access_tokens
  WHERE created_at > NOW() - INTERVAL '90 days'
    AND revoked = false
`);

const definedScopes = Object.keys(SCOPE_DEFINITIONS);
const unusedScopes = definedScopes.filter(s => !activeScopes.has(s));
console.log('Unused scopes (candidates for deprecation):', unusedScopes);
```

---

## Versioning Scopes

APIs evolve. When a scope's meaning changes significantly, versioning prevents breaking existing clients.

```
// Original
posts:write    // create and update posts

// v2 — write now includes publish (breaking change for some clients)
posts:write:v2  // create, update, and publish posts
posts:write     // kept for backward compatibility — create and update only
```

A lighter approach: use a date or version prefix for scopes that are expected to evolve:

```
2024.posts:read
2024.posts:write
```

For most APIs, scope versioning is rarely needed — keep scope definitions stable and additive. When breaking changes are unavoidable, keep the old scope valid with its old semantics and introduce the new one alongside it.

---

## Designing Consent Screens Users Can Understand

The consent screen is where scopes become user-visible. The technical scope name (`posts:write`) must translate into language a non-developer can evaluate.

```javascript
const SCOPE_DISPLAY = {
  'profile:read':  {
    name: 'View your profile',
    description: 'Read your name, email, and profile picture.',
    risk: 'low',
  },
  'posts:write': {
    name: 'Create and edit posts',
    description: 'Create new posts and edit existing ones on your behalf.',
    risk: 'medium',
  },
  'posts:delete': {
    name: 'Delete posts',
    description: 'Permanently delete your posts. This cannot be undone.',
    risk: 'high',
  },
  'billing:write': {
    name: 'Manage your billing',
    description: 'Add, update, or remove payment methods and billing details.',
    risk: 'high',
  },
};
```

Principles for readable consent screens:
- **Plain language, not technical names.** "Read your email address" not `user:email:read`.
- **Explain what will happen**, not just what is permitted.
- **Flag high-risk scopes** visually — colour, icon, or a warning label.
- **Group related scopes** under a single line when possible (`"Read your profile and email"` vs two separate lines).
- **Don't bury the dangerous scopes** in a collapsed list. High-risk permissions should be visible without expanding.

---

## The Minimal Scope Checklist

Before publishing your scope design:

- [ ] Every scope has a human-readable name and description for consent screens
- [ ] Every API endpoint has exactly one (or more) required scopes documented
- [ ] `403 insufficient_scope` responses include the required scope name
- [ ] Read and write operations are split for every resource
- [ ] Sensitive operations (delete, billing, admin) have isolated scopes
- [ ] No scope grants broader access than the user themselves has
- [ ] Scope hierarchy (if any) is documented and tested
- [ ] A deprecation process exists for unused scopes

---

## Further Reading

- [OAuth 2.0 Explained](/blog/oauth2-explained) — the authorisation framework scopes operate within
- [What Is OpenID Connect?](/blog/openid-connect-explained) — standard OIDC scopes (`openid`, `profile`, `email`)
- [RBAC vs ABAC](/blog/rbac-vs-abac) — how scopes relate to the broader authorisation model
- [API Security Checklist](/blog/api-security-checklist) — scope validation as part of API authorisation
