---
title: "RBAC vs ABAC: Choosing the Right Access Control Model"
description: "Role-Based and Attribute-Based Access Control solve authorisation differently. Learn how each works, where each breaks down, and the hybrid patterns most production systems actually use."
pubDate: 2026-06-03
author: "Khashayar Parhami"
tags: ["security", "guide", "identity"]
image: "/images/og/rbac-vs-abac.png"
featured: false
---

Authorisation — deciding what an authenticated user is allowed to do — is where most systems quietly get it wrong. The data model is usually straightforward; the access control model rarely is. RBAC and ABAC are the two dominant approaches, and the choice between them shapes how your system scales, how easy it is to audit, and how precisely you can express real-world policy.

## Role-Based Access Control (RBAC)

RBAC assigns permissions to roles, then assigns roles to users. Access is determined by what roles a user holds.

```
User → Roles → Permissions → Resources
```

A concrete example:

```
Roles:      viewer, editor, admin
Permissions: read:reports, write:reports, delete:reports, manage:users

viewer  → [read:reports]
editor  → [read:reports, write:reports]
admin   → [read:reports, write:reports, delete:reports, manage:users]

alice (admin) → can do everything
bob (viewer)  → can only read reports
```

Checking access at runtime is a simple lookup:

```javascript
function canAccess(user, permission) {
  return user.roles.some(role => ROLE_PERMISSIONS[role].includes(permission));
}

if (!canAccess(req.user, 'write:reports')) {
  return res.status(403).json({ error: 'Forbidden' });
}
```

### Where RBAC works well

RBAC is the right default for most applications. It's easy to reason about, easy to audit ("what can admins do?"), and easy to implement. Role assignments fit naturally into admin UIs, and most team structures map cleanly to a role hierarchy.

It works especially well when:
- User permissions follow a predictable hierarchy (viewer < editor < admin)
- Access rules don't depend heavily on context or data attributes
- You need to answer "what can this role do?" in an audit

### Where RBAC breaks down

RBAC struggles when permissions need to be contextual. Consider these requirements that RBAC cannot express cleanly:

- A user can edit their *own* reports but not others'
- Managers can approve expenses *only for their department*
- Documents marked "confidential" can only be read by users with clearance level ≥ 3
- Access is only permitted during business hours from corporate IP ranges

You can hack around these with fine-grained roles (`editor:own`, `editor:dept-finance`) but role explosion follows quickly. A system with 50 resource types and 10 contextual dimensions becomes unmaintainable.

---

## Attribute-Based Access Control (ABAC)

ABAC evaluates access based on attributes — properties of the user, the resource, the action, and the environment — against a policy.

```
Policy: ALLOW if
  user.department == resource.department
  AND user.clearance >= resource.sensitivity
  AND environment.time is BUSINESS_HOURS
  AND action == 'read'
```

The four attribute categories:

| Category | Examples |
|---|---|
| **Subject** (user) | `department`, `clearance`, `location`, `employment_type` |
| **Resource** | `owner`, `sensitivity`, `department`, `created_at` |
| **Action** | `read`, `write`, `delete`, `approve` |
| **Environment** | `time`, `ip_address`, `device_trust`, `geo` |

A policy engine evaluates rules against these attributes at request time:

```javascript
function evaluate(policy, context) {
  const { user, resource, action, environment } = context;

  return policy.rules.every(rule => {
    switch (rule.type) {
      case 'user_attr':   return user[rule.attr] === rule.value;
      case 'resource_attr': return resource[rule.attr] === rule.value;
      case 'comparison':  return user[rule.attr] >= resource[rule.attr];
      default: return false;
    }
  });
}

const allowed = evaluate(documentReadPolicy, {
  user: { department: 'finance', clearance: 3 },
  resource: { department: 'finance', sensitivity: 2 },
  action: 'read',
  environment: { hour: 14, ip: '10.0.0.1' },
});
```

### Where ABAC works well

ABAC shines when access rules are contextual, data-driven, or dynamic:

- Multi-tenant SaaS where users can only access their own organisation's data
- Healthcare systems where access depends on patient-provider relationships
- Financial platforms where trade access depends on trader certifications and asset class
- Zero-trust environments where device posture and network context affect access

ABAC also scales better than RBAC as complexity grows. Adding a new attribute (`user.contractor = true`) and a new policy clause is cleaner than adding a new role and reassigning users.

### Where ABAC breaks down

ABAC policies can become hard to understand and audit. "What can Alice do?" requires evaluating every policy with Alice's current attribute set — there's no simple role list to read. Policy sprawl is real.

ABAC also requires attribute infrastructure: something must provide `user.department`, `resource.sensitivity`, and `environment.ip` at evaluation time. That data pipeline needs to exist and be authoritative.

---

## Side-by-Side Comparison

| Dimension | RBAC | ABAC |
|---|---|---|
| Decision basis | User's role membership | Attribute evaluation against policy |
| Contextual access | Limited | Native |
| Implementation complexity | Low | High |
| Auditability | High — roles are explicit | Lower — requires policy + attribute inspection |
| Scales with resource types | Poorly (role explosion) | Well |
| Scales with user count | Well | Well |
| Runtime performance | Fast (role lookup) | Slower (policy evaluation) |
| Tooling maturity | Broad | Growing (OPA, Cedar, Casbin) |
| Best for | Standard permission hierarchies | Fine-grained, contextual policy |

---

## The Hybrid Pattern

Most real systems use both. RBAC handles coarse-grained access; ABAC handles fine-grained rules within those boundaries.

A typical layered approach:

```
1. RBAC gate: does this user's role permit this action at all?
   → viewer cannot call DELETE /documents/:id regardless of attributes

2. ABAC gate: given that the role permits it, do the contextual rules allow it?
   → editor can only DELETE documents they own, in their department,
     and only if the document is not in "approved" state
```

```javascript
async function authorise(user, action, resource, environment) {
  // Layer 1: RBAC — coarse check
  if (!hasRolePermission(user.roles, action)) {
    return { allowed: false, reason: 'insufficient_role' };
  }

  // Layer 2: ABAC — fine-grained contextual check
  const policy = await policyStore.get(action, resource.type);
  const allowed = evaluatePolicy(policy, { user, resource, action, environment });

  return { allowed, reason: allowed ? null : 'policy_denied' };
}
```

This pattern keeps the simple cases fast (most requests are denied at the RBAC layer before touching policy evaluation) while enabling precise rules where they're needed.

---

## Policy Engines Worth Knowing

If you're building ABAC at any scale, reach for a dedicated policy engine rather than hand-rolling evaluation logic.

**[Open Policy Agent (OPA)](https://www.openpolicyagent.org/)** — CNCF project, language-agnostic, uses the Rego policy language. Widely adopted for Kubernetes admission control and API authorisation. Runs as a sidecar or embedded library.

**[Cedar](https://www.cedarpolicy.com/)** — open-sourced by AWS, used in Amazon Verified Permissions. Formally verified, designed for application authorisation. Policy-as-data with a readable syntax.

**[Casbin](https://casbin.org/)** — supports RBAC, ABAC, and hybrid models in a unified framework. Libraries for most languages, model defined in config files.

---

## Choosing Between Them

A few questions to guide the decision:

**Can your access rules be expressed as "role X can do action Y on resource type Z"?** If yes with minimal exceptions, RBAC is sufficient and simpler.

**Do permissions depend on the relationship between the user and the specific resource?** If a user can edit *their own* items but not others', you need at minimum object-level RBAC (scoped roles) or ABAC.

**Do environmental factors affect access?** Time of day, device trust level, IP range, geolocation — these are ABAC attributes. RBAC cannot express them.

**How important is auditability?** If you regularly need to answer "who has access to what?", RBAC's explicit role assignments are much easier to reason about and report on.

**Are you building B2B SaaS?** Each tenant likely needs its own permission model. ABAC with a tenant attribute is cleaner than managing per-tenant role sets.

---

## Further Reading

- [API Security Checklist](/blog/api-security-checklist) — authorisation controls for APIs in production
- [What Is OpenID Connect?](/blog/openid-connect-explained) — how identity claims flow into authorisation decisions
- [OAuth 2.0 Explained](/blog/oauth2-explained) — scopes as a lightweight RBAC layer
