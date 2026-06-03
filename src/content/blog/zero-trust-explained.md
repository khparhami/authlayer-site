---
title: "Zero Trust Architecture: A Practical Primer"
description: "Zero trust replaces perimeter-based security with identity-aware, continuously verified access. Learn what it actually means in practice — identity, device posture, micro-segmentation, continuous authorisation, and how to implement it without boiling the ocean."
pubDate: 2026-06-03
author: "Khashayar Parhami"
tags: ["security", "guide", "identity"]
image: "/images/og/zero-trust-explained.png"
featured: false
---

"Zero trust" is one of the most overloaded terms in security. Vendors apply it to everything from VPN replacements to firewall rules. Compliance frameworks cite it. Job descriptions require it. Very few documents explain what it actually means in a running system, what problems it solves, and how to implement it without a multi-year transformation programme.

This guide cuts through the marketing and describes zero trust as an architectural principle — what changes, why it matters, and what concrete controls it implies.

## The Problem with Perimeter Security

Traditional network security is built on a perimeter model: draw a boundary around your infrastructure, trust everything inside it, and block everything outside.

```
Internet (untrusted)
        │
    ┌───▼──────────────────────────────────┐
    │  Firewall / VPN                      │
    │                                      │
    │  ┌──────────┐  ┌──────────────────┐  │
    │  │ Corp     │  │ Production       │  │
    │  │ Network  │  │ Servers          │  │
    │  └──────────┘  └──────────────────┘  │
    │                                      │
    │  "Trusted" — anything in here        │
    │  can talk to anything else           │
    └──────────────────────────────────────┘
```

This model made sense when:
- All employees worked in the office on corporate hardware
- All applications ran in your data centre
- The perimeter was a physical building and a known IP range

None of those assumptions hold today. Employees work from home, cafés, and airports. Applications run in multiple clouds, SaaS services, and third-party environments. Contractors and partners need access. Mobile devices and personal laptops connect to corporate systems. The perimeter dissolved.

The deeper problem: once an attacker is inside the perimeter — via phishing, a compromised device, a malicious contractor, or a supply chain attack — they move freely. Internal traffic is trusted by default. Lateral movement is easy. The 2023 MGM breach, the SolarWinds compromise, and dozens of others followed exactly this pattern: get past the perimeter once, then move laterally at will.

## The Zero Trust Principle

Zero trust replaces implicit trust with explicit, continuous verification:

> **Never trust, always verify — regardless of network location.**

An employee on the corporate network gets the same level of trust as an employee on public Wi-Fi: none by default. Access is granted based on verified identity, device health, and the specific resource being requested — evaluated at the time of each access, not at network connection time.

Three foundational assertions:

1. **The network is hostile.** Treat all network traffic — internal and external — as potentially hostile. Encrypt everything. Verify everything.
2. **Identity is the perimeter.** The boundary is no longer a network edge. It's the verified identity of the user or service requesting access.
3. **Least privilege, always.** Every user and service gets access only to the specific resources they need, for the minimum time required.

## The Five Pillars

Zero trust is not a single product. It's a set of controls across five domains:

### 1. Identity

Every access request must be authenticated and the identity verified — not just at login, but continuously throughout the session.

- Strong authentication (MFA, passwordless) for every user
- Machine identities (service accounts, workloads) verified via certificates or service tokens
- Identity provider as the authoritative source of truth — not network location
- Short-lived sessions with continuous re-evaluation

```
Access decision = f(who you are, not where you are)
```

### 2. Device

A verified identity on a compromised device is still a risk. Device posture checks enforce that the device meets security requirements before access is granted.

Checks typically include:
- OS version and patch level
- Disk encryption enabled
- Endpoint detection and response (EDR) agent running
- No known malware or policy violations
- Corporate-managed vs personal device distinction

```javascript
// Access policy evaluation — identity + device
function evaluateAccess(identity, device, resource) {
  if (!identity.mfaVerified) return { granted: false, reason: 'mfa_required' };
  if (!device.encrypted) return { granted: false, reason: 'device_not_encrypted' };
  if (device.osVersion < resource.minOsVersion) return { granted: false, reason: 'os_out_of_date' };
  if (device.managedByOrg === false && resource.requiresManagedDevice) {
    return { granted: false, reason: 'unmanaged_device' };
  }
  return { granted: true };
}
```

### 3. Network

Micro-segmentation replaces flat internal networks with fine-grained segments where services can only communicate with explicitly permitted peers.

In a flat network, a compromised service can make requests to any other internal service. With micro-segmentation:

```
Before (flat):
  payments-service → can reach user-service, orders-service,
                     admin-service, database, everything

After (micro-segmented):
  payments-service → can reach ONLY: orders-service (port 443),
                                     payments-db (port 5432)
                     All other connections: denied by default
```

This is enforced at the network layer (security groups, firewall rules, network policies in Kubernetes) and increasingly at the application layer via mutual TLS and service meshes.

### 4. Applications

Applications are not trusted because they're running "inside" the infrastructure. Each application:

- Requires authentication and authorisation for every request
- Receives only the permissions it explicitly needs
- Has its own identity (service account, certificate) used for all outbound calls
- Logs all access for audit

Application-level zero trust often means moving away from "allow all internal traffic" rules and requiring service-to-service authentication even for internal APIs. See [Service-to-Service Authentication](/blog/service-to-service-auth) for implementation patterns.

### 5. Data

Data is classified by sensitivity, and access policies are enforced at the data level — not just at the application or network level.

- Data classification (public, internal, confidential, restricted)
- Encryption at rest and in transit for all sensitive data
- Data loss prevention (DLP) controls on exfiltration paths
- Audit logging on data access, especially for sensitive records

## Continuous Authorisation

Traditional systems authorise at login: you authenticate once, receive a session, and that session lasts until it expires. Zero trust shifts toward **continuous authorisation** — access decisions are re-evaluated throughout the session, not just at its start.

What can trigger re-evaluation:
- User moves to a new network (office → home)
- Device posture changes (VPN disconnects, patch falls behind, malware detected)
- Time passes (step-up authentication for sensitive operations)
- Unusual behaviour pattern detected (location change, new device, off-hours access)
- Resource sensitivity increases (accessing financial records vs reading public docs)

```
Initial auth:
  alice logs in, MFA verified, device clean → session token issued

Mid-session re-evaluation:
  alice attempts to export 50,000 customer records
  → risk score elevated
  → step-up authentication required before proceeding
  → action logged and flagged for review
```

This is distinct from just having short session timeouts. It's context-aware access that responds to changes in risk posture in real time.

## The Policy Engine

Zero trust requires a policy engine that can evaluate "should this principal access this resource right now?" against all available signals. This is sometimes called a **Policy Decision Point (PDP)**.

Inputs to the decision:
- User identity and attributes (role, department, clearance)
- Device posture (managed, encrypted, patched)
- Resource classification (sensitivity, owner, data type)
- Network context (IP, location, VPN status)
- Time and behaviour (business hours, access history)
- Threat intelligence (known bad IPs, compromised accounts)

```javascript
async function authorise(request) {
  const [identity, device, resource, threat] = await Promise.all([
    identityService.verify(request.token),
    deviceService.getPosture(request.deviceId),
    resourceService.classify(request.resourceId),
    threatIntel.check(request.ip, request.userId),
  ]);

  // Block if threat intelligence flagged this user or IP
  if (threat.flagged) return deny('threat_detected');

  // Require managed device for confidential resources
  if (resource.sensitivity === 'confidential' && !device.managed) {
    return deny('unmanaged_device');
  }

  // Require recent MFA for sensitive operations
  if (resource.sensitivity === 'restricted' && identity.mfaAge > 300) {
    return stepUp('mfa_required');
  }

  // RBAC check
  if (!hasPermission(identity.roles, request.action, resource.type)) {
    return deny('insufficient_permission');
  }

  return allow();
}
```

## Implementing Zero Trust Without Boiling the Ocean

A full zero trust architecture is a multi-year effort. The key is sequencing — prioritise the controls that reduce the most risk first.

### Phase 1 — Identity first (immediate impact)

The highest-leverage starting point: enforce strong authentication everywhere.

- Enforce MFA for all users, all applications
- Eliminate shared accounts and service accounts with user passwords
- Implement SSO so authentication is centralised and auditable
- Enforce short-lived sessions (8-hour max, re-auth for sensitive operations)
- Audit and remove stale accounts and excessive permissions

This alone addresses the majority of credential-based attacks. Most breaches start with compromised credentials — if MFA is enforced everywhere, the blast radius shrinks dramatically.

### Phase 2 — Device visibility

- Deploy MDM (Mobile Device Management) for corporate devices
- Enforce device posture checks before granting access to sensitive applications
- Differentiate access policies between managed and unmanaged devices
- Implement endpoint detection and response (EDR)

### Phase 3 — Network segmentation

- Audit what services can reach what — most teams are surprised by how open internal networks are
- Apply micro-segmentation to the highest-risk service groups first (payment systems, identity infrastructure, admin interfaces)
- Require service-to-service authentication with mTLS or service JWTs
- Move toward a service mesh for automatic mTLS in Kubernetes environments

### Phase 4 — Continuous evaluation

- Implement risk-based step-up authentication
- Add behavioural anomaly detection to your identity platform
- Build data classification into your access policies
- Implement session revocation that propagates to all systems in real time

## Common Misconceptions

**"Zero trust means no trust."** It means no *implicit* trust based on network location. Trust is earned through verified identity and enforced through policy, not eliminated.

**"Zero trust is a product."** No single product implements zero trust. It's an architectural approach that requires changes to identity, network, device management, and application layers. Vendors selling "zero trust" are selling components, not the whole.

**"Zero trust requires ripping everything out."** Incremental adoption is the standard. Start with identity (MFA, SSO), add device posture, then work through network segmentation. Each phase delivers value independently.

**"Zero trust means no VPN."** VPNs can coexist with zero trust. Zero trust challenges the *assumption of trust* that VPNs grant, not the encrypted tunnels themselves. Some organisations replace VPNs with identity-aware proxies (BeyondCorp-style access); others keep VPNs and layer zero trust controls on top.

## Further Reading

- [RBAC vs ABAC](/blog/rbac-vs-abac) — the authorisation models that power zero trust policy decisions
- [Service-to-Service Authentication](/blog/service-to-service-auth) — mTLS and service identity inside a zero trust network
- [MFA Complete Guide](/blog/mfa-complete-guide) — the identity verification layer zero trust depends on
- [API Security Checklist](/blog/api-security-checklist) — application-layer controls that complement network zero trust
