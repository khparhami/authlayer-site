---
title: "The Entra ID Role Flaw That Let You Hijack Service Principals"
description: "Microsoft just patched an Entra ID privilege escalation bug that allowed low-privileged roles to take over service principals. Here's what broke and why it keeps breaking."
pubDate: 2026-04-29
author: "AuthLayer Team"
tags: ["security", "azure", "identity", "vulnerabilities"]
image: "/images/og/entra.jpg"
featured: false
---

Microsoft quietly patched an Entra ID vulnerability this week that let attackers escalate into service principal ownership from a role that had no business having that access. It's fixed now. But the class of bug it represents? That one's not going anywhere.

## What broke

Entra ID's role-based access model has a long tail of implicit permissions that aren't documented anywhere obvious. A lower-privileged role — something that looks harmless on paper — could be used to modify service principal properties in a way that effectively handed over ownership.

Service principals are the machine identities in Azure. They're how your CI/CD pipeline authenticates to Azure resources, how your app talks to the Microsoft Graph API, how your automation scripts run without a human in the loop. If I can take over your service principal, I can do anything it could do — read secrets from Key Vault, call APIs, access storage, pivot through your environment. The blast radius depends on what the service principal was permissioned to do. In most tenants I've seen, that's quite a lot.

The specifics of the flaw come down to how Entra evaluates role permissions during certain service principal update operations. The guard wasn't checking what it needed to check. A role that should have been read-only wasn't read-only in all contexts.

## Why this keeps happening in cloud identity systems

Cloud IAM systems are genuinely hard to reason about. Entra ID has hundreds of built-in roles. Each role is a set of allowed actions expressed as permission strings like `microsoft.directory/servicePrincipals/credentials/update`. The problem is that these permissions interact with each other in non-obvious ways, and the documentation often lags behind what the API actually enforces.

I've seen this pattern in AWS IAM too — a policy that looks innocuous until you chain it with another permission that gives you `iam:PassRole` or `sts:AssumeRole`. The individual permission looks fine. The combination is a full privilege escalation path.

In Entra, the equivalent is a role that can update service principal properties combined with an operation that doesn't re-check the owner. You don't need every piece; you just need the right piece.

## The specific risk with service principals

Here's what makes service principal takeover worse than a lot of other escalation paths: service principals are often over-permissioned, long-lived, and under-monitored.

Credentials (client secrets and certificates) on service principals don't expire by default unless you configure them to. They don't trigger MFA. They don't show up in user sign-in logs the same way human accounts do. Conditional Access policies frequently exclude service principals entirely because enforcing them for machine identities requires careful policy design that most teams haven't done.

So if an attacker adds a credential to a service principal, they can authenticate as that principal silently, indefinitely, from anywhere. No suspicious human login to detect. No MFA prompt to block. Just an app authenticating with a client secret like normal.

## What to do right now

Patch first — if you're on an affected version, apply the update. Then do this:

**Audit service principal credential age.** Run this in the Entra admin centre or via PowerShell to find service principals with credentials older than 90 days. Anything older than a year with Owner-level permissions should be investigated.

```powershell
Get-MgServicePrincipal -All | ForEach-Object {
  $sp = $_
  Get-MgServicePrincipalPasswordCredential -ServicePrincipalId $sp.Id |
  Where-Object { $_.EndDateTime -lt (Get-Date).AddDays(90) } |
  Select-Object @{n='DisplayName';e={$sp.DisplayName}}, StartDateTime, EndDateTime
}
```

**Review who has Application Administrator and Cloud Application Administrator roles.** These roles can add credentials to any service principal in the tenant. If you have 40 people in Application Administrator, that's 40 potential blast radius owners for any service principal credential they could touch.

**Enable Entra ID workload identity logs.** Service principal sign-ins are in the `ServicePrincipalSignInLogs` table in Log Analytics. Most teams have this disabled or aren't alerting on it. An attacker adding a new credential and then authenticating from an unusual IP should be detectable — if you're looking.

**Set credential expiry policies.** Entra now supports [application authentication method policies](https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/configure-app-instance-property-lock) that enforce maximum credential lifetimes. Turn this on. A secret that expires in 90 days does a lot to limit dwell time.

## The bigger picture

This vulnerability is a symptom of a structural problem. Cloud identity systems have accreted permissions and roles over years of feature additions, and the security model of "here's a list of allowed actions" doesn't give you a clean way to reason about what combinations of those actions could do.

Zero-standing-access models — where service principals request just-in-time elevated permissions rather than holding them permanently — are the right long-term direction. Products like Entra PIM for workload identities are moving this way. But adoption is slow because it requires rethinking how your automation is written.

Until then: audit your service principals, monitor their sign-in logs, and assume that any principal with credentials older than six months has been compromised and work backwards from there. It's not paranoia. It's just what the threat model requires.
