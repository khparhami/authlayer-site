---
title: "OAuth Sprawl: How Shadow AI Apps Become Attack Vectors"
description: "The Vercel breach shows how a single unapproved OAuth connection to an AI tool became a full internal compromise. OAuth tokens are persistent, programmatic, and invisible to most security teams — and attackers know it."
pubDate: 2026-04-30
author: "AuthLayer Team"
tags: ["oauth", "security", "identity", "saas", "ai"]
featured: false
---

A Vercel employee connected an AI productivity suite to their Google Workspace account without company approval. That tool got compromised. Attackers walked in through the OAuth token it held and reached internal dashboards, employee records, API keys, NPM tokens, and GitHub tokens. The employee hadn't touched the AI app in months. The OAuth connection was still alive.

This is the Vercel breach, and it's a clean illustration of a problem that's been building for years: OAuth sprawl.

## What OAuth sprawl actually means

Most security teams have a reasonable handle on their first-party OAuth integrations — the Salesforce connected to Workday, the GitHub App connected to CI. What they don't have is visibility into what individual employees have connected to their work accounts from the outside.

Every time someone clicks "Sign in with Google" on a new SaaS tool, or clicks through an OAuth consent screen to let an AI assistant read their calendar and email, they're creating a persistent, programmatic bridge between a third-party system and your identity provider. That bridge survives:

- The employee losing interest in the app
- The app going through an acquisition or change in ownership
- The app's own security incident

The OAuth token doesn't expire when the employee stops using the tool. It doesn't get revoked when the company's security team runs their quarterly SaaS audit. It sits there, silently granting access, waiting.

## The four categories of shadow AI

The Vercel incident sits in a wider taxonomy of risk that's been called "shadow AI" — a category that goes beyond the classic "shadow IT" concept because AI tools uniquely require broad OAuth access to be useful.

**Shadow apps** are unapproved SaaS tools employees use with corporate accounts. An AI writing tool that needs to read your documents. A meeting summarizer that needs to access your calendar and video calls. Each requires OAuth access to function.

**Shadow tenants** happen when employees create personal-account access to enterprise systems — signing into Microsoft 365 or Google Workspace with a personal account and then connecting external apps to that. The IT team can't see it; the OAuth grants live under a personal account that falls outside your IdP's visibility.

**Shadow extensions** are browser extensions with permissions to read page content, intercept network requests, or access cookies. Many are legitimate. Some aren't. All of them run with the same permissions as the browser session, which includes whatever you're authenticated to.

**Shadow integrations** are the Vercel case: an unapproved OAuth connection from a managed corporate account to a third-party service. The employee is using a corporate identity to authenticate; the company just doesn't know the connection was made.

## Why this matters more now than it did two years ago

AI tools have made this worse in a specific way. Legacy SaaS tools often asked for fairly narrow OAuth scopes — access to your files, or access to your calendar, but not both. AI productivity suites want everything: email, calendar, documents, contacts, and sometimes the ability to send and write on your behalf. They're useful precisely because they have broad context. That broad context is also exactly what makes a compromised OAuth token dangerous.

The numbers back this up. Device code phishing — an attack technique that exploits OAuth's device authorization flow to steal tokens — increased 37x year-over-year, according to recent tracking data. Attackers have noticed that OAuth tokens are a reliable path in that bypasses MFA entirely. You're not stealing a password. You're stealing a long-lived token that was already authenticated with MFA.

## How the attack works in practice

The Vercel breach followed a pattern that's becoming more common:

1. Employee installs an AI tool for personal or work use
2. Tool requests OAuth access to Google Workspace; employee consents
3. Tool stores the OAuth refresh token in its own database
4. Tool is compromised — in this case, through an infostealer infection at the tool vendor
5. Attacker extracts stored OAuth tokens
6. Attacker uses the token to access the target's Google Workspace account
7. From there: internal dashboards, API keys, tokens for downstream systems

Step 6 doesn't require the victim's password. It doesn't trigger an MFA challenge. The attacker is presenting a valid OAuth token — the server sees a legitimate, previously-authorized access request and responds accordingly.

This is also why employee offboarding is often less clean than it looks. Even if you revoke the employee's account, any OAuth tokens granted from that account to external systems should be explicitly revoked — otherwise they may continue to function against whatever the token was scoped to.

## What a compromised OAuth token can access

It depends on the scopes granted. Google OAuth scopes are granular; the problem is that users rarely read them before clicking "Allow," and AI tools typically request the broadest scopes they can justify.

Common scopes that AI tools request and that make compromised tokens dangerous:

| Scope | What an attacker gets |
|---|---|
| `gmail.readonly` | Full read access to the victim's email — including password reset emails, 2FA codes, internal comms |
| `drive.readonly` | All files in Google Drive — documents, spreadsheets, credentials stored in docs |
| `calendar.readonly` | Calendar events, meeting details, attendee lists — useful for social engineering |
| `gmail.send` | Ability to send email as the victim — spearphishing from a trusted address |
| `drive.file` | Read/write access to files the app has previously opened |

A token with `gmail.readonly` and `drive.readonly` is enough to map out most of an organization's sensitive data if the victim is a developer or IT administrator.

## What to do

**Audit existing OAuth grants.** This is the first priority and harder than it sounds. For Google Workspace, you can see connected apps in the admin console under Security > API controls > App access control. For Microsoft 365, it's in Entra ID under Enterprise Applications. Export and review what's there — you'll find apps that haven't been used in years still holding active grants.

```bash
# Pull OAuth grants from Entra ID via Microsoft Graph
# Requires Global Reader or Application Administrator role
curl -H "Authorization: Bearer $TOKEN" \
  "https://graph.microsoft.com/v1.0/servicePrincipals?$filter=tags/any(t:t eq 'WindowsAzureActiveDirectoryIntegratedApp')&$select=displayName,appId,oauth2PermissionScopes"
```

**Set a default-deny OAuth consent policy.** Both Google Workspace and Microsoft 365 allow you to require admin approval before a user can grant OAuth access to a new application. This breaks the "click Allow and move on" pattern that leads to sprawl.

In Microsoft Entra, this is under: Entra admin centre > Enterprise applications > Consent and permissions > User consent settings. Set it to "Do not allow user consent." Yes, this will generate support tickets. The security trade-off is worth it.

In Google Workspace: Admin console > Security > API controls > Third-party app access. Set "Google Services" to "Restricted" and manage the allowlist explicitly.

**Enable OAuth token revocation as part of offboarding.** Don't just disable the account. For every employee departure, run a process that explicitly revokes all OAuth grants from their managed account. Google Workspace and Microsoft 365 both support this via API and admin console.

**Monitor for unusual OAuth grant events.** New OAuth grants — especially to apps that haven't been seen before — should trigger a review. Google Workspace audit logs include OAuth grant events in the Token audit log. Microsoft Entra logs these in the Audit log under "Add OAuth 2.0 permission grant."

```kusto
// Microsoft Sentinel: alert on new OAuth grants to unknown applications
AuditLogs
| where OperationName == "Add OAuth 2.0 permission grant"
| where Result == "success"
| extend AppName = tostring(TargetResources[0].displayName)
| where AppName !in~ (KnownApprovedApps)
| project TimeGenerated, AppName, InitiatedBy, TargetResources
```

**Address device code phishing specifically.** If your users don't authenticate to devices that use the device code flow (printers, smart TVs, limited-input devices), block it entirely. In Entra Conditional Access, you can block the "Device code flow" authentication method for all users. This eliminates one of the primary techniques attackers are using to harvest OAuth tokens at scale.

## The structural problem

OAuth was designed for delegated authorization — letting users grant third-party apps controlled access to their data. The assumption baked into that design is that users will make informed choices about what they grant and that they'll revoke grants they no longer need.

Neither assumption held up at enterprise scale. Users click through consent screens. Grants accumulate. Tools get acquired and change ownership. The employee who granted access leaves, and the grant stays.

The AI wave has accelerated this because AI tools are genuinely useful when they have broad access. The incentive to grant broad OAuth consent is higher than it's ever been, right at the moment when the supply chain risk attached to AI vendors is also higher than it's ever been.

Treating every OAuth grant as a persistent credential — with all the lifecycle management that implies — is the right mental model. Audit them like you audit service account credentials. Revoke them when they're no longer needed. Approve new ones through a deliberate process, not a user consent screen.

The Vercel case is a clean example because the attacker path was short and the impact was visible. Most of the time, these tokens sit quietly in vendor databases, waiting for a breach that may or may not be disclosed. You can't wait for disclosure. You need the inventory now.
