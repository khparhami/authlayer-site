---
title: "The OAuth Back Door: How UNC6395 Entered 700 Organisations Without Triggering MFA"
description: "UNC6395 didn't phish in real time or crack any passwords. They presented OAuth refresh tokens that Drift had already been granted — and walked into Salesforce environments across 700+ organisations. OAuth grants don't expire when employees leave. Attackers know this."
pubDate: 2026-05-07
author: "AuthLayer Team"
tags: ["oauth", "identity", "security", "saas"]
image: "/images/og/oauth-tokens.jpg"
featured: false
---

UNC6395 didn't send a phishing email on the day of the breach. They didn't try to crack any passwords. They didn't trigger an MFA prompt.

They presented an OAuth refresh token — one that Drift, a sales engagement platform, had been granted weeks or months earlier. That token gave them access to Salesforce. Across 700+ organisations.

This is the attack that was detailed this week by researchers tracking the group, and it's a clean illustration of a problem that gets less attention than password theft and phishing: OAuth refresh tokens are persistent, MFA-bypassing credentials, and most organisations have no real-time visibility into them.

## What happened

UNC6395 obtained OAuth refresh tokens — likely through earlier phishing campaigns — that belonged to Drift's integration with Salesforce. Drift, like most sales tools, uses OAuth to connect to Salesforce: a user authorises the connection once, Drift receives a refresh token, and from then on it can request new access tokens on its own without further user interaction.

The attacker's move was precise. Rather than logging in as a user, they used Drift's already-granted token to authenticate directly against Salesforce's API. From Salesforce's perspective, the request came from Drift — a trusted, previously authorised integration. No login event. No MFA challenge. No anomaly in a login audit log.

The scale — 700+ organisations — reflects a structural feature of how OAuth integrations work in multi-tenant SaaS. A single compromised vendor token can mean access across every customer that has granted that vendor OAuth access to their accounts.

## Why OAuth tokens outlive everything

OAuth refresh tokens have two properties that make them dangerous once stolen.

**They don't expire when passwords change.** Changing a user's password revokes their session cookies and forces re-authentication in a browser. It does not revoke OAuth grants. A refresh token issued six months ago is still valid after a password reset.

**They don't expire when the user stops using the app.** If an employee connected a third-party sales tool to their corporate Salesforce, then left the company, the OAuth grant almost certainly still exists. Offboarding checklists ask IT to disable accounts and reclaim devices. They rarely audit which OAuth grants the departing employee created.

These two properties together mean that OAuth tokens are effectively permanent credentials — unless someone explicitly revokes them. And most organisations have no process for that.

## The numbers behind the gap

Research published alongside the UNC6395 disclosures put some numbers to the problem:

- **80%** of security leaders acknowledge unmanaged OAuth grants as a critical risk
- **45%** of organisations do nothing to monitor OAuth grants at scale
- **33%** track OAuth grants via manual spreadsheets

The spreadsheet finding is the most telling. OAuth grants are created continuously — every time an employee clicks through a consent screen, every time an integration is installed, every time a developer authorises a tool against a staging environment that ends up pointing at production. Manual processes can't keep up with the creation rate, let alone track revocations.

## What the attack chain looks like

For defenders, the sequence is worth understanding step by step:

1. Attacker obtains a valid OAuth refresh token for a target integration (via phishing, credential theft from a compromised vendor, or purchasing from an initial access broker)
2. Attacker makes a token refresh request to the identity provider's token endpoint: `POST /oauth/token` with `grant_type=refresh_token`
3. Identity provider returns a fresh access token — the refresh token was valid, no MFA required
4. Attacker uses the access token to call the target application's API (Salesforce, Google Workspace, Microsoft 365, etc.)
5. Application logs show legitimate API calls from a trusted OAuth client — not a login event, not an unusual source IP

From a SIEM perspective, step 4 and 5 look identical to normal application traffic unless you're specifically watching for:

- Token refresh events from unexpected IP ranges
- API call volumes outside baseline for that integration
- Refresh token use after the authorising user's account has been disabled

## What closes the gap

Three controls address this at different layers.

**Audit and age-out OAuth grants continuously.** In most enterprise IdPs, delegated OAuth grants are accessible via API and can be enumerated, attributed to users, and revoked programmatically. Grants older than a defined threshold, grants tied to offboarded users, and grants from unrecognised publishers should be reviewed and revoked on a schedule — not just during quarterly SaaS audits.

```bash
# Microsoft Graph: list all OAuth permission grants in your tenant
GET https://graph.microsoft.com/v1.0/oauth2PermissionGrants
```

```powershell
# Filter for grants with no active principal (e.g. departed users)
Get-MgOauth2PermissionGrant -All |
  Where-Object { -not (Get-MgUser -UserId $_.PrincipalId -ErrorAction SilentlyContinue) }
```

**Treat token refresh events as authentication events.** If your SIEM is ingesting IdP logs, token refresh requests should be treated with the same scrutiny as interactive logins. Refresh from an IP not associated with the authorised application's infrastructure is a signal worth alerting on. Most organisations don't have this detection in place because refresh events are high-volume and considered routine.

**Enforce short-lived access tokens with explicit refresh token expiry.** OAuth access tokens are typically short-lived (1 hour is common). Refresh tokens often aren't — or have their expiry set to values like 90 days or longer. Tighten refresh token expiry for third-party integrations, and consider requiring re-authorisation (which does trigger MFA) for integrations that haven't been used within a defined window.

In Entra ID, token lifetime policies can be scoped per application:

```powershell
New-MgPolicyTokenLifetimePolicy -Definition @(
  '{"TokenLifetimePolicy":{"Version":1,"RefreshTokenMaxInactiveTime":"7.00:00:00"}}'
) -DisplayName "Short refresh - third-party integrations" -IsOrganizationDefault $false
```

## The structural problem

The UNC6395 campaign is notable not because the technique is new — OAuth token theft has been well-documented for years — but because of the scale and the efficiency. The attacker didn't need to run a live phishing operation against each target organisation. They needed one set of valid tokens for one vendor integration. The SaaS supply chain delivered the rest.

This is the same structural vulnerability that sits behind the Vercel/shadow AI breach, the Okta support system compromise, and most of the high-profile SaaS identity incidents of the past two years. The perimeter being crossed isn't a VPN or a firewall. It's an OAuth consent screen that someone clicked through eight months ago and nobody has looked at since.

The defence is unglamorous: know what OAuth grants exist in your environment, attribute them to active users, verify the scopes are still appropriate, and revoke anything that can't be justified. It doesn't require new tooling. It requires treating OAuth grants the way you'd treat service account credentials — as persistent, high-value access that needs to be inventoried and governed.

---

*UNC6395 indicators of compromise and the Drift token analysis are available via Mandiant. Token lifecycle policy documentation for Entra ID is available in the Microsoft identity platform docs.*
