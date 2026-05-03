---
title: "Vishing + AiTM: How a Phone Call Is Bypassing Your SSO and MFA"
description: "Two cybercrime groups are combining voice phishing with adversary-in-the-middle proxies to steal SSO session tokens after MFA completes — and then running rapid SaaS extortion. Here's the exact attack chain and what actually stops it."
pubDate: 2026-05-04
author: "AuthLayer Team"
tags: ["phishing", "mfa", "identity", "sso"]
image: "/images/og/vishing.jpg"
featured: false
---

Two cybercrime clusters tracked by CrowdStrike are running a campaign that combines voice phishing with adversary-in-the-middle proxies to harvest SSO session tokens — and then moving through SaaS environments fast enough to exfiltrate and extort before most security teams know they're in.

The technique isn't new. The scale and speed are.

## The attack chain

It starts with a phone call. Not a robocall — a live person, speaking confidently, claiming to be from IT, the help desk, or security. The caller tells the target they need to re-authenticate urgently: suspicious activity on their account, a compliance audit, a required system migration. Whatever framing fits the target's context.

The caller directs the victim to a URL. The page looks exactly like the company's SSO login portal — same branding, same URL structure if the attacker registered a convincing lookalike domain. It is, in fact, a transparent proxy sitting between the victim and the real identity provider.

When the victim enters their credentials, the proxy forwards them to the real IdP and relays the challenge back in real time. The victim receives their MFA prompt — a TOTP code, a push notification, an SMS — and completes it normally. The proxy captures the resulting session token.

This is what makes it different from traditional phishing. The attacker doesn't need your password or your MFA code after the fact. They need the authenticated session token that your IdP issues after you prove both factors. The proxy gets it in the same moment you do.

## Why MFA doesn't protect against this

Most MFA implementations are protecting the wrong thing. TOTP codes, SMS OTPs, and push notifications prove that the person authenticating possesses a second factor. They do not prove that the person is authenticating to a legitimate endpoint.

An AiTM proxy exploits this gap. The victim successfully completes a legitimate authentication ceremony — they really did enter their password, they really did approve the MFA push. The token that gets issued is a real, valid session token. The proxy just intercepted it in transit.

This is why it's more accurate to call this session hijacking than phishing. The attacker isn't replaying stolen credentials later. They're sitting in the middle of a live authentication and stealing the session at the moment it's created.

Push notification fatigue attacks — where attackers spam MFA pushes until someone approves — have the same class of problem but are noisier. AiTM via vishing is quieter: one authentication event, one captured session, no anomalous login pattern.

## The SSO factor

Single sign-on amplifies the impact. In a well-configured SSO environment, one authenticated session can access dozens of downstream applications — email, file storage, project management, HR systems, financial tools. An attacker who captures the SSO session token doesn't need to compromise each application separately. The IdP session is the skeleton key.

The vishing component solves the detection problem that pure AiTM phishing emails face. Security gateways scan for lookalike domains in email links. An urgent phone call from a convincing "IT help desk" caller bypasses email filtering entirely. The link gets delivered verbally or via SMS from a spoofed number.

CrowdStrike's reporting on recent campaigns notes that these groups move quickly post-compromise. Dwell time before data exfiltration is measured in hours, not days. The SaaS extortion model — download SharePoint, OneDrive, or email archives, then threaten to leak — doesn't require persistence or lateral movement. The attacker logs in, downloads, logs out, and sends a ransom demand.

## What the targeted environments look like

These attacks consistently target organizations with:

- **Okta or Azure AD / Entra ID as the IdP** — widely used, well-documented, attackers know the UI
- **Heavy SaaS footprint** — Microsoft 365, Google Workspace, Salesforce, Box, Confluence
- **IT help desk processes with low verification requirements** — password resets done over phone without strong identity proofing
- **SMS or push MFA** — susceptible to interception by AiTM proxies

Organizations that use hardware security keys (FIDO2/WebAuthn) for all users are significantly harder to attack via this method. The technical reason matters: FIDO2 authentication is origin-bound. The credential proves possession of a key tied to a specific domain. An AiTM proxy at `secure-okta-login.com` cannot satisfy an authentication request for `yourcompany.okta.com` — the cryptographic binding breaks the proxy model entirely.

## Defences that work

**Deploy phishing-resistant MFA.** FIDO2/WebAuthn security keys (YubiKey, Google Titan) and device-bound passkeys are the only MFA methods that break the AiTM attack class. They are domain-bound by design — the authenticator signs a challenge that includes the origin, so a proxy at a different domain cannot relay the authentication successfully. This is the only control that addresses the root cause rather than the symptoms.

TOTP, SMS, and push MFA do not protect against AiTM. Implementing number matching on push notifications raises the bar slightly — it requires the attacker's proxy to display the correct number to the victim in real time, which is possible but adds friction. It is not a substitute for domain-bound MFA.

**Enable Continuous Access Evaluation.** Microsoft and Google both support token binding and continuous evaluation that can detect session anomalies post-issuance. In Microsoft Entra, Continuous Access Evaluation (CAE) can revoke tokens near-instantly when conditions change — including when the sign-in IP changes significantly. Enable it.

```
Entra admin centre → Identity → Overview → Continuous Access Evaluation → Enable
```

**Require re-authentication for sensitive operations.** Even if an attacker captures a session token, Conditional Access policies that require fresh authentication for high-value operations (accessing specific SharePoint sites, bulk downloads, email export) add friction that buys detection time.

**Harden help desk processes.** The vishing component is the enabler. IT help desks that will process account changes based on a caller identifying themselves by name and employee ID are the entry point. Effective controls:

- Out-of-band callback to the employee's known number before any account change
- Manager approval for account recovery requests
- Hardware key verification for password resets where possible
- Recorded acknowledgement that staff will never be asked to authenticate to a link provided over phone

**Deploy token anomaly detection.** A legitimate user doesn't usually use their SSO session from a different IP, ASN, or country within minutes of authentication. These events are detectable:

```kusto
// Entra ID — flag sign-ins where session IP differs from authentication IP
SigninLogs
| where TimeGenerated > ago(1h)
| extend authIP = IPAddress
| join kind=inner (
    AADNonInteractiveUserSignInLogs
    | project UserId, SessionId, IPAddress
) on $left.UserId == $right.UserId
| where authIP != IPAddress
| project TimeGenerated, UserPrincipalName, authIP, IPAddress, AppDisplayName
```

**Monitor for bulk SaaS data access.** Post-compromise exfiltration generates detectable signals. Unusual volume downloads from SharePoint or OneDrive, mass email exports, or bulk file access outside business hours should trigger alerts regardless of whether the session appears authenticated.

## The broader shift

This campaign is an example of a trend that's been building for several years: attackers adapting to MFA adoption by targeting the session layer rather than the credential layer. As more organizations deploy MFA, the value of a captured session token — which is already post-MFA — has increased correspondingly.

The identity industry's response is FIDO2 and passkeys, which bind credentials to origins and eliminate the proxy attack surface entirely. Adoption is growing but uneven. Large enterprises with legacy systems often can't deploy hardware keys uniformly. In those gaps, vishing-enabled AiTM campaigns will continue to find purchase.

The operational playbook for these groups is now well-established enough that CrowdStrike is tracking multiple independent clusters using similar techniques. It's no longer a sophisticated novel attack — it's becoming a standard technique available to moderately capable threat actors. That's the signal that it's time to treat phishing-resistant MFA as a baseline, not an aspiration.

Push your organization toward FIDO2. In the meantime, harden the help desk — that's where the key gets handed over.
