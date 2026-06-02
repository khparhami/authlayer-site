---
title: "Before, During, and After: Authentication Is Being Attacked at Every Stage"
description: "This week's threat landscape in one picture: AI infrastructure deployed with no authentication, automated tools abusing Azure OAuth pre-trusted apps, and malware stealing OTPs directly from Microsoft Phone Link. Three separate attacks on the same kill chain."
pubDate: 2026-05-06
author: "Khashayar Parhami"
tags: ["identity", "oauth", "mfa", "security"]
image: "/images/og/auth-attack-surface.jpg"
featured: false
---

Three stories broke this week that, taken individually, look like separate security incidents. Taken together, they map out exactly where authentication is being broken right now — not at one point, but at every stage of the authentication lifecycle: before you authenticate, during it, and after it.

## Before you authenticate: AI services with no auth at all

Researchers published findings from a scan of over one million self-hosted AI services exposed to the internet. The headline number is stark: a significant proportion had no authentication by default.

The services in scope aren't obscure. They're the tools engineering teams are spinning up to self-host model inference, vector databases, AI gateways, and LLM orchestration layers — Ollama, LocalAI, Flowise, LangFlow, open-source RAG pipelines. These tools are often installed following quickstart guides that don't mention authentication, or with authentication disabled to simplify local development and never re-enabled before the instance becomes accessible externally.

What does unauthenticated access to an AI service get an attacker? Depending on the service:

- **Direct access to model inference** — query the model, exfiltrate embedded data, probe for prompt injection vectors
- **Access to the vector database** — the data that was chunked and embedded is often sensitive: internal documentation, customer records, source code, financial data
- **API keys stored in the service's configuration** — AI gateway services often hold credentials for downstream providers (OpenAI, Anthropic, AWS Bedrock). An exposed gateway is an exposed key store
- **Persistent prompt injection** — if the vector database is writable, an attacker can inject malicious context that gets retrieved and fed to the model for every subsequent query

The pattern is a structural one that's been present in every wave of new infrastructure tooling. Kubernetes dashboards in 2018. Elasticsearch in 2019. Redis instances. Now AI services. The dynamic is the same: new tools, fast adoption, security configuration treated as optional, and a scanning gap where the community hasn't built the muscle memory to check for exposed instances before they go live.

If your organisation is running self-hosted AI infrastructure, the first question to answer is not "which model are we running" — it's "what does an unauthenticated HTTP request to port 11434 return."

## During authentication: automated OAuth abuse against Azure

ConsentFix v3 is a toolset circulating in threat actor forums that automates the OAuth abuse flow against Microsoft Azure — specifically targeting first-party Microsoft applications that are pre-trusted and pre-consented by default in every Azure tenant.

The previous generation of this attack required manual steps: set up a phishing page, wait for victims to visit, manually exchange authorization codes for refresh tokens. ConsentFix v3 uses Pipedream as an automation backbone, removing the manual bottleneck entirely.

The attack chain:

1. Threat actor validates the target's Azure tenant ID and profiles employees for impersonation
2. Fake Azure portal interface is stood up, hosting a legitimate OAuth authorization flow (pointing at a real Microsoft endpoint)
3. Victim completes the OAuth flow on what looks like a normal Microsoft login — because it largely is one
4. The authorization code lands in Pipedream via webhook
5. Pipedream immediately exchanges the code for a refresh token via Microsoft's token endpoint, automatically
6. Refresh token is imported into tooling and used for persistent account access

The critical detail is step 2: the tool targets Microsoft's own first-party apps, which have pre-granted consent in every tenant. This means there is no consent prompt for the victim to click through and potentially be suspicious of. The flow looks legitimate because the OAuth authorization is legitimate — for an app the tenant already trusts.

This is a structural weakness in how tenant-wide pre-consent works. Microsoft grants certain first-party applications implicit consent that can't be revoked at the user level. An OAuth phishing attack that routes through one of those apps never triggers the "This application wants access to..." screen that security awareness training teaches users to scrutinize.

The automation component is the accelerant. When each credential capture requires manual operator involvement, campaigns are limited by headcount. Automated token exchange via Pipedream or similar means the operator can run phishing infrastructure at scale with minimal intervention.

**What to do:** In Entra admin centre, review your tenant's consent policies. Restrict user consent to publisher-verified applications, require admin approval for all consent grants, and audit existing delegated permissions. Even for first-party apps, Conditional Access policies with sign-in frequency and session controls can limit how long a captured refresh token remains useful.

```powershell
# Find all OAuth delegated permission grants in your tenant
Get-MgOauth2PermissionGrant -All | Select-Object ClientId, ConsentType, Scope, PrincipalId |
  Where-Object { $_.ConsentType -eq "AllPrincipals" } |
  Sort-Object ClientId
```

## After authentication: OTP interception without touching the phone

CloudZ is a remote access tool whose latest variant deploys a plugin called Pheno that intercepts SMS messages and OTP codes from Windows machines — without compromising the victim's mobile device.

The vector is Microsoft Phone Link, the Windows application that pairs a smartphone with a PC and surfaces notifications, messages, and calls on the desktop. When Phone Link is active, SMS messages received on the linked phone appear in a local SQLite database on the Windows machine.

Pheno monitors for active Phone Link sessions and reads directly from that database. Any SMS that arrives — including TOTP delivery codes, bank authentication codes, account verification messages — is exfiltrated to the attacker's infrastructure. The mobile device is never touched. No SIM swap. No SS7 exploit. Just a read from a local file.

The delivery mechanism is a fake ScreenConnect update, which gets the initial foothold via a Rust-based loader. From there a .NET loader installs CloudZ with sandbox evasion and analysis-tool detection (Wireshark, Fiddler, Procmon, Sysmon checks), then deploys the Pheno plugin.

The attack is significant because it reframes what "device-based" MFA actually means. SMS OTPs are commonly assumed to require phone access to steal. Phone Link breaks that assumption cleanly: if the Windows machine is compromised, any SMS OTP the phone receives is compromised without any interaction with the phone itself.

This isn't the first attack vector on Phone Link-style integrations, but it's among the cleanest. It requires no special permissions beyond what a standard remote access tool has on a Windows machine (file system read access), and it produces a continuous stream of authentication codes as the victim uses them.

**What to do:** Move away from SMS OTPs. TOTP authenticator apps that generate codes locally (Authy, Microsoft Authenticator in TOTP mode, Google Authenticator) don't have this exposure — the code is generated on the phone, not transmitted via SMS to a machine where it can be read from disk. FIDO2 hardware keys are the stronger option: they produce signatures that are origin-bound and single-use, so intercepting one gives an attacker nothing reusable.

If you're using SMS OTP for anything — account recovery, primary MFA, fallback — this is the week to schedule migration off it.

## The kill chain view

What makes these three attacks notable together is that they cover the entire authentication lifecycle:

- **No auth on AI infrastructure** = attacker gets in before authentication is even on the table
- **Automated OAuth abuse** = attacker hijacks the authentication event itself, capturing the session token as it's issued
- **Phone Link OTP theft** = attacker defeats the second factor after it's been triggered, capturing the code before it expires

Most security architecture treats these as separate concerns. They're not. An attacker who can't get into an AI service directly might phish an operator's Azure credentials instead. An attacker blocked by FIDO2 MFA might pivot to stealing SMS OTPs from a compromised workstation. The authentication stack is a chain, and this week's research shows active work on every link.

The common thread in the defences is the same one it's been for years: reduce dependence on SMS and push-based MFA, enforce admin approval on OAuth consent, treat every piece of AI infrastructure as a credential store, and monitor delegated permissions like you monitor service account credentials. None of this is new. The attack tooling is just making the cost of not doing it more immediate.

---

*Indicators of compromise for CloudZ/Pheno are available via Cisco Talos. ConsentFix v3 analysis is available via Microsoft MSRC. AI service exposure data is from the Censys research publication.*
