---
title: "NIST SP 800-63-4 Is Final: What the New Digital Identity Guidelines Actually Change"
description: "NIST's fourth revision of the Digital Identity Guidelines is now in effect. Syncable passkeys can meet AAL2. SMS OTP is restricted. KBA is out. Here's what changed, what it means for your stack, and what you need to update."
pubDate: 2026-06-17
author: "Khashayar Parhami"
tags: ["nist", "identity", "mfa", "passkeys", "standards"]
image: "/images/og/nist-800-63-4.png"
featured: false
---

NIST SP 800-63 has governed digital identity for federal agencies — and by extension shaped commercial identity best practices — since 2004. The fourth revision landed at the end of 2024 and is now actively driving compliance work in both the public sector and any private organisation that does business with it.

The changes are substantial. Two of them will directly affect decisions you're making right now about authentication architecture.

---

## What the document actually is

SP 800-63-4 is published in three separate volumes:

- **SP 800-63A** — Enrollment and Identity Proofing (how you verify who someone is when they enroll)
- **SP 800-63B** — Authentication and Authenticator Lifecycle Management (how they prove identity on return visits)
- **SP 800-63C** — Federation and Assertions (how identity is communicated across systems)

Most developers interact primarily with 800-63B. That's where MFA requirements, authenticator types, and session management rules live.

The framework defines three assurance levels for each domain:

- **IAL** (Identity Assurance Level) — how confident you are the person is who they claim to be at enrollment
- **AAL** (Authenticator Assurance Level) — the strength of authentication on each subsequent access
- **FAL** (Federation Assurance Level) — the strength of the assertion passed between systems in federated identity flows

---

## The change that matters most: syncable authenticators at AAL2

In SP 800-63B revision 3, achieving AAL2 required a hardware-bound authenticator or a software authenticator on a device that could verify user presence. The implicit assumption was that a cryptographic key was bound to a single piece of hardware — it couldn't be copied or synced.

**Revision 4 explicitly classifies syncable authenticators as a distinct authenticator type and allows them to meet AAL2 under defined conditions.**

A syncable authenticator is what the industry calls a passkey: a FIDO2 credential whose private key is managed by a passkey provider (Apple iCloud Keychain, Google Password Manager, 1Password, Dashlane, etc.) and can be synchronised across devices via end-to-end encrypted cloud backup.

This is a significant policy shift. The key is no longer hardware-bound. It lives in a secure enclave on your device, encrypted, and backed up to a cloud service you control. If your phone is wiped, you recover the passkey from your provider's sync service.

The AAL2 conditions for syncable authenticators are:

1. The sync channel must be end-to-end encrypted (the passkey provider must not have access to the plaintext key material)
2. Access to the sync service must itself require authentication
3. The authenticator must verify user presence (biometric or PIN) at the point of use
4. The relying party must perform phishing-resistant verification — the FIDO2 WebAuthn protocol already enforces this through origin binding

This resolves a tension that has existed since passkeys launched. Under rev 3, strict reading of NIST suggested passkeys were only AAL1 because the key could sync to another device. Teams building to federal standards had to choose between hardware keys (AAL2) and passkeys (practical, but potentially AAL1). That ambiguity is now resolved.

**If you're building a system that needs to meet AAL2, passkeys are now an explicitly supported path.**

---

## SMS OTP: still allowed, but now officially restricted

SP 800-63B rev 3 moved PSTN-based authenticators (SMS and voice OTP) into a "restricted" category — meaning they were allowed but required a documented risk acceptance and additional controls. That classification stands in rev 4, with more explicit conditions.

To use SMS OTP at AAL2, organisations must now:

- Document the risk acceptance in their authentication policy
- Notify users that the authenticator type has security limitations
- Provide an alternative authenticator path (you can't make SMS the only MFA option)
- Have a mitigation plan for SIM-swap scenarios

The language matters here. PSTN is not prohibited. Federal agencies and regulated industries use it because it's the only MFA option that works reliably across their entire user population. But NIST is being explicit: this is a risk acceptance, not a security recommendation. If you're designing a new system today, build toward TOTP or passkeys. SMS stays for legacy coverage.

What rev 4 does not do is give SMS a rehabilitation. The underlying threat model — SIM-swap fraud, SS7 interception, carrier-side social engineering — hasn't changed. SS7 attacks that redirect SMS messages to attacker-controlled numbers are well-documented and commercially available as attack tooling.

---

## KBA is gone

Knowledge-based authentication — security questions, static shared secrets like "mother's maiden name" or "name of first pet" — is removed as an acceptable identity proofing mechanism across all IALs.

This was coming. KBA fails for two converging reasons:

1. **Data availability**: The answers to almost all KBA questions are either in public records, social media, data broker files, or a recent breach dataset. Searching `[person name] + city grew up` on LinkedIn, public records, and Facebook produces answers to 70-80% of typical KBA question sets.

2. **AI-assisted lookup**: Large language models with access to web search can now answer KBA questions about public figures and semi-public individuals faster and more accurately than the users themselves. "What was the name of your first school?" is answerable from public records in a majority of cases.

NIST's position: KBA was never adequate for anything above IAL1, and the threat model has deteriorated to the point where it isn't adequate at any level.

**If you have KBA anywhere in your identity proofing or account recovery flows, it needs to come out.**

---

## Password policy: what actually changed

The password guidance in rev 4 builds on the significant shift in rev 3 — which eliminated mandatory rotation and complexity rules — and makes several additions:

**Minimum length stays at 8 characters. Maximum length must support at least 64 characters.** If your system is truncating passwords or rejecting long passphrases, that's now explicitly out of compliance.

**Compromised credential checking is required.** When a user sets or changes a password, you must check it against a list of known compromised passwords. NIST maintains a reference but doesn't mandate a specific list; common implementations use the k-Anonymity model from Have I Been Pwned.

```python
import hashlib
import requests

def is_compromised(password: str) -> bool:
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    resp = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}")
    return suffix in resp.text
```

**Unicode support is required.** Passwords must support the full Unicode character set. Truncating or stripping non-ASCII characters is out of compliance.

**No complexity rules imposed by the verifier.** You cannot require upper/lower/number/symbol combinations. NIST's rationale: complexity rules produce predictable password patterns (Password1!, Passw0rd!) that are worse than long random passphrases. Length is the security property; complexity is user friction that doesn't help.

**No security hints visible at the authenticator prompting screen.** If your login page says "Your password must contain..." — that hint is now non-compliant.

---

## What changed in federation (800-63C)

The federation volume has updates that matter for systems using OIDC or SAML to pass identity between components.

**FAL2 now requires phishing-resistant assertion binding.** At FAL2, the assertion (the ID token or SAML assertion) must be bound in a way that prevents interception and replay on a different channel. For OIDC, this means either sender-constrained tokens (DPoP — Demonstration of Proof of Possession) or back-channel flows where the token is never exposed to the browser.

The current common pattern of handing an ID token in the URL or a cookie that's decoupled from the channel it was issued on is FAL1, not FAL2. If you need FAL2, you need to implement DPoP or switch to back-channel token delivery.

**Allowlisting for federation relationships is required above FAL1.** You can't have an open "accept any OIDC provider" integration at FAL2. Every trusted identity provider must be explicitly registered.

---

## How to assess your current system

Map each user-facing authentication surface to an assurance level, then check whether your current authenticators satisfy that level.

| Flow | Required Level | Current Auth | Compliant? |
|------|---------------|--------------|------------|
| General user login | AAL1 | Password only | Yes |
| Admin console | AAL2 | Password + SMS | Compliant but restricted — document risk acceptance |
| HR/payroll access | AAL2 | Password + TOTP | Yes |
| Identity proofing | IAL2 | KBA + document | No — remove KBA |
| API-to-API | AAL2 | mTLS + service JWT | Yes |

For the SMS row: you're not required to replace it immediately, but you are required to document the risk acceptance and provide an alternative MFA option.

For the KBA row: there is no path to compliance. Remove KBA from identity proofing and replace it with document-based proofing, biometric verification, or in-person proofing depending on the IAL you need to meet.

---

## The passkeys migration window

The AAL2 classification of syncable authenticators gives a practical migration path that previously didn't exist cleanly.

The prior constraints:
- TOTP apps (Google Authenticator, Authy) are AAL2 — but require users to manage a separate app and are phishable (a user can be tricked into entering an OTP on a fake site)
- Hardware keys (YubiKey) are AAL2 and phishing-resistant — but carry device cost and the user experience for non-technical staff is friction-heavy
- SMS OTP is restricted, not recommended for new systems

Passkeys now fit as: **AAL2, phishing-resistant, syncable, user-friendly**. They require biometric or PIN verification at use. The cryptographic binding to the origin domain means a passkey issued for `app.company.com` cannot be used on `app-company.com`. The key never leaves the device in usable form.

For new systems, the NIST-compliant path is clear: implement passkeys as the primary AAL2 authenticator. Keep TOTP as a fallback. Remove SMS from new enrollment flows (keep it in legacy flows with documented risk acceptance if necessary for your user base).

---

## Compliance timeline

SP 800-63-4 is currently guidance for federal agencies and contractors. For private organisations, it's the industry reference that downstream standards (PCI-DSS, FedRAMP, SOC 2 assessors) increasingly cite.

FedRAMP Authorization Program has signalled it will update requirements to reference rev 4. For organisations pursuing FedRAMP authorisation, the updated controls will apply to new authorisations and annual assessments.

If you're not in a regulated sector: rev 4 is still the right target. The attackers are not respecting your compliance timeline. The changes NIST made — deprecating KBA, restricting SMS, classifying passkeys as AAL2 — reflect where the attack surface actually is in 2026, not where it was in 2017 when rev 3 was published.

---

*SP 800-63-4 is published by NIST and freely available at pages.nist.gov/800-63-4. The three volumes — 63A, 63B, and 63C — are separate documents and can be read independently based on which aspect of identity management you're implementing.*
