---
title: "MFA Complete Guide: TOTP, FIDO2, Push Notifications, and What to Use When"
description: "A practical comparison of every major MFA method — TOTP authenticator apps, SMS OTP, FIDO2 hardware keys, push notifications, and passkeys — with attack resistance ratings and implementation advice."
pubDate: 2026-02-20
author: "AuthLayer Team"
tags: ["mfa", "security", "guide", "fido2"]
image: "/images/og/mfa.jpg"
---

Multi-factor authentication is the single most impactful security control you can add to an authentication flow. But not all MFA is equal — SMS OTP and FIDO2 hardware keys sit at opposite ends of the security spectrum. Here's how to choose.

## The MFA Spectrum

| Method | Phishing Resistant | SIM Swap Resistant | Ease of Use | Cost |
|---|---|---|---|---|
| SMS OTP | No | No | High | Low |
| Email OTP | No | Yes | High | Low |
| TOTP (Authenticator app) | No | Yes | Medium | Free |
| Push Notification | Partial | Yes | High | Vendor cost |
| FIDO2 Hardware Key | Yes | Yes | Medium | $25–$60/key |
| Passkeys (device-bound) | Yes | Yes | Very High | Free |

## SMS OTP — Convenient but Weak

SMS one-time passwords are the most widely deployed MFA method and the weakest. The attack surface is large:

- **SIM swapping** — attacker convinces carrier to port your number to their SIM
- **SS7 attacks** — protocol-level interception of SMS routing
- **Real-time phishing** — attacker proxies login in real time, relaying OTP before it expires

**NIST SP 800-63B** has deprecated SMS OTP for high-assurance use cases. It's better than no MFA, but should be a fallback, not a primary method.

**When to use it:** Fallback option only. Never as the sole or primary second factor for sensitive accounts.

## TOTP — The Authenticator App Standard

TOTP (Time-based One-Time Password, RFC 6238) generates a 6-digit code that rotates every 30 seconds using a shared secret and the current timestamp.

```
TOTP = HOTP(secret, floor(currentTime / 30))
```

Common apps: Google Authenticator, Authy, Microsoft Authenticator, 1Password.

**Strengths:**
- Works offline
- No SIM dependency
- Free to implement (no vendor)

**Weaknesses:**
- Phishable — a real-time phishing proxy can capture and relay the TOTP before it expires
- Relies on device time sync (allow ±1 window on validation)
- Backup codes need secure storage

**Implementation tip:** Store the TOTP secret encrypted at rest. Use a constant-time comparison for the OTP to prevent timing attacks.

```python
import hmac
# Use hmac.compare_digest, not ==
if not hmac.compare_digest(expected_otp, provided_otp):
    raise AuthenticationError("Invalid OTP")
```

## Push Notifications — Convenient but Vulnerable to MFA Fatigue

Push MFA (Okta Verify, Duo Push, Microsoft Authenticator) sends a push notification to the user's registered device: "Approve this login?"

**MFA fatigue attacks** are the primary threat: an attacker with the user's password spams push notifications until the user, fatigued or confused, taps "Approve". This technique was used in the Uber breach of 2022.

**Mitigations:**
- **Number matching** — the login screen shows a number; the push notification asks "Is this your number?" Eliminates blind approval
- **Geographic context** — show the login location in the push; user can spot anomalies
- **Rate limiting** — block push requests after N denials in a time window

Number matching is now required by most enterprise identity providers and should be enabled by default.

## FIDO2 / WebAuthn — The Gold Standard

FIDO2 is a phishing-resistant authentication standard built on public-key cryptography. The authenticator (hardware key or device) stores a private key; the server holds the public key. The origin (`https://example.com`) is cryptographically bound to the credential.

**Why it's phishing-resistant:** Even if a user is tricked onto `https://examp1e.com`, the credential is registered for `https://example.com`. The browser will not present the credential to a different origin — the authentication simply won't complete.

```
Registration:
  Server → Browser: challenge
  Browser → Authenticator: create credential for origin
  Authenticator → Browser: { publicKey, credentialId }
  Browser → Server: store publicKey

Authentication:
  Server → Browser: challenge
  Browser → Authenticator: sign challenge using privateKey for this origin
  Authenticator → Browser: signed assertion
  Browser → Server: verify signature with stored publicKey
```

**Hardware keys:** YubiKey, Google Titan Key. Best for privileged admin accounts.

**Platform authenticators:** Face ID, Touch ID, Windows Hello. These are the basis for passkeys.

## Passkeys — FIDO2 for Everyone

Passkeys are FIDO2 credentials that sync across devices via the OS vendor's cloud (iCloud Keychain, Google Password Manager). They look and feel like "log in with Face ID" — no code to type, no app to open.

**What they solve:** Traditional FIDO2 hardware keys require the physical key to be present. Passkeys are synced — so losing your phone doesn't mean losing access.

**Security model:** The private key is encrypted inside the secure enclave and synced encrypted. Apple, Google, and Microsoft can't see the private key. The origin binding still applies.

Passkeys represent the most usable phishing-resistant authentication available today and should be the target state for consumer-facing applications.

## Choosing MFA for Your Use Cases

**Consumer accounts (low–medium sensitivity):**
TOTP as primary, SMS as fallback, passkeys for modern clients.

**Employee / workforce accounts:**
Push with number matching as default, FIDO2 hardware keys for privileged roles, phishing-resistant MFA required for admin console access.

**Privileged admin access:**
FIDO2 hardware keys only. No exceptions.

**Developer API access:**
Short-lived credentials (OIDC tokens, AWS STS), not MFA on every request — but require MFA on the identity provider login that issues those credentials.

## Implementation Checklist

- Require MFA enrollment before first resource access
- Offer TOTP + passkeys as primary methods
- Deprioritise or remove SMS for new enrollments
- Enable number matching on all push-based MFA
- Log and alert on MFA denials — a spike suggests an active attack
- Implement account recovery that doesn't bypass MFA (backup codes stored securely, not emailed in plaintext)
