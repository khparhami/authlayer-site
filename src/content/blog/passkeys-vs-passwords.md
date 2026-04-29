---
title: "Passkeys vs Passwords: How Passkeys Work and Why They Win"
description: "Passkeys use public-key cryptography to replace passwords entirely. Learn the technical mechanics, the security properties, and what implementing passkeys actually looks like in 2026."
pubDate: 2026-03-10
author: "AuthLayer Team"
tags: ["passkeys", "fido2", "security", "guide"]
---

Passwords have been the dominant authentication mechanism for 60 years. They're also a catastrophic source of breaches — credential stuffing, phishing, password reuse, and weak choices are behind the majority of account takeovers. Passkeys solve all of this at the cryptographic level.

## The Problem with Passwords

Every password-based system has the same fundamental flaw: a shared secret that travels over the network, gets stored on a server, and can be guessed, stolen, phished, or leaked.

- **700M+ credentials** are leaked in data breaches annually
- **80% of hacking-related breaches** involve stolen or weak credentials (Verizon DBIR)
- Phishing success rates approach **30%** in targeted campaigns
- Password reuse means one breach cascades into many

No amount of complexity requirements, forced rotation, or MFA bolted on top fully solves these — they're mitigations for a broken model.

## How Passkeys Work

Passkeys use **asymmetric public-key cryptography**. There is no shared secret. The server never holds anything that lets it authenticate as the user.

### Registration

1. Your device generates a **key pair**: a private key and a public key
2. The private key is stored in the device's **secure enclave** — hardware-protected, never exported
3. The public key is sent to the server and stored alongside your account

### Authentication

1. The server sends a **cryptographic challenge** (random bytes)
2. Your device signs the challenge with the **private key** (using Face ID / fingerprint to unlock it)
3. The server verifies the signature using the stored **public key**

```
Server stores:  PUBLIC KEY  (useless to an attacker — it's already public)
Device stores:  PRIVATE KEY (never leaves the secure enclave)
Network carries: SIGNATURE  (only valid for this challenge, one time)
```

**What an attacker gets from a breach:** The public key. Which is... useless for authentication.

## Origin Binding — The Phishing Kill Switch

Here's what makes passkeys fundamentally different from TOTP or SMS:

When a passkey is created, it's **bound to the exact origin** (`https://yourbank.com`). When you try to authenticate, the browser checks that the current page's origin matches the registered origin. If you're on a phishing page (`https://y0urbank.com`), the browser will not present the passkey credential.

The user can't be tricked into authenticating on the wrong site — because the credential simply won't work there.

This is the property that NIST and the FIDO Alliance call **phishing resistance** — and it's why passkeys are categorically different from TOTP.

## Synced vs Device-Bound Passkeys

**Synced passkeys** (what most users get)
- Private key stored in OS keychain, synced encrypted via cloud
- Apple: iCloud Keychain, Google: Google Password Manager, Windows: coming via Windows Hello
- Survives device loss — you can sign in on a new phone
- Private key encrypted; Apple/Google cannot read it

**Device-bound passkeys** (hardware security keys)
- Private key stays on the hardware key (YubiKey, etc.) and never syncs
- Required for highest-assurance use cases
- Loss of device = loss of credential (have a spare key registered)

For consumer applications, synced passkeys are the right choice. For privileged enterprise access, device-bound passkeys (hardware keys) are preferred.

## Implementing Passkeys with WebAuthn

The WebAuthn API is built into all modern browsers. Here's the shape of a registration and authentication flow:

```javascript
// Registration — create a passkey
const credential = await navigator.credentials.create({
  publicKey: {
    challenge: serverChallenge,       // random bytes from your server
    rp: { name: "Your App", id: "yourapp.com" },
    user: { id: userId, name: userEmail, displayName: userName },
    pubKeyCredParams: [
      { type: "public-key", alg: -7 },   // ES256
      { type: "public-key", alg: -257 }, // RS256
    ],
    authenticatorSelection: {
      residentKey: "required",           // enables passkey behaviour
      userVerification: "required",      // requires biometric/PIN
    },
  }
});

// Send credential.response to server for storage
```

```javascript
// Authentication — use a passkey
const assertion = await navigator.credentials.get({
  publicKey: {
    challenge: serverChallenge,
    rpId: "yourapp.com",
    userVerification: "required",
  }
});

// Send assertion.response to server for verification
```

Server-side, you'll verify the signature against the stored public key and validate the origin, challenge, and `rpId`. Libraries like `@simplewebauthn/server` (Node.js), `py_webauthn` (Python), or `webauthn4j` (Java) handle the verification logic.

## Passkeys vs Other Auth Methods

| Property | Password | TOTP | SMS OTP | Passkey |
|---|---|---|---|---|
| Phishing resistant | No | No | No | **Yes** |
| Breach resistant | No | Partial | No | **Yes** |
| No shared secret | No | No | No | **Yes** |
| Works offline | Yes | Yes | No | Yes |
| Frictionless UX | Partially | No | Partially | **Yes** |
| No server-side secret | No | No | No | **Yes** |

## Adoption State in 2026

Passkeys are now supported by:
- **iOS** (16+), **macOS** (Ventura+), **Android** (9+), **Windows 11**
- **Chrome**, **Safari**, **Firefox**, **Edge**
- Major platforms: Apple, Google, Microsoft, GitHub, PayPal, Shopify, Amazon

The ecosystem has reached the point where passkeys can be offered as a primary (or sole) authentication method for the vast majority of users.

## Migration Path

You don't have to replace passwords overnight:

1. **Add passkeys as an option** — register a passkey alongside your existing password
2. **Promote passkeys on login** — prompt users to upgrade at sign-in
3. **Remove password as a requirement** for users who have registered a passkey
4. **Eventually deprecate passwords** — for new accounts, require passkey enrollment at signup

The goal state is: user has a passkey, no password stored in your database.
