---
title: "Public Key and Private Key Explained: The Cryptography Behind Modern Auth"
description: "Public/private key pairs are the foundation of TLS, JWT signing, SSH, passkeys, and most of modern authentication. This article explains how asymmetric cryptography works, why the split between keys matters, and where you encounter it in everyday auth systems."
pubDate: 2026-08-03
author: "Khashayar Parhami"
tags: ["cryptography", "security", "jwt", "tls", "passkeys", "fundamentals"]
image: "/images/og/public-key-cryptography.png"
featured: false
---

Most auth systems depend on a deceptively simple idea: two mathematically related numbers, one of which you can share freely and one of which you keep secret. Understanding why that works — and where it breaks — is one of the more useful things you can know if you work with authentication systems.

This article is about asymmetric cryptography: what the two keys are, what each one is for, and how the pair shows up across TLS, JWT signing, SSH, and passkeys.

---

## Symmetric vs asymmetric: the essential difference

Symmetric cryptography uses the same key to lock and unlock. AES, for example, takes a secret key, encrypts a message, and the recipient decrypts it with the same key. This works when both parties can securely exchange the key beforehand — inside a data centre, between services that share a vault. It breaks down when strangers need to communicate securely over a public network before they've had any prior contact.

That is the problem public key cryptography solves.

Asymmetric cryptography generates a *pair* of keys. The two keys are mathematically linked: something encrypted with one can only be decrypted with the other. But knowing the public key does not let you derive the private key. The keys are not interchangeable — each one does a different job.

- The **public key** can be distributed to anyone. It is safe to post it, embed it in a certificate, or hand it to a stranger.
- The **private key** is secret. Only the owner holds it. If it leaks, the security model collapses entirely.

---

## What each key can do

The two operations asymmetric cryptography enables are **encryption** and **signing**. They use the keys in opposite directions.

### Encryption

> Encrypted with the *public key*, decrypted with the *private key*.

If you want to send a secret to someone, encrypt it with their public key. Only they can decrypt it, because only they have the private key. No prior secret sharing needed.

This is how early HTTPS key exchanges worked (RSA key exchange) and how systems like PGP email encryption operate.

### Signing

> Signed with the *private key*, verified with the *public key*.

If you want to prove that a message came from you and has not been tampered with, sign it with your private key. Anyone with your public key can verify the signature — they confirm the message was signed by whoever holds the matching private key, and that no bytes have changed since it was signed.

This is how JWT RS256 and ES256 work, how SSH host verification works, how software code signing works, and how passkeys authenticate a user.

The key insight: signing does not hide the message. It proves its origin and integrity. Encryption hides content. Both use the same key pair but in opposite orientations.

---

## The math: why you can't reverse it

The security of asymmetric cryptography rests on hard mathematical problems. "Hard" here has a precise meaning: there is no known efficient algorithm, even for a modern computer, that solves the problem in a practical timeframe.

**RSA** relies on the integer factoring problem. The public key is the product of two very large prime numbers (`n = p × q`). Finding `p` and `q` from `n` alone — necessary to derive the private key — requires factoring a number that is typically 2048 or 4096 bits long. No efficient algorithm for this is publicly known.

**Elliptic Curve Cryptography (ECC)** relies on the elliptic curve discrete logarithm problem. Given a starting point `G` on the curve and the result point `Q = k × G`, finding the scalar `k` is computationally infeasible. ECC gives you equivalent security to RSA at much smaller key sizes — a 256-bit EC key offers roughly the same security as a 3072-bit RSA key.

Neither problem is provably unsolvable; they are practically unsolvable with currently known algorithms. This matters: a sufficiently powerful quantum computer running Shor's algorithm could factor large integers or solve discrete logs efficiently, which is why NIST standardised post-quantum cryptography algorithms (CRYSTALS-Kyber for key encapsulation, CRYSTALS-Dilithium for signatures) in 2024.

---

## Where you encounter key pairs in auth systems

### TLS (HTTPS)

Every HTTPS connection involves a server certificate, which contains the server's public key. During the TLS handshake:

1. The client receives the server's certificate.
2. The client verifies the certificate was signed by a trusted Certificate Authority (CA).
3. The client and server use the server's key pair to establish a shared symmetric session key.

From that point the connection uses symmetric encryption (AES-GCM or ChaCha20-Poly1305) because it is faster. The asymmetric key pair is used once per handshake to bootstrap the symmetric key — a technique called a *key agreement* or *key exchange*.

In modern TLS 1.3, the server's RSA or EC key pair is used for authentication only (signing), while the actual key exchange uses an ephemeral Diffie-Hellman key. This is why TLS 1.3 provides *forward secrecy*: if the server's long-term private key is compromised later, past sessions cannot be decrypted because the session keys were ephemeral and discarded.

### JWT signing (RS256 and ES256)

A JSON Web Token signed with RS256 or ES256 works like this:

1. The authorization server signs the JWT payload with its **private key**.
2. The resource server or client verifies the JWT signature using the authorization server's **public key**.

The authorization server publishes its public keys at a JWKS URI (e.g. `https://auth.example.com/.well-known/jwks.json`). Any verifier can fetch those keys and confirm that a JWT was actually issued by that server and has not been tampered with since.

This is in contrast to HS256, which uses a shared secret. With HS256, the same key that signs tokens can also forge them — so you cannot safely share the key with an untrusted resource server. RS256 and ES256 let you separate the signer (authorization server, holds private key) from the verifiers (resource servers, hold only the public key). Verifiers can confirm authenticity but cannot mint new tokens.

```json
// JWKS endpoint response (abbreviated)
{
  "keys": [
    {
      "kty": "EC",
      "crv": "P-256",
      "use": "sig",
      "kid": "2026-08-key-1",
      "x": "l8tFrhx-34tV3hRICRDY9zSjtblS4joP...",
      "y": "9VE4jf_Ok_o64zbTTlcuNSmr3jf9gZUu..."
    }
  ]
}
```

The `kid` (key ID) claim in a JWT header lets verifiers select the right key if the server has rotated or published multiple keys simultaneously. Key rotation — generating a new private key and updating the JWKS — is routine operational practice; keeping old public keys published until existing tokens expire avoids a verification outage.

### SSH

When you authenticate to a server with SSH using a key pair:

1. Your SSH client holds the **private key** (typically `~/.ssh/id_ed25519`).
2. The server holds your **public key** in `~/.ssh/authorized_keys`.
3. The server sends a challenge; your client signs it with the private key.
4. The server verifies the signature with the stored public key.

No password is ever transmitted. The server never sees your private key. This is why SSH key authentication is more phishing-resistant than passwords — an attacker who intercepts the connection sees the signed challenge response, which is useless without the original private key.

The server's own host key works in reverse: the server signs its identity, and your client verifies it against a known-hosts record. This prevents a server impersonation attack.

### Passkeys (WebAuthn / FIDO2)

Passkeys are a user-facing implementation of the same mechanism. When you register a passkey:

1. Your device (or platform authenticator) generates a key pair.
2. The **private key** stays on the device, protected by the secure enclave, never exported.
3. The **public key** is sent to the server and stored.

When you authenticate:

1. The server sends a challenge.
2. Your device signs it with the private key.
3. The server verifies the signature with the stored public key.

The credential is *origin-bound* — the signature includes the relying party origin. A phishing site that tricks you into authenticating receives a signed challenge bound to the phishing domain, not the legitimate one. The legitimate server rejects it. This is the property that makes passkeys phishing-resistant in a way that TOTP codes and push notifications are not.

---

## Key sizes and algorithm choices

Current recommendations as of 2026:

| Use case | Algorithm | Minimum key size |
|---|---|---|
| General asymmetric signing | ECDSA (P-256) | 256-bit |
| General asymmetric signing | RSA | 2048-bit (3072 recommended) |
| Key exchange in TLS | ECDH (X25519) | 255-bit |
| SSH key | Ed25519 | 256-bit |
| Code signing | ECDSA or RSA | P-256 / 3072-bit RSA |

Ed25519 and X25519 (Curve25519) are increasingly preferred over the NIST P-curves for performance and implementation safety reasons. The NIST curves require careful constant-time implementation to avoid side-channel attacks; Curve25519 was designed from the outset to be harder to implement incorrectly.

RSA below 2048 bits is deprecated by NIST. RSA-1024 should be treated as broken.

---

## What "the private key is secret" actually means

The security model for asymmetric cryptography has one hard requirement: the private key must never be exposed. This is not a soft recommendation.

**At rest**: Private keys should be stored encrypted, ideally in a hardware-protected store:
- TPM / secure enclave (passkeys, modern device certificates)
- HSM (hardware security module) for server certificates and signing keys
- Platform keystores (`Keychain` on macOS/iOS, `Android Keystore`, Windows DPAPI) for application keys
- Secrets manager (Vault, AWS Secrets Manager) for infrastructure keys, as a minimum

**In transit**: Private keys should never leave their origin system. HTTPS certificates should be generated on the server, with the private key staying there. If you are given someone else's private key, the key is already compromised.

**Access control**: Limit which processes can read a private key. The web server process needs the TLS private key; the database process does not. Use filesystem permissions, keystore access controls, or separate processes.

**Rotation**: Private keys should have a lifetime. TLS certificates expire (Let's Encrypt issues 90-day certificates). SSH host keys should be rotated when a server is rebuilt. JWT signing keys should be rotated on a schedule and after any suspected exposure. The JWKS endpoint pattern with `kid` claims exists precisely to make rotation possible without breaking verifiers.

---

## Common mistakes

**Checking only the signature, not the algorithm**: A JWT library that accepts both HS256 and RS256 can be tricked into accepting a token where an attacker has substituted the authorization server's public key as the HMAC shared secret. Always pin the expected algorithm when verifying JWTs; reject `alg: "none"` unconditionally.

**Storing private keys in source control**: A private key committed to a repository is permanently compromised, even if the commit is later deleted. Rotate immediately; don't try to scrub history as the only remediation.

**Using the same key pair for multiple purposes**: A key used for signing should not also be used for encryption. RFC 7517 encodes this in the `use` claim (`sig` vs `enc`). Cross-purpose key use creates subtle attack surfaces.

**Trusting a public key without verifying its provenance**: A public key you received over an insecure channel might have been swapped. Certificate Authorities, JWKS URIs over HTTPS, and SSH `known_hosts` fingerprint verification all exist to address this. Public key pinning in mobile apps is another mechanism, though it creates operational complexity around rotation.

---

## The bigger picture

Asymmetric cryptography is the reason two parties who have never met can communicate securely over the internet. The public key can travel in the open — through a certificate, a JWKS endpoint, an `authorized_keys` file — and it does not weaken the system. The private key stays locked down, and that lockdown is the entire security boundary.

Every time you see RS256 or ES256 in a JWT, a P-256 key in a passkey registration, or the green padlock on an HTTPS site, the same basic property is being exploited: a mathematical relationship that lets you verify without revealing, and authenticate without transmitting secrets.

The systems break in predictable ways: private key leakage, implementation bugs in the cryptographic operations, algorithm confusion attacks, or side-channel leakage from non-constant-time implementations. The mitigations are equally predictable: hardware key storage, pinned algorithms, standard libraries rather than homebrew implementations, and rotation schedules that limit the blast radius when a key is eventually compromised.

---

*For key algorithm recommendations, NIST SP 800-57 Part 1 (Revision 5) covers cryptographic key management. The post-quantum migration guidance is in NIST SP 800-208 and FIPS 203–205. RFC 7517 defines the JWK format; RFC 7515 defines JWS (signed JWTs). The WebAuthn specification is published by the W3C at w3.org/TR/webauthn.*
