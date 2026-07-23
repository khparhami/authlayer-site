---
title: "DPoP Explained: Sender-Constrained Tokens and Why Bearer Tokens Are a Liability"
description: "Bearer tokens work like cash — whoever holds them can spend them. DPoP (RFC 9449) binds an access token to a client's private key, so a stolen token is useless without the key that signed it. Here's how it works and how to implement it."
pubDate: 2026-07-22
author: "Khashayar Parhami"
tags: ["oauth", "tokens", "security", "dpop", "api-security"]
image: "/images/og/oauth-tokens.jpg"
featured: false
---

Every access token your application receives is, in security terms, a bearer credential. The name is intentional: whoever bears the token can use it. The server that issued it has no way to verify that the entity presenting the token is the same entity that was originally granted it.

This is fine when tokens are short-lived and the transport is secure. It becomes a serious problem when tokens are stolen from browser storage, leaked through a misconfigured log aggregator, extracted from a compromised proxy, or intercepted via an AiTM phishing kit. In all those cases, the attacker presents a legitimate token from a network location the issuer never expected, and the resource server has no mechanism to reject it.

DPoP — Demonstrating Proof of Possession, standardised in RFC 9449 — closes this gap.

---

## The bearer token problem, precisely stated

An OAuth access token issued by a standard authorization server is opaque to the resource server in a specific way: the token encodes what the holder is allowed to do (scopes, audience, expiry), but not *who* is allowed to present it.

When the resource server validates the token, it verifies:
- The token is signed by the trusted authorization server
- The token has not expired
- The `aud` claim matches this resource server
- The scopes cover the requested operation

What it does **not** verify is whether the HTTP client making this particular request is the same client that obtained the token. The token is the entire credential. Possession equals authorization.

NIST SP 800-63-4 names this directly. FAL2 (Federation Assurance Level 2) now requires that assertions be bound to the channel — meaning the token must be cryptographically tied to the party presenting it, not merely held by them. Back-channel token delivery is one option. DPoP is the other.

---

## What DPoP does

DPoP binds an access token to a specific key pair held by the client. The binding happens in two places:

1. **At the authorization server**: when issuing the access token, the server includes a `cnf` (confirmation) claim in the token that contains a thumbprint of the client's public key.

2. **At the resource server**: on each request, the client attaches a proof — a signed JWT that demonstrates possession of the private key that matches the `cnf` thumbprint. The resource server verifies the proof before accepting the token.

A stolen access token cannot be replayed by an attacker who doesn't also hold the private key. The token and the proof are separate, and only the original client has both.

---

## The request flow

Here is a DPoP-enabled token request and a subsequent API call.

**Step 1 — Token request with DPoP proof**

The client generates a key pair, then constructs a DPoP proof JWT:

```json
// DPoP proof header
{
  "typ": "dpop+jwt",
  "alg": "ES256",
  "jwk": {
    "kty": "EC",
    "crv": "P-256",
    "x": "l8tFrhx-34tV3hRICRDY9zSjtblS4joP...",
    "y": "9VE4jf_Ok_o64zbTTlcuNSmr3jf9gZUu..."
  }
}

// DPoP proof payload
{
  "jti": "e1d7f8a9-4b26-4c71-b3f2-1a2b3c4d5e6f",
  "htm": "POST",
  "htu": "https://auth.example.com/token",
  "iat": 1753142400
}
```

The proof is signed with the client's private key and sent in the `DPoP` HTTP header alongside the standard token request:

```http
POST /token HTTP/1.1
Host: auth.example.com
Content-Type: application/x-www-form-urlencoded
DPoP: eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7...

grant_type=authorization_code&code=SplxlOBeZQQYbYS6WxSbIA...
```

**Step 2 — Authorization server binds the token**

The server extracts the public key from the proof's `jwk` header, verifies the proof signature, and embeds the key thumbprint in the access token:

```json
// Access token payload (simplified)
{
  "sub": "user_01J8K2M...",
  "iss": "https://auth.example.com",
  "aud": "https://api.example.com",
  "scope": "read:data",
  "exp": 1753146000,
  "cnf": {
    "jkt": "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"
  }
}
```

The `jkt` value is the JWK thumbprint (SHA-256 hash) of the client's public key.

**Step 3 — API request with DPoP proof**

The client constructs a new proof for this specific request — different `jti`, matching `htm` and `htu` — and sends it alongside the access token:

```http
GET /data HTTP/1.1
Host: api.example.com
Authorization: DPoP eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9...
DPoP: eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7...
```

Note the `Authorization` scheme changes from `Bearer` to `DPoP`.

**Step 4 — Resource server validates both**

The resource server:
1. Verifies the access token signature and claims
2. Extracts the `cnf.jkt` thumbprint from the token
3. Extracts the public key from the DPoP proof's `jwk` header
4. Computes the thumbprint of that key and checks it matches `cnf.jkt`
5. Verifies the DPoP proof signature using that public key
6. Checks `htm` matches the request method, `htu` matches the request URL
7. Checks `iat` is recent (rejects old proofs — configurable window, typically 30–60 seconds)
8. Checks `jti` has not been seen before (replay prevention)

If all checks pass, the request proceeds. If the token is stolen and presented without the matching key, step 4 fails.

---

## Implementation in Python

A minimal DPoP proof generator using `python-jose` and `cryptography`:

```python
import json
import time
import uuid
import hashlib
import base64
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from jose import jwt

def generate_dpop_key_pair():
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    pub_numbers = public_key.public_key().public_numbers() if hasattr(public_key, 'public_key') else public_key.public_numbers()
    return private_key, public_key

def key_to_jwk(public_key):
    pub_numbers = public_key.public_numbers()
    def b64(n):
        return base64.urlsafe_b64encode(
            n.to_bytes((n.bit_length() + 7) // 8, 'big')
        ).rstrip(b'=').decode()
    return {"kty": "EC", "crv": "P-256", "x": b64(pub_numbers.x), "y": b64(pub_numbers.y)}

def jwk_thumbprint(jwk: dict) -> str:
    # RFC 7638 canonical member set for EC keys
    canonical = json.dumps(
        {"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"], "y": jwk["y"]},
        separators=(",", ":"), sort_keys=True
    )
    digest = hashlib.sha256(canonical.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()

def make_dpop_proof(private_key, public_key, method: str, url: str) -> str:
    jwk = key_to_jwk(public_key)
    headers = {"typ": "dpop+jwt", "alg": "ES256", "jwk": jwk}
    payload = {
        "jti": str(uuid.uuid4()),
        "htm": method.upper(),
        "htu": url,
        "iat": int(time.time()),
    }
    pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()
    )
    return jwt.encode(payload, pem, algorithm="ES256", headers=headers)
```

Usage in a token request:

```python
import requests

private_key, public_key = generate_dpop_key_pair()

proof = make_dpop_proof(private_key, public_key, "POST", "https://auth.example.com/token")

resp = requests.post("https://auth.example.com/token", headers={"DPoP": proof}, data={
    "grant_type": "authorization_code",
    "code": auth_code,
    "client_id": CLIENT_ID,
    "redirect_uri": REDIRECT_URI,
})

access_token = resp.json()["access_token"]

# Subsequent API call
api_proof = make_dpop_proof(private_key, public_key, "GET", "https://api.example.com/data")
api_resp = requests.get(
    "https://api.example.com/data",
    headers={"Authorization": f"DPoP {access_token}", "DPoP": api_proof}
)
```

---

## DPoP vs mTLS

DPoP is not the only sender-constraining mechanism. Mutual TLS (RFC 8705) achieves the same goal: the client presents a certificate during the TLS handshake and the authorization server embeds the certificate thumbprint in the token.

| Property | DPoP | mTLS (RFC 8705) |
|---|---|---|
| Where binding lives | Application layer (JWTs) | Transport layer (TLS) |
| Client setup | Generate a key pair in JS/code | Provision and manage client certificate |
| Works from browser | Yes — key in Web Crypto API | Difficult — browsers don't expose client cert to JS |
| Works behind load balancer | Yes — proof travels with request | Requires header forwarding or passthrough TLS |
| Revocation | Short-lived proofs, no issue | Certificate revocation adds complexity |
| Enterprise support | Newer — adoption growing | Well-established in financial services (FAPI) |

**When to use DPoP**: browser-based clients (SPAs), mobile apps, server-to-server calls where provisioning client certificates is friction-heavy.

**When to use mTLS**: backend services with existing PKI, financial services (FAPI 2.0 mandates mTLS or DPoP), scenarios where transport-layer guarantees are preferred.

FAPI 2.0 (the Financial-grade API profile used by open banking implementations) allows either DPoP or mTLS for sender-constraining tokens. DPoP is increasingly the implementation choice because it works cleanly in environments where TLS termination at a load balancer would otherwise strip the client certificate before it reached the application.

---

## nonce support

One variant worth knowing: DPoP proofs can include an authorization server-provided `nonce` in the payload. The server issues a `nonce` in the `DPoP-Nonce` response header; subsequent requests must include it in the proof.

Nonces mitigate a scenario where an attacker can observe a fresh DPoP proof in transit and replay it within the `iat` freshness window (before the `jti` record is checked). With a nonce, the server can also enforce a tighter validity window or rotate the nonce per-request.

If the server requires a nonce and the client sends a proof without one (or with an expired one), the response is `401 Unauthorized` with a `WWW-Authenticate: DPoP error="use_dpop_nonce"` header and a new `DPoP-Nonce` value. The client retries with the provided nonce.

---

## Authorization server and library support

DPoP shipped in RFC 9449 in September 2023. Adoption across major platforms:

| Platform | Status |
|---|---|
| Keycloak | Supported since 21.0 |
| Auth0 | Supported (Enterprise plan) |
| Microsoft Entra ID | Supported (Continuous Access Evaluation) |
| Okta | Supported |
| Spring Security OAuth | Supported since 6.3 |
| `oauth2-server` (Node.js) | Supported |
| `authlib` (Python) | Supported since 1.2 |

On the client side, any library that supports custom `Authorization` header construction and can sign JWTs can implement DPoP without library support — the proof is a standard JWT with a specific structure.

---

## What DPoP does not solve

DPoP binds the token to a key pair, not to a user session or device. If an attacker compromises the client process itself — exfiltrating both the token and the private key material — DPoP does not help. It is a transport-layer and storage-exfiltration defence, not a defence against full client compromise.

It also does not address phishing. A user can still be directed to a phishing site that proxies an authentication flow and captures the resulting token and key material before the DPoP binding is established. Phishing resistance requires origin-bound credentials — passkeys — not sender-constrained tokens.

DPoP and passkeys are complementary:
- Passkeys make the authentication phishing-resistant
- DPoP makes the resulting access token non-replayable from a different network location

Building both into your auth stack means an attacker needs to compromise both the user's authenticator and the client's key material to do anything useful with captured credentials.

---

## What to do now

If you are operating bearer tokens today, the transition to DPoP is incremental:

1. **Check your authorization server** — if it's on the list above, DPoP can likely be enabled per-client without a migration.

2. **Start with your most sensitive API clients** — internal admin tooling, financial operations endpoints, anything that handles access to sensitive bulk data.

3. **Key storage matters** — in a browser, generate and store the key pair in the non-extractable Web Crypto API (`{ extractable: false }`). This means the private key cannot be exported from the browser process even if an attacker runs arbitrary JavaScript. In a backend service, store in a hardware security module or platform key store.

4. **Implement the nonce flow from the start** — it's easier to build it correctly than to retrofit it after your authorization server starts requiring nonces.

5. **Monitor for DPoP validation errors** — `use_dpop_nonce`, `invalid_dpop_proof`, and `authorization_pending` in your resource server logs are signals that clients are misconfigured or that someone is attempting replay.

---

The trend in OAuth security is toward tokens that mean less without their context. DPoP is the practical, application-layer version of that principle: the token is only as good as the key held by the entity that obtained it. Bearer tokens made OAuth simple to adopt; sender-constrained tokens make it appropriate for environments where token theft is a realistic threat model, which in 2026 is most of them.

---

*RFC 9449 (DPoP) is freely available at datatracker.ietf.org/doc/html/rfc9449. The related RFC 8705 covers mTLS sender-constraining. FAPI 2.0 security profile guidance is published by the OpenID Foundation at openid.net/specs/fapi-2_0-security-profile.*
