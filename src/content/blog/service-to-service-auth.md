---
title: "Service-to-Service Authentication: API Keys, mTLS, and JWTs"
description: "When services talk to each other, user identity doesn't apply. Learn how to authenticate machine-to-machine traffic using API keys, mutual TLS, OAuth client credentials, and service JWTs — with guidance on when to use each."
pubDate: 2026-06-03
author: "Khashayar Parhami"
tags: ["api-security", "security", "guide"]
image: "/images/og/service-to-service-auth.png"
featured: false
---

Most authentication content focuses on users — how to log in, manage sessions, issue tokens. But in modern distributed systems, the majority of traffic is service-to-service: an API gateway calling a payments service, a background worker hitting a database API, a Lambda function invoking another microservice. No human is involved. The question is how these services prove their identity to each other.

This is machine identity, and it's one of the most underspecified areas of application security. A system that carefully validates every user JWT might accept any internal request without verification, trusting that "if it's inside the network it must be legitimate" — an assumption that fails badly once an attacker is inside, or once a misconfigured service fires off requests it shouldn't.

---

## The Options

Four main approaches, roughly in order of implementation complexity:

1. **API keys** — shared secret, pre-issued, sent as a header
2. **Mutual TLS (mTLS)** — both sides present certificates, verified at the TLS layer
3. **OAuth 2.0 client credentials** — service authenticates to an auth server, receives a short-lived access token
4. **Service JWTs** — service signs its own JWT assertion and presents it to a peer

Each has a different trust model, operational overhead, and suitability depending on your architecture.

---

## API Keys

The simplest approach: issue a random secret to each calling service and require it in a header.

```http
GET /internal/orders HTTP/1.1
Host: orders.internal
X-API-Key: sk_live_4f8e2b...
```

The receiving service looks up the key in a database or cache, checks it's valid and not revoked, and identifies the caller.

### What API keys are good for

- Simple, synchronous internal APIs where operational simplicity matters
- Third-party integrations where you control the issuing process
- Webhooks — providing a secret the receiver can use to verify the sender

### The problems with API keys

**They're long-lived by default.** A leaked API key is valid until manually rotated. Unlike JWTs, there's no built-in expiry.

**No cryptographic proof of identity.** Anyone who obtains the key can use it. There's no way to verify the key was sent by a specific service — only that someone has the key.

**Rotation is operationally painful.** Rotating a key requires updating every service that uses it, often requiring coordinated deployments.

**No standard format.** Every system invents its own header name, key format, and validation logic.

### Making API keys safer

If you use API keys, follow these practices:

```javascript
// Store hashed keys, not plaintext — treat them like passwords
const keyHash = crypto.createHash('sha256').update(rawKey).digest('hex');
await db.apiKeys.create({ hash: keyHash, serviceId: 'payments-service', scopes: ['orders:read'] });

// Validate on every request
async function validateApiKey(rawKey) {
  const hash = crypto.createHash('sha256').update(rawKey).digest('hex');
  const key = await db.apiKeys.findOne({ hash, revokedAt: null });
  if (!key) throw new AuthError('Invalid API key');
  await db.apiKeys.update({ id: key.id, lastUsedAt: new Date() });
  return key;
}
```

- Hash keys before storage (SHA-256 minimum)
- Scope keys to specific operations
- Set expiry dates and enforce rotation
- Log every use with caller identity and timestamp
- Never log the raw key value

---

## Mutual TLS (mTLS)

Standard TLS has one-sided authentication: the client verifies the server's certificate, but the server doesn't verify the client. Mutual TLS adds the other direction — the client also presents a certificate, and the server verifies it.

```
Client                          Server
  |                               |
  |--- ClientHello -------------→ |
  |← ServerHello, Certificate --- |  ← server cert (standard TLS)
  |--- Certificate ─────────────→ |  ← client cert (mutual TLS)
  |--- CertificateVerify ───────→ |
  |        ... handshake ...       |
  |========= Encrypted ========== |
```

Once the mTLS handshake completes, both sides have verified each other's identity cryptographically. The application layer receives a verified client identity without any additional auth headers.

```javascript
// Express — read the verified client certificate
app.use((req, res, next) => {
  const cert = req.socket.getPeerCertificate();
  if (!cert || !req.client.authorized) {
    return res.status(401).json({ error: 'Client certificate required' });
  }
  // cert.subject.CN is the service name baked into the certificate
  req.serviceIdentity = cert.subject.CN;
  next();
});
```

### What mTLS is good for

- Zero-trust service meshes (Istio, Linkerd, Consul Connect) — mTLS between every service, managed automatically
- High-assurance environments where cryptographic proof of service identity is required
- Payment networks, financial infrastructure, regulated environments

### The operational overhead

mTLS requires a **PKI (Public Key Infrastructure)** — a certificate authority that issues and manages service certificates. Every service needs a certificate, certificates expire and must be rotated, and the CA itself must be protected.

In a service mesh, this is mostly handled for you: the control plane issues short-lived certificates to each service's sidecar proxy and handles rotation automatically. Outside a service mesh, it's significant operational work.

**Certificate lifetime:** Use short-lived certificates (24 hours to a few days) with automated rotation rather than long-lived ones. A 90-day cert that's never rotated is a liability.

```bash
# Vault PKI — issue a 24-hour service cert
vault write pki/issue/service-role \
  common_name="payments-service" \
  ttl="24h"
```

---

## OAuth 2.0 Client Credentials

The client credentials grant is OAuth 2.0's mechanism for machine-to-machine authentication. A service authenticates to an authorisation server using its `client_id` and `client_secret`, receives a short-lived access token, and presents that token to peer services.

```
Service A                    Auth Server                  Service B
   |                              |                            |
   |-- POST /token -----------→   |                            |
   |   client_id=svc-a            |                            |
   |   client_secret=...          |                            |
   |   grant_type=client_credentials                           |
   |← access_token (JWT, 5min) -- |                            |
   |                              |                            |
   |-- GET /orders ───────────────────────────────────────→    |
   |   Authorization: Bearer eyJ...                            |
   |                              |                            |
   |                              |← validate token (JWKS) --- |
   |← 200 OK ────────────────────────────────────────────── → |
```

The access token is a JWT signed by the auth server. Service B validates it by verifying the signature against the auth server's public keys (JWKS), checking expiry, audience, and scope — the same validation applied to user tokens.

```javascript
// Service A — fetch a token (with caching)
class TokenClient {
  constructor(authServerUrl, clientId, clientSecret) {
    this.tokenUrl = `${authServerUrl}/token`;
    this.clientId = clientId;
    this.clientSecret = clientSecret;
    this.cachedToken = null;
    this.tokenExpiry = 0;
  }

  async getToken() {
    // Return cached token if still valid (with 30s buffer)
    if (this.cachedToken && Date.now() < this.tokenExpiry - 30_000) {
      return this.cachedToken;
    }

    const response = await fetch(this.tokenUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'client_credentials',
        client_id: this.clientId,
        client_secret: this.clientSecret,
        scope: 'orders:read payments:write',
      }),
    });

    const { access_token, expires_in } = await response.json();
    this.cachedToken = access_token;
    this.tokenExpiry = Date.now() + expires_in * 1000;
    return access_token;
  }
}

// Service B — validate the token
import { createRemoteJWKSet, jwtVerify } from 'jose';

const JWKS = createRemoteJWKSet(new URL('https://auth.internal/.well-known/jwks.json'));

async function verifyServiceToken(token) {
  const { payload } = await jwtVerify(token, JWKS, {
    issuer: 'https://auth.internal',
    audience: 'https://orders.internal',
    algorithms: ['RS256'],
  });
  return payload; // { sub: 'svc-payments', scope: 'orders:read', exp: ... }
}
```

### What client credentials is good for

- Microservices architectures with a shared internal auth server
- When you want the same token validation logic for both user and service requests
- When scopes on service tokens matter — you want `payments-service` to have `orders:read` but not `orders:write`

### Client secret management

Never hardcode client secrets. Load them from a secrets manager at startup:

```javascript
// AWS Secrets Manager
const secret = await secretsManager.getSecretValue({ SecretId: 'svc-payments/client-secret' });
const { clientSecret } = JSON.parse(secret.SecretString);
```

Rotate client secrets on a schedule. If your auth server supports **Private Key JWT** authentication (RFC 7523), use that instead of client secrets — the service signs an assertion with its private key rather than sending a shared secret.

---

## Service JWTs (JWT Bearer Assertion)

Rather than calling an auth server first, a service can sign its own JWT assertion and present it directly to a peer. This is defined in RFC 7523 and is sometimes called a JWT bearer assertion or a service-signed JWT.

```javascript
import { SignJWT, importPKCS8 } from 'jose';

const privateKey = await importPKCS8(process.env.SERVICE_PRIVATE_KEY, 'RS256');

async function createServiceAssertion(targetAudience) {
  return new SignJWT({})
    .setProtectedHeader({ alg: 'RS256', kid: 'payments-service-key-2026' })
    .setIssuer('payments-service')
    .setSubject('payments-service')
    .setAudience(targetAudience)
    .setIssuedAt()
    .setExpirationTime('5m')
    .setJti(crypto.randomUUID())
    .sign(privateKey);
}

// Call orders service
const token = await createServiceAssertion('orders-service');
await fetch('https://orders.internal/v1/orders', {
  headers: { Authorization: `Bearer ${token}` },
});
```

The receiving service validates the JWT using the caller's public key — which it fetches from a service registry, a well-known JWKS endpoint, or a pre-shared certificate.

Service JWTs work well when you don't want the operational overhead of a central auth server, but they require each service to manage its own signing keys and for peers to have a way to discover public keys.

---

## Comparison

| | API Keys | mTLS | Client Credentials | Service JWT |
|---|---|---|---|---|
| Complexity | Low | High | Medium | Medium |
| Expiry | Manual | Short-lived cert | Short-lived token | Short-lived (built-in) |
| Cryptographic proof | No | Yes | No (secret-based) | Yes (key-based) |
| Secret to protect | Key | CA + private key | Client secret | Private key |
| Revocation | Manual | CRL / OCSP | Token expiry | Token expiry |
| Works without auth server | Yes | Yes | No | Yes |
| Scopes / permissions | Custom | Via cert fields | Yes (OAuth scopes) | Yes (JWT claims) |
| Best for | Simple internal APIs | Service mesh, zero-trust | Microservices with shared IdP | Peer-to-peer without central IdP |

---

## Secret Management Principles

Regardless of which mechanism you choose, secrets — API keys, client secrets, private keys — must be managed correctly:

**Never store secrets in source code or environment variables baked into images.** Use a secrets manager (AWS Secrets Manager, HashiCorp Vault, GCP Secret Manager) and load at runtime.

**Rotate on a schedule, not just on breach.** Rotation should be automated and non-disruptive. If rotation requires a manual deployment, it won't happen often enough.

**Limit secret access by service.** Each service should only be able to read its own secrets. Use IAM roles, service accounts, or Vault policies to enforce this.

**Log secret access.** Know when a secret was last accessed and by what. Unexpected access patterns are early indicators of compromise.

---

## Further Reading

- [API Security Checklist](/blog/api-security-checklist) — controls for the APIs these services call
- [JWT Best Practices for Production Applications](/blog/jwt-best-practices) — token design and validation for service tokens
- [OAuth 2.0 Explained](/blog/oauth2-explained) — the client credentials grant in context
