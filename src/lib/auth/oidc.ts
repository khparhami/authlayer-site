import type { OIDCDiscovery, TokenMetadata } from './types.js';
import { isBlockedHost } from '../ssrf.js';

// ─── OIDC Discovery ──────────────────────────────────────────────────────────

export async function discoverOIDC(issuer: string): Promise<OIDCDiscovery> {
  let parsed: URL;
  try {
    parsed = new URL(issuer);
  } catch {
    throw new Error('Invalid issuer URL');
  }
  if (parsed.protocol !== 'https:') throw new Error('Issuer must use HTTPS');
  if (isBlockedHost(parsed.hostname)) throw new Error('Issuer hostname is not allowed');

  const discoveryUrl = `${issuer.replace(/\/$/, '')}/.well-known/openid-configuration`;
  const res = await fetch(discoveryUrl, {
    headers: { Accept: 'application/json' },
    signal: AbortSignal.timeout(8000),
  });
  if (!res.ok) throw new Error(`OIDC discovery failed: HTTP ${res.status}`);

  const doc = await res.json() as OIDCDiscovery;
  if (!doc.authorization_endpoint || !doc.token_endpoint) {
    throw new Error('Invalid OIDC discovery document — missing required endpoints');
  }
  return doc;
}

// ─── Token exchange ──────────────────────────────────────────────────────────

export interface TokenExchangeResult {
  accessToken: string;
  idToken?: string;
  tokenType: string;
  expiresIn?: number;
  scope?: string;
  metadata: TokenMetadata;
}

export async function exchangeCode(opts: {
  tokenEndpoint: string;
  code: string;
  clientId: string;
  redirectUri: string;
  codeVerifier: string;
}): Promise<TokenExchangeResult> {
  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    code: opts.code,
    client_id: opts.clientId,
    redirect_uri: opts.redirectUri,
    code_verifier: opts.codeVerifier,
  });

  const res = await fetch(opts.tokenEndpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' },
    body: body.toString(),
    signal: AbortSignal.timeout(10000),
  });

  if (!res.ok) {
    // SECURITY: do not include response body — it may contain partial tokens or secrets
    throw new Error(`Token exchange failed: HTTP ${res.status}`);
  }

  const json = await res.json() as {
    access_token?: string;
    id_token?: string;
    token_type?: string;
    expires_in?: number;
    scope?: string;
  };

  if (!json.access_token) throw new Error('No access token in response');

  const metadata = extractTokenMetadata(json.access_token, json.expires_in, json.scope);

  return {
    accessToken: json.access_token,
    idToken: json.id_token,
    tokenType: json.token_type ?? 'Bearer',
    expiresIn: json.expires_in,
    scope: json.scope,
    metadata,
  };
}

// ─── Token metadata extraction ───────────────────────────────────────────────

export function extractTokenMetadata(
  accessToken: string,
  expiresIn?: number,
  scope?: string,
): TokenMetadata {
  if (!accessToken.startsWith('eyJ')) {
    return {
      tokenType: 'opaque',
      expiresInSeconds: expiresIn,
      scopes: scope?.split(' ').filter(Boolean),
    };
  }

  try {
    const parts = accessToken.split('.');
    if (parts.length !== 3) return { tokenType: 'opaque', expiresInSeconds: expiresIn };

    const pad = (s: string) => s.padEnd(s.length + (4 - s.length % 4) % 4, '=');
    const headerJson = JSON.parse(atob(pad(parts[0].replace(/-/g, '+').replace(/_/g, '/'))));
    const payloadJson = JSON.parse(atob(pad(parts[1].replace(/-/g, '+').replace(/_/g, '/'))));

    const nowSec = Math.floor(Date.now() / 1000);
    return {
      tokenType: 'JWT',
      algorithm: headerJson.alg,
      keyId: headerJson.kid,
      issuer: payloadJson.iss,
      subject: payloadJson.sub,
      audience: payloadJson.aud,
      issuedAt: payloadJson.iat,
      expiresAt: payloadJson.exp,
      notBefore: payloadJson.nbf,
      expiresInSeconds: expiresIn ?? (payloadJson.exp ? payloadJson.exp - nowSec : undefined),
      scopes: scope?.split(' ').filter(Boolean) ?? payloadJson.scope?.split(' ').filter(Boolean),
    };
  } catch {
    return { tokenType: 'JWT', expiresInSeconds: expiresIn };
  }
}

// ─── Token revocation ────────────────────────────────────────────────────────

export async function revokeToken(opts: {
  revocationEndpoint: string;
  token: string;
  clientId: string;
}): Promise<void> {
  const body = new URLSearchParams({
    token: opts.token,
    client_id: opts.clientId,
  });
  await fetch(opts.revocationEndpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: body.toString(),
    signal: AbortSignal.timeout(5000),
  });
  // Errors silently swallowed — revocation is best-effort
}
