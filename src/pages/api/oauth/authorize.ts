export const prerender = false;

import type { APIRoute } from 'astro';
import { isBlockedHost, parseAuthUrl } from '@/lib/ssrf.js';
import { discoverOIDC } from '@/lib/auth/oidc.js';
import { generateCodeVerifier, generateCodeChallenge, generateState, generateNonce } from '@/lib/auth/pkce.js';
import type { OAuthFlowState } from '@/lib/auth/types.js';

interface KVNamespace {
  get(key: string): Promise<string | null>;
  put(key: string, value: string, opts?: { expirationTtl?: number }): Promise<void>;
  delete(key: string): Promise<void>;
}

function jsonError(message: string, status: number): Response {
  return new Response(JSON.stringify({ error: message }), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

export const POST: APIRoute = async ({ request, url, locals }) => {
  const kv = (locals as Record<string, unknown>)?.runtime
    ? ((locals as { runtime: { env: Record<string, KVNamespace> } }).runtime.env?.RATE_LIMIT_KV)
    : undefined;

  if (!kv) return jsonError('KV binding not available', 503);

  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return jsonError('Invalid JSON body', 400);
  }

  const { issuer, clientId, scopes, domain, apiUrl, authUrl } =
    body as Record<string, string | undefined>;

  if (!issuer || typeof issuer !== 'string')   return jsonError('issuer is required', 400);
  if (!clientId || typeof clientId !== 'string') return jsonError('clientId is required', 400);
  if (!domain || typeof domain !== 'string')   return jsonError('domain is required', 400);

  // Validate issuer — must be HTTPS and not a blocked/private host
  let issuerUrl: URL;
  try {
    issuerUrl = new URL(issuer);
  } catch {
    return jsonError('Invalid issuer URL', 400);
  }
  if (issuerUrl.protocol !== 'https:') return jsonError('Issuer must use HTTPS', 400);
  if (isBlockedHost(issuerUrl.hostname)) return jsonError('Issuer hostname is not allowed', 400);

  // Validate optional URLs via SSRF helper
  const safeApiUrl = apiUrl ? parseAuthUrl(apiUrl) : null;
  const safeAuthUrl = authUrl ? parseAuthUrl(authUrl) : null;

  // OIDC discovery
  let discovery;
  try {
    discovery = await discoverOIDC(issuer);
  } catch (e) {
    return jsonError(`OIDC discovery failed: ${e instanceof Error ? e.message : 'unknown'}`, 400);
  }

  // Generate PKCE and state
  // SECURITY: codeVerifier is secret — stored in KV only for the duration of the flow (600s)
  const codeVerifier  = await generateCodeVerifier();
  const codeChallenge = await generateCodeChallenge(codeVerifier);
  const state         = generateState();
  const nonce         = generateNonce();

  const redirectUri     = `${url.origin}/api/oauth/callback`;
  const requestedScopes = (scopes?.trim()) || 'openid';

  // Build authorization URL
  const authParams = new URLSearchParams({
    response_type: 'code',
    client_id:     clientId,
    redirect_uri:  redirectUri,
    scope:         requestedScopes,
    state,
    nonce,
    code_challenge:        codeChallenge,
    code_challenge_method: 'S256',
  });
  const authorizationUrl = `${discovery.authorization_endpoint}?${authParams.toString()}`;

  // Store flow state in KV (TTL 600s)
  const flowState: OAuthFlowState = {
    state,
    nonce,
    codeVerifier,       // SECURITY: secret
    domain,
    apiUrl:              safeApiUrl ?? undefined,
    authUrl:             safeAuthUrl ?? undefined,
    issuer,
    tokenEndpoint:       discovery.token_endpoint,
    jwksUri:             discovery.jwks_uri,
    revocationEndpoint:  discovery.revocation_endpoint,
    clientId,
    redirectUri,
    requestedScopes,
    expiresAt:           Date.now() + 600_000,
  };

  await kv.put(`oauth:${state}`, JSON.stringify(flowState), { expirationTtl: 600 });

  return new Response(JSON.stringify({ authorizationUrl }), {
    headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
  });
};
