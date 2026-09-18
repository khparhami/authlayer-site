export const prerender = false;

import type { APIRoute } from 'astro';
import { exchangeCode, revokeToken } from '@/lib/auth/oidc.js';
import { runScan, PAID_TESTS, classifyFinding } from '@/lib/checks/registry.js';
import { runAuthenticatedTests } from '@/lib/checks/authenticated.js';
import type { OAuthFlowState, AuthenticatedContext, AuthConnectionInfo } from '@/lib/auth/types.js';

interface KVNamespace {
  get(key: string): Promise<string | null>;
  put(key: string, value: string, opts?: { expirationTtl?: number }): Promise<void>;
  delete(key: string): Promise<void>;
}

function htmlError(message: string, status = 400): Response {
  const safe = message.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  return new Response(
    `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>Authentication Error</title></head><body><p>${safe}</p><p><a href="/tools/health-check">Return to assessment</a></p></body></html>`,
    { status, headers: { 'Content-Type': 'text/html;charset=utf-8', 'Cache-Control': 'no-store' } }
  );
}

export const GET: APIRoute = async ({ url, locals }) => {
  const kv = (locals as Record<string, unknown>)?.runtime
    ? ((locals as { runtime: { env: Record<string, KVNamespace> } }).runtime.env?.RATE_LIMIT_KV)
    : undefined;

  if (!kv) return htmlError('KV binding not available', 503);

  // Handle error redirects from the IdP
  const idpError = url.searchParams.get('error');
  if (idpError) {
    const desc = url.searchParams.get('error_description') ?? idpError;
    return htmlError(`Authorization was denied: ${desc}`);
  }

  // SECURITY: code is never logged
  const code  = url.searchParams.get('code');
  const state = url.searchParams.get('state');

  if (!code)  return htmlError('Missing authorization code');
  if (!state) return htmlError('Missing state parameter');

  // Read and immediately delete flow state (prevents replay)
  const raw = await kv.get(`oauth:${state}`);
  await kv.delete(`oauth:${state}`);

  if (!raw) return htmlError('OAuth flow state not found or expired. Please try again.');

  let flowState: OAuthFlowState;
  try {
    flowState = JSON.parse(raw) as OAuthFlowState;
  } catch {
    return htmlError('Invalid flow state');
  }

  if (flowState.state !== state) return htmlError('State mismatch — possible CSRF');
  if (Date.now() > flowState.expiresAt) return htmlError('OAuth flow expired. Please try again.');

  // Exchange authorization code for tokens
  // SECURITY: code and codeVerifier are never logged
  let tokenResult;
  try {
    tokenResult = await exchangeCode({
      tokenEndpoint: flowState.tokenEndpoint,
      code,                             // SECURITY: never log
      clientId:      flowState.clientId,
      redirectUri:   flowState.redirectUri,
      codeVerifier:  flowState.codeVerifier, // SECURITY: never log
    });
  } catch (e) {
    return htmlError(`Token exchange failed: ${e instanceof Error ? e.message : 'unknown'}`);
  }

  // Build authenticated context — SECURITY: this object must NEVER be serialized or stored
  const authCtx: AuthenticatedContext = {
    accessToken:     tokenResult.accessToken, // SECURITY: never log, never serialize
    tokenType:       tokenResult.tokenType,
    tokenMetadata:   tokenResult.metadata,
    domain:          flowState.domain,
    apiUrl:          flowState.apiUrl,
    authUrl:         flowState.authUrl,
    issuer:          flowState.issuer,
    clientId:        flowState.clientId,
    requestedScopes: flowState.requestedScopes,
  };

  const ctx = {
    domain:  flowState.domain,
    authUrl: flowState.authUrl ?? null,
    apiUrl:  flowState.apiUrl ?? null,
  };

  // Run base scan and authenticated tests in parallel
  const [scanResult, authFindings] = await Promise.all([
    runScan(ctx, PAID_TESTS),
    runAuthenticatedTests(authCtx),
  ]);

  // Revoke token immediately after tests (best-effort, fire-and-forget)
  // SECURITY: real token passed only to the revocation call — never stored
  if (flowState.revocationEndpoint) {
    revokeToken({
      revocationEndpoint: flowState.revocationEndpoint,
      token:     tokenResult.accessToken, // SECURITY: used only in this HTTP call
      clientId:  flowState.clientId,
    }).catch(() => { /* best-effort — revocation failure is non-fatal */ });
  }

  // Classify authenticated findings and merge with scan results
  const classifiedAuthFindings = authFindings.map(f => ({
    ...f,
    classification: classifyFinding(f),
  }));

  // Build safe AuthConnectionInfo — no tokens, safe to serialize
  const authConnection: AuthConnectionInfo = {
    issuer:           flowState.issuer,
    scopes:           tokenResult.scope?.split(' ').filter(Boolean)
                        ?? flowState.requestedScopes.split(' ').filter(Boolean),
    algorithm:        tokenResult.metadata.algorithm,
    expiresInSeconds: tokenResult.expiresIn,
    tokenType:        tokenResult.metadata.tokenType,
  };

  // Merge results — SECURITY: accessToken is NOT present in any serialized field
  const mergedResult = {
    ...scanResult,
    authenticated:  true,
    authConnection,
    findings:       [...scanResult.findings, ...classifiedAuthFindings],
    testsRun:       scanResult.testsRun + classifiedAuthFindings.length,
  };

  // Store under a single-use UUID (TTL 3600s)
  const resultId = crypto.randomUUID();
  await kv.put(`result:${resultId}`, JSON.stringify(mergedResult), { expirationTtl: 3600 });

  return new Response(null, {
    status: 302,
    headers: {
      Location:        `/tools/health-check?auth_result=${resultId}`,
      'Cache-Control': 'no-store',
    },
  });
};
