import type { Finding } from './types.js';
import type { AuthenticatedContext } from '../auth/types.js';
import { redactSensitive } from '../assessment/evidence.js';
import { isBlockedHost } from '../ssrf.js';

export interface AuthSecurityTest {
  test_id: string;
  name: string;
  run(ctx: AuthenticatedContext): Promise<Finding>;
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function base(test_id: string, name: string, overrides: Partial<Finding>): Finding {
  return {
    test_id,
    name,
    category: 'authentication',
    status: 'error',
    severity: 'medium',
    confidence: 'high',
    finding: 'Check did not complete',
    ...overrides,
  };
}

function authorizedHeaders(ctx: AuthenticatedContext): Record<string, string> {
  // SECURITY: Authorization header contains the real token — used only for HTTP requests, never serialized
  return {
    Authorization: `${ctx.tokenType} ${ctx.accessToken}`,
    Accept: 'application/json',
  };
}

// ─── AUTH-020: Token Metadata Analysis ───────────────────────────────────────

const auth020: AuthSecurityTest = {
  test_id: 'AUTH-020',
  name: 'Token Metadata Analysis',
  async run(ctx) {
    const meta = ctx.tokenMetadata;

    if (meta.tokenType === 'opaque') {
      return base('AUTH-020', 'Token Metadata Analysis', {
        status: 'info',
        severity: 'informational',
        confidence: 'high',
        finding: 'Access token is opaque (not a JWT). Structural analysis not applicable.',
        detail: 'Opaque tokens cannot be analysed structurally without server-side introspection.',
      });
    }

    const alg = meta.algorithm ?? '';
    const weakAlgs = ['HS256', 'HS384', 'HS512', 'none', ''];
    const strongAlgs = ['RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512', 'ES256', 'ES384', 'ES512', 'EdDSA'];

    const issues: string[] = [];

    if (alg === 'none') {
      issues.push('Algorithm is "none" — token has no cryptographic signature');
    } else if (weakAlgs.includes(alg)) {
      issues.push(`Algorithm ${alg} is symmetric — the signing secret must be kept secure on both the issuer and all verifying parties`);
    } else if (!strongAlgs.includes(alg)) {
      issues.push(`Algorithm ${alg} is not a recognised strong asymmetric algorithm`);
    }

    if (meta.expiresAt !== undefined) {
      const issuedAt = meta.issuedAt ?? (meta.expiresAt - (meta.expiresInSeconds ?? 0));
      const lifetimeSec = meta.expiresAt - issuedAt;
      if (lifetimeSec > 86400) {
        issues.push(`Token lifetime ${Math.round(lifetimeSec / 3600)}h exceeds the 24-hour best-practice maximum`);
      }
    } else {
      issues.push('Token has no expiry (exp claim is missing)');
    }

    const evidence = `Token type: JWT\nAlgorithm: ${alg || '(none)'}\nIssuer: ${meta.issuer ?? 'n/a'}\nExpiry: ${meta.expiresAt ? new Date(meta.expiresAt * 1000).toISOString() : 'none'}\nKey ID: ${meta.keyId ?? 'n/a'}\nAuthorization: Bearer [REDACTED]`;

    if (alg === 'none') {
      return base('AUTH-020', 'Token Metadata Analysis', {
        status: 'fail',
        severity: 'critical',
        confidence: 'confirmed',
        finding: 'JWT uses "alg: none" — the token has no cryptographic signature and can be forged.',
        detail: issues.join('. '),
        evidence,
        remediation: 'Reject any token where alg is "none". Enforce RS256 or ES256 on the authorisation server and validate alg on every verifying service.',
        owasp_mapping: 'A02:2021 – Cryptographic Failures',
        cwe: 'CWE-347',
        references: [{ label: 'JWT alg:none attack', url: 'https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/' }],
      });
    }

    if (issues.length > 0) {
      return base('AUTH-020', 'Token Metadata Analysis', {
        status: 'warn',
        severity: 'medium',
        confidence: 'high',
        finding: `JWT metadata observation: ${issues[0]}`,
        detail: issues.join('. '),
        evidence,
        owasp_mapping: 'A02:2021 – Cryptographic Failures',
        cwe: 'CWE-347',
      });
    }

    return base('AUTH-020', 'Token Metadata Analysis', {
      status: 'pass',
      severity: 'informational',
      confidence: 'high',
      finding: `JWT uses ${alg}${meta.expiresAt ? `, expires ${new Date(meta.expiresAt * 1000).toISOString()}` : ''}`,
      evidence,
    });
  },
};

// ─── AUTH-021: Granted Scope Analysis ────────────────────────────────────────

const SENSITIVE_SCOPE_PATTERNS = [
  'admin', 'root', 'superuser', 'write', 'delete', 'manage',
  'offline_access', 'full-access', 'full_access', 'all', 'sudo',
  'global', 'impersonate',
];

const auth021: AuthSecurityTest = {
  test_id: 'AUTH-021',
  name: 'Granted Scope Analysis',
  async run(ctx) {
    const grantedScopes = ctx.tokenMetadata.scopes
      ?? ctx.requestedScopes.split(' ').filter(Boolean);

    const sensitiveGranted = grantedScopes.filter(s =>
      SENSITIVE_SCOPE_PATTERNS.some(p => s.toLowerCase().includes(p))
    );

    const evidence = redactSensitive(
      `Requested scopes: ${ctx.requestedScopes}\nGranted scopes: ${grantedScopes.join(' ')}\nAuthorization: Bearer [REDACTED]`
    );

    if (sensitiveGranted.length > 0) {
      return base('AUTH-021', 'Granted Scope Analysis', {
        status: 'warn',
        severity: 'medium',
        confidence: 'medium',
        finding: `Broad or sensitive scopes were granted: ${sensitiveGranted.join(', ')}`,
        detail: 'The token was issued scopes that may provide elevated or broad access. Verify that the minimum required privilege principle is enforced and that sensitive scopes are restricted to authorised clients.',
        evidence,
        remediation: 'Request only the scopes required for the specific operation. Restrict sensitive scopes to privileged client registrations.',
        owasp_mapping: 'A01:2021 – Broken Access Control',
        cwe: 'CWE-269',
      });
    }

    return base('AUTH-021', 'Granted Scope Analysis', {
      status: 'pass',
      severity: 'informational',
      confidence: 'high',
      finding: `Granted scopes appear appropriately limited (${grantedScopes.join(' ') || 'none'})`,
      evidence,
    });
  },
};

// ─── AUTH-022: Anonymous vs. Authenticated Access ─────────────────────────────

const auth022: AuthSecurityTest = {
  test_id: 'AUTH-022',
  name: 'Anonymous vs. Authenticated Access',
  async run(ctx) {
    const targetUrl = ctx.apiUrl ?? `https://${ctx.domain}`;

    let target: URL;
    try {
      target = new URL(targetUrl);
    } catch {
      return base('AUTH-022', 'Anonymous vs. Authenticated Access', {
        status: 'not_applicable',
        severity: 'informational',
        finding: 'No valid API URL available for anonymous/authenticated comparison.',
      });
    }

    if (isBlockedHost(target.hostname)) {
      return base('AUTH-022', 'Anonymous vs. Authenticated Access', {
        status: 'error',
        severity: 'informational',
        finding: 'Target host is not reachable from the assessment scanner.',
        errorReason: 'Host is in a blocked or private IP range.',
      });
    }

    const [anonSettled, authSettled] = await Promise.allSettled([
      fetch(targetUrl, { headers: { Accept: 'application/json' }, signal: AbortSignal.timeout(8000) }),
      // SECURITY: real token used only in this HTTP request — never logged or serialized
      fetch(targetUrl, { headers: authorizedHeaders(ctx), signal: AbortSignal.timeout(8000) }),
    ]);

    const anonStatus = anonSettled.status === 'fulfilled' ? anonSettled.value.status : null;
    const authStatus = authSettled.status === 'fulfilled' ? authSettled.value.status : null;

    const [anonBody, authBody] = await Promise.allSettled([
      anonSettled.status === 'fulfilled' ? anonSettled.value.text() : Promise.reject('no response'),
      authSettled.status === 'fulfilled' ? authSettled.value.text() : Promise.reject('no response'),
    ]);
    const anonLen = anonBody.status === 'fulfilled' ? anonBody.value.length : 0;
    const authLen = authBody.status === 'fulfilled' ? authBody.value.length : 0;

    const evidence = [
      `Target: ${targetUrl}`,
      `Anonymous:     HTTP ${anonStatus ?? 'error'}, body ${anonLen} bytes`,
      `Authenticated: HTTP ${authStatus ?? 'error'}, body ${authLen} bytes`,
      `Authorization: Bearer [REDACTED]`,
    ].join('\n');

    // Endpoint serves identical response regardless of auth — possible missing access control
    if (anonStatus !== null && authStatus !== null
        && anonStatus < 400 && authStatus < 400
        && anonLen === authLen) {
      return base('AUTH-022', 'Anonymous vs. Authenticated Access', {
        status: 'warn',
        severity: 'medium',
        confidence: 'medium',
        finding: `Endpoint returns identical responses anonymously and with authentication (HTTP ${anonStatus}, ${anonLen} bytes). Access control may not be enforced.`,
        detail: 'If this endpoint should require authentication, it may not be enforcing access control. If it is intentionally public this observation is informational.',
        evidence,
        owasp_mapping: 'A01:2021 – Broken Access Control',
        cwe: 'CWE-306',
      });
    }

    // Endpoint correctly requires auth
    if ((anonStatus === 401 || anonStatus === 403) && authStatus !== null && authStatus < 400) {
      return base('AUTH-022', 'Anonymous vs. Authenticated Access', {
        status: 'pass',
        severity: 'informational',
        confidence: 'high',
        finding: `Endpoint correctly rejects anonymous requests (HTTP ${anonStatus}) and accepts authenticated requests (HTTP ${authStatus}).`,
        evidence,
      });
    }

    return base('AUTH-022', 'Anonymous vs. Authenticated Access', {
      status: 'info',
      severity: 'informational',
      confidence: 'medium',
      finding: `Anonymous: HTTP ${anonStatus ?? 'error'} (${anonLen} bytes)  Authenticated: HTTP ${authStatus ?? 'error'} (${authLen} bytes)`,
      evidence,
    });
  },
};

// ─── AUTH-023: Token Lifetime Policy ─────────────────────────────────────────

const auth023: AuthSecurityTest = {
  test_id: 'AUTH-023',
  name: 'Token Lifetime Policy',
  async run(ctx) {
    const meta = ctx.tokenMetadata;
    const lifetime = meta.expiresInSeconds;

    if (lifetime === undefined) {
      return base('AUTH-023', 'Token Lifetime Policy', {
        status: 'warn',
        severity: 'medium',
        confidence: 'medium',
        finding: 'Token lifetime could not be determined — neither expires_in nor the exp claim is present.',
        detail: 'Without a defined expiry, the token may be long-lived or non-expiring, increasing the blast radius of a credential theft.',
        evidence: `Token type: ${meta.tokenType}\nexpires_in: not provided\nexp claim: not present\nAuthorization: Bearer [REDACTED]`,
        remediation: 'Set an explicit token lifetime using the expires_in response field and an exp claim in the JWT payload.',
        owasp_mapping: 'A07:2021 – Identification and Authentication Failures',
        cwe: 'CWE-613',
      });
    }

    const hours = lifetime / 3600;
    const evidence = `Token lifetime: ${lifetime}s (${hours.toFixed(1)}h)\nAuthorization: Bearer [REDACTED]`;

    if (lifetime <= 0) {
      return base('AUTH-023', 'Token Lifetime Policy', {
        status: 'warn',
        severity: 'low',
        confidence: 'high',
        finding: 'Token has already expired at the time of assessment.',
        evidence,
      });
    }

    if (lifetime > 86400) {
      return base('AUTH-023', 'Token Lifetime Policy', {
        status: 'warn',
        severity: 'medium',
        confidence: 'high',
        finding: `Token lifetime is ${hours.toFixed(1)} hours — exceeds the 24-hour best-practice maximum.`,
        detail: 'Long-lived access tokens increase the blast radius of credential theft. Prefer short-lived tokens (≤ 1 hour) combined with refresh token rotation.',
        evidence,
        remediation: 'Reduce access token lifetime to 1 hour or less. Implement refresh token rotation with short refresh token lifetimes.',
        owasp_mapping: 'A07:2021 – Identification and Authentication Failures',
        cwe: 'CWE-613',
        references: [
          { label: 'OAuth 2.0 Security Best Current Practice §4.2.2', url: 'https://datatracker.ietf.org/doc/html/rfc9700#section-4.2.2' },
        ],
      });
    }

    return base('AUTH-023', 'Token Lifetime Policy', {
      status: 'pass',
      severity: 'informational',
      confidence: 'high',
      finding: `Token lifetime is ${hours.toFixed(1)} hours — within acceptable range.`,
      evidence,
    });
  },
};

// ─── Exports ──────────────────────────────────────────────────────────────────

export const AUTHENTICATED_TESTS: AuthSecurityTest[] = [auth020, auth021, auth022, auth023];

export async function runAuthenticatedTests(ctx: AuthenticatedContext): Promise<Finding[]> {
  const results = await Promise.allSettled(AUTHENTICATED_TESTS.map(t => t.run(ctx)));
  return results.map((r, i) => {
    if (r.status === 'fulfilled') return r.value;
    return base(AUTHENTICATED_TESTS[i].test_id, AUTHENTICATED_TESTS[i].name, {
      status: 'error',
      finding: 'Authenticated test threw an unexpected error.',
      errorReason: 'Internal error during authenticated test execution.',
    });
  });
}
