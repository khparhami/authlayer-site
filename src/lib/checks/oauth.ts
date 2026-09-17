import type { SecurityTest, Finding, ScanContext } from './types.js';

async function fetchWithTimeout(url: string, init: RequestInit = {}, ms = 6000): Promise<Response> {
  return fetch(url, { ...init, signal: AbortSignal.timeout(ms) });
}

const oidcDiscovery: SecurityTest = {
  test_id: 'AUTH-010',
  name: 'OIDC Discovery Endpoint',
  version: '1.0.0',
  category: 'oauth',
  severity: 'informational',
  confidence: 'confirmed',
  owasp_mapping: 'A07:2021',
  safe_for_production: true,
  requires_active_testing: false,
  async run({ domain }: ScanContext): Promise<Finding> {
    const base = {
      test_id: this.test_id, name: this.name, category: this.category,
      severity: this.severity, confidence: this.confidence,
      owasp_mapping: this.owasp_mapping,
      detail: "The OpenID Connect discovery document at /.well-known/openid-configuration exposes the authorization server's metadata including supported flows, scopes, and endpoints.",
      remediation: 'No action required if found. Review the metadata to ensure deprecated grant types are not advertised. Restrict the endpoint if it should not be publicly accessible.',
      references: [{ label: 'OpenID Connect Discovery 1.0', url: 'https://openid.net/specs/openid-connect-discovery-1_0.html' }],
    };
    try {
      const res = await fetchWithTimeout(`https://${domain}/.well-known/openid-configuration`);
      if (!res.ok) return { ...base, status: 'info', finding: 'No OIDC discovery endpoint found (not an identity provider, or hosted elsewhere)' };
      const meta = await res.json() as Record<string, unknown>;
      const issuer = typeof meta.issuer === 'string' ? meta.issuer : 'unknown';
      return { ...base, status: 'info', finding: `OIDC discovery found — issuer: ${issuer}` };
    } catch {
      return { ...base, status: 'info', finding: 'No OIDC discovery endpoint found or request failed' };
    }
  },
};

const pkceSupport: SecurityTest = {
  test_id: 'AUTH-010b',
  name: 'PKCE Enforcement',
  version: '1.0.0',
  category: 'oauth',
  severity: 'high',
  confidence: 'high',
  owasp_mapping: 'A07:2021',
  cwe: 'CWE-345',
  safe_for_production: true,
  requires_active_testing: false,
  async run({ domain }: ScanContext): Promise<Finding> {
    const base = {
      test_id: this.test_id, name: this.name, category: this.category,
      severity: this.severity, confidence: this.confidence,
      owasp_mapping: this.owasp_mapping, cwe: this.cwe,
      detail: 'PKCE (Proof Key for Code Exchange) prevents authorization code interception attacks. For public clients (SPAs, mobile apps) PKCE is mandatory per OAuth 2.1.',
      remediation: 'Require PKCE for all public clients. In the OIDC metadata, code_challenge_methods_supported should include S256. In Auth0: Applications → Advanced → PKCE Enabled.',
      references: [
        { label: 'RFC 7636 — PKCE', url: 'https://tools.ietf.org/html/rfc7636' },
        { label: 'OAuth 2.1 Draft', url: 'https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1' },
      ],
    };
    try {
      const res = await fetchWithTimeout(`https://${domain}/.well-known/openid-configuration`);
      if (!res.ok) return { ...base, status: 'info', finding: 'No OIDC discovery endpoint — PKCE check not applicable', confidence: 'informational' };
      const meta = await res.json() as { code_challenge_methods_supported?: string[] };
      const methods = meta.code_challenge_methods_supported ?? [];
      if (methods.includes('S256')) return { ...base, status: 'pass', finding: 'PKCE S256 is listed in supported code challenge methods' };
      if (methods.length > 0) return { ...base, status: 'warn', finding: `PKCE methods found but S256 not listed: ${methods.join(', ')}`, confidence: 'medium' };
      return { ...base, status: 'fail', finding: 'OIDC metadata does not advertise PKCE support (code_challenge_methods_supported absent)' };
    } catch {
      return { ...base, status: 'error', finding: 'Could not evaluate PKCE support', errorReason: 'Request failed or timed out.' };
    }
  },
};

const grantTypes: SecurityTest = {
  test_id: 'AUTH-010c',
  name: 'Deprecated OAuth Grant Types',
  version: '1.0.0',
  category: 'oauth',
  severity: 'high',
  confidence: 'confirmed',
  owasp_mapping: 'A07:2021',
  cwe: 'CWE-287',
  safe_for_production: true,
  requires_active_testing: false,
  async run({ domain }: ScanContext): Promise<Finding> {
    const base = {
      test_id: this.test_id, name: this.name, category: this.category,
      severity: this.severity, confidence: this.confidence,
      owasp_mapping: this.owasp_mapping, cwe: this.cwe,
      detail: 'The implicit grant and password grant (Resource Owner Password Credentials) are deprecated in OAuth 2.1. Implicit flow exposes tokens in URL fragments; the password grant requires clients to handle user credentials directly.',
      remediation: "Migrate implicit flow clients to Authorization Code + PKCE. Replace password grant with device authorization flow or Authorization Code flow.",
      references: [
        { label: 'OAuth 2.1 — Removed Flows', url: 'https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1#section-1.3' },
        { label: 'RFC 6749 — OAuth 2.0', url: 'https://tools.ietf.org/html/rfc6749' },
      ],
    };
    try {
      const res = await fetchWithTimeout(`https://${domain}/.well-known/openid-configuration`);
      if (!res.ok) return { ...base, status: 'info', finding: 'No OIDC discovery endpoint — grant type check not applicable', confidence: 'informational' };
      const meta = await res.json() as { grant_types_supported?: string[] };
      const grants = meta.grant_types_supported ?? [];
      const deprecated = grants.filter(g => g === 'implicit' || g === 'password');
      if (deprecated.length > 0) return { ...base, status: 'fail', finding: `Deprecated grant type(s) advertised: ${deprecated.join(', ')}` };
      return { ...base, status: 'pass', finding: `Supported grants: ${grants.join(', ') || 'not specified'} — no deprecated flows detected` };
    } catch {
      return { ...base, status: 'error', finding: 'Could not evaluate OAuth grant types', errorReason: 'Request failed or timed out.' };
    }
  },
};

const webauthnSupport: SecurityTest = {
  test_id: 'AUTH-007',
  name: 'Passkey / WebAuthn Support',
  version: '1.0.0',
  category: 'oauth',
  severity: 'informational',
  confidence: 'medium',
  owasp_mapping: 'A07:2021',
  safe_for_production: true,
  requires_active_testing: false,
  async run({ domain }: ScanContext): Promise<Finding> {
    const base = {
      test_id: this.test_id, name: this.name, category: this.category,
      severity: this.severity, confidence: this.confidence,
      owasp_mapping: this.owasp_mapping,
      detail: 'Passkeys (FIDO2/WebAuthn) are phishing-resistant authenticators that cannot be stolen via standard phishing or replayed across origins. NIST SP 800-63-4 classifies synced passkeys as meeting AAL2.',
      remediation: 'Implement WebAuthn using the browser Credential Management API. Libraries: SimpleWebAuthn (Node.js), py_webauthn (Python). For hosted identity: Okta, Auth0, and Microsoft Entra support passkeys natively.',
      references: [
        { label: 'W3C Web Authentication', url: 'https://www.w3.org/TR/webauthn-3/' },
        { label: 'FIDO2 Overview', url: 'https://fidoalliance.org/fido2/' },
        { label: 'NIST SP 800-63B-4', url: 'https://pages.nist.gov/800-63-4/sp800-63b.html' },
      ],
    };
    try {
      const res = await fetchWithTimeout(`https://${domain}/.well-known/webauthn`, {}, 5000);
      if (res.ok) return { ...base, status: 'pass', finding: 'WebAuthn /.well-known/webauthn endpoint is present' };
      return { ...base, status: 'info', finding: 'No WebAuthn well-known endpoint detected — passkey support may still exist in the application', confidence: 'low' };
    } catch {
      return { ...base, status: 'info', finding: 'Could not check WebAuthn endpoint', confidence: 'low' };
    }
  },
};

const IDP_SIGNATURES: Array<{ name: string; patterns: RegExp[] }> = [
  { name: 'Auth0',             patterns: [/cdn\.auth0\.com|auth0\.js|\.auth0\.com/i] },
  { name: 'Okta',              patterns: [/\.okta\.com|\.okta-emea\.com|okta-auth-js/i] },
  { name: 'Microsoft Entra',   patterns: [/login\.microsoftonline\.com|aadcdn\.msftauth|msal\.js|\.b2clogin\.com/i] },
  { name: 'Google Identity',   patterns: [/accounts\.google\.com|gsi\/client|google-signin/i] },
  { name: 'AWS Cognito',       patterns: [/cognito-idp\.|amazoncognito\.com/i] },
  { name: 'Ping Identity',     patterns: [/\.pingone\.com|\.pingidentity\.com/i] },
  { name: 'OneLogin',          patterns: [/\.onelogin\.com/i] },
  { name: 'Keycloak',          patterns: [/\/auth\/realms\/|keycloak\.js/i] },
  { name: 'Firebase Auth',     patterns: [/identitytoolkit\.googleapis\.com|firebaseapp\.com\/__|firebase-auth/i] },
  { name: 'Cloudflare Access', patterns: [/cloudflareaccess\.com/i] },
  { name: 'WorkOS',            patterns: [/workos\.com|authkit\.com/i] },
  { name: 'Clerk',             patterns: [/clerk\.dev|clerk\.com|\.clerk\.accounts/i] },
  { name: 'Stytch',            patterns: [/stytch\.com/i] },
  { name: 'Passage (1Password)', patterns: [/passage\.id|passageidentity\.com/i] },
];

const PASSKEY_CAPABLE_IDPS = new Set([
  'Auth0', 'Okta', 'Microsoft Entra', 'Google Identity', 'AWS Cognito',
  'Ping Identity', 'WorkOS', 'Clerk', 'Stytch', 'Passage (1Password)', 'Cloudflare Access',
]);

const oauthUsage: SecurityTest = {
  test_id: 'AUTH-008',
  name: 'OAuth / OIDC Usage',
  version: '1.0.0',
  category: 'oauth',
  severity: 'informational',
  confidence: 'medium',
  owasp_mapping: 'A07:2021',
  safe_for_production: true,
  requires_active_testing: false,
  async run({ domain, authUrl }: ScanContext): Promise<Finding> {
    const base = {
      test_id: this.test_id, name: this.name, category: this.category,
      severity: this.severity, confidence: this.confidence,
      owasp_mapping: this.owasp_mapping,
      detail: 'Detecting whether the site uses OAuth 2.0 or OpenID Connect helps understand the overall authentication architecture and where to direct security configuration effort.',
      remediation: 'If OAuth is in use, ensure you are using Authorization Code + PKCE (not implicit flow), validate state and nonce parameters, and bind tokens to the client that requested them.',
      references: [
        { label: 'RFC 6749 — OAuth 2.0', url: 'https://tools.ietf.org/html/rfc6749' },
        { label: 'OpenID Connect Core 1.0', url: 'https://openid.net/specs/openid-connect-core-1_0.html' },
      ],
    };
    try {
      const pageUrls = [`https://${domain}/`, `https://${domain}/login`, `https://${domain}/signin`, ...(authUrl ? [authUrl] : [])];
      const [discoveryRes, ...pageResponses] = await Promise.allSettled([
        fetchWithTimeout(`https://${domain}/.well-known/openid-configuration`, {}, 5000),
        ...pageUrls.map(u => fetchWithTimeout(u, { redirect: 'manual' }, 5000)),
      ]);
      if (discoveryRes.status === 'fulfilled' && discoveryRes.value.ok) {
        return { ...base, status: 'pass', finding: 'OIDC discovery endpoint found — site acts as or integrates an OAuth/OIDC authorization server' };
      }
      const oauthPatterns = /oauth|client_id|response_type=code|response_type=token|authorize\?|openid|oidc/i;
      const socialPatterns = /sign.?in with|continue with|login with|connect with.*(google|github|microsoft|apple|facebook|twitter|slack)/i;
      for (const r of pageResponses) {
        if (r.status !== 'fulfilled') continue;
        const text = await r.value.text().catch(() => '');
        if (oauthPatterns.test(text)) return { ...base, status: 'pass', finding: 'OAuth-related parameters or endpoints detected in page content' };
        if (socialPatterns.test(text)) return { ...base, status: 'pass', finding: 'Social/federated login options detected — OAuth delegation in use' };
      }
      return { ...base, status: 'info', finding: 'No OAuth or OIDC usage detected — may use session-based or custom authentication', confidence: 'low' };
    } catch {
      return { ...base, status: 'error', finding: 'Could not determine OAuth usage', errorReason: 'Request failed or timed out.' };
    }
  },
};

const idpDetection: SecurityTest = {
  test_id: 'EXT-004a',
  name: 'Identity Provider Detection',
  version: '1.0.0',
  category: 'oauth',
  severity: 'informational',
  confidence: 'medium',
  owasp_mapping: 'A05:2021',
  safe_for_production: true,
  requires_active_testing: false,
  async run({ domain, authUrl }: ScanContext): Promise<Finding> {
    const base = {
      test_id: this.test_id, name: this.name, category: this.category,
      severity: this.severity, confidence: this.confidence,
      owasp_mapping: this.owasp_mapping,
      detail: 'Identifying the identity provider in use helps understand the authentication architecture and where to direct security configuration effort.',
      remediation: 'No action required from detection alone. Ensure your IdP is on a supported version, MFA enforcement is configured, and admin access to the IdP console is protected with phishing-resistant authentication.',
      references: [],
    };
    try {
      const pageUrls = [...(authUrl ? [authUrl] : []), `https://${domain}/`, `https://${domain}/login`, `https://${domain}/signin`];
      const pages = await Promise.allSettled(
        pageUrls.map(u => fetchWithTimeout(u, { redirect: 'manual' }, 6000).then(r => r.text()))
      );
      let oidcIssuer = '';
      try {
        const disc = await fetchWithTimeout(`https://${domain}/.well-known/openid-configuration`, {}, 4000);
        if (disc.ok) {
          const meta = await disc.json() as { issuer?: string };
          oidcIssuer = meta.issuer ?? '';
        }
      } catch { /* skip */ }
      const haystack = pages
        .filter((r): r is PromiseFulfilledResult<string> => r.status === 'fulfilled')
        .map(r => r.value).join('\n') + '\n' + oidcIssuer;
      const detected = IDP_SIGNATURES
        .filter(idp => idp.patterns.some(p => p.test(haystack)))
        .map(idp => idp.name);
      if (detected.length === 0) return { ...base, status: 'info', finding: 'No known identity provider fingerprint detected — may use a custom or less common IdP', confidence: 'low' };
      return { ...base, status: 'pass', finding: `Identity provider detected: ${detected.join(', ')}` };
    } catch {
      return { ...base, status: 'error', finding: 'Could not scan for identity provider fingerprints', errorReason: 'Request failed or timed out.' };
    }
  },
};

const phishingResistance: SecurityTest = {
  test_id: 'AUTH-007b',
  name: 'Phishing-Resistant Authentication',
  version: '1.0.0',
  category: 'oauth',
  severity: 'informational',
  confidence: 'medium',
  owasp_mapping: 'A07:2021',
  cwe: 'CWE-308',
  safe_for_production: true,
  requires_active_testing: false,
  async run({ domain, authUrl }: ScanContext): Promise<Finding> {
    const base = {
      test_id: this.test_id, name: this.name, category: this.category,
      severity: this.severity, confidence: this.confidence,
      owasp_mapping: this.owasp_mapping, cwe: this.cwe,
      detail: 'Phishing-resistant authentication (passkeys, FIDO2 hardware keys) binds the credential to the origin domain at the cryptographic level. NIST SP 800-63-4 requires phishing-resistant MFA for AAL3 and endorses it for AAL2.',
      remediation: 'Implement WebAuthn via the browser Credential Management API or a hosted IdP with native passkey support (Okta, Auth0, Microsoft Entra, Google Identity).',
      references: [
        { label: 'W3C Web Authentication', url: 'https://www.w3.org/TR/webauthn-3/' },
        { label: 'NIST SP 800-63B-4 — AAL2', url: 'https://pages.nist.gov/800-63-4/sp800-63b.html#aal2' },
      ],
    };
    try {
      const pageUrls = [...(authUrl ? [authUrl] : []), `https://${domain}/login`, `https://${domain}/signin`, `https://${domain}/`];
      const [wellKnown, ...pages] = await Promise.allSettled([
        fetchWithTimeout(`https://${domain}/.well-known/webauthn`, {}, 5000),
        ...pageUrls.map(u => fetchWithTimeout(u, { redirect: 'manual' }, 6000).then(r => r.text())),
      ]);
      const wellKnownFound = wellKnown.status === 'fulfilled' && wellKnown.value.ok;
      const corpus = pages
        .filter((r): r is PromiseFulfilledResult<string> => r.status === 'fulfilled')
        .map(r => r.value).join('\n');
      const webauthnApi = /navigator\.credentials|PublicKeyCredential|webauthn|authenticatorAttachment/i.test(corpus);
      const passkeyUi   = /passkey|use your fingerprint|face id|touch id|security key|sign in with a passkey|biometric/i.test(corpus);
      const scriptAsset = /src=["'][^"']*(?:webauthn|passkey|fido)[^"']*\.js[^"']*["']/i.test(corpus);
      let idpSignal = '';
      for (const idp of IDP_SIGNATURES) {
        if (PASSKEY_CAPABLE_IDPS.has(idp.name) && idp.patterns.some(p => p.test(corpus))) {
          idpSignal = idp.name; break;
        }
      }
      const signals: string[] = [];
      if (wellKnownFound) signals.push('/.well-known/webauthn endpoint');
      if (webauthnApi)    signals.push('WebAuthn API in page scripts');
      if (passkeyUi)      signals.push('passkey/biometric UI language');
      if (scriptAsset)    signals.push('WebAuthn script assets referenced');
      if (idpSignal)      signals.push(`${idpSignal} (passkey-capable IdP detected)`);
      if (signals.length >= 2) return { ...base, status: 'pass', finding: `Phishing-resistant auth signals: ${signals.join(', ')}` };
      if (signals.length === 1) return { ...base, status: 'warn', finding: `Partial signal — ${signals[0]} detected but not confirmed end-to-end`, confidence: 'low' };
      return { ...base, status: 'info', finding: 'No passkey or WebAuthn signals detected — login page may be a client-rendered SPA; manual verification recommended', confidence: 'low' };
    } catch {
      return { ...base, status: 'error', finding: 'Could not evaluate phishing-resistant authentication signals', errorReason: 'Request failed or timed out.' };
    }
  },
};

export const OAUTH_TESTS: SecurityTest[] = [
  oidcDiscovery, pkceSupport, grantTypes, webauthnSupport, oauthUsage, idpDetection, phishingResistance,
];
