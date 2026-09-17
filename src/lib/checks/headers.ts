import type { SecurityTest, Finding, ScanContext } from './types.js';

async function fetchWithTimeout(url: string, init: RequestInit = {}, ms = 8000): Promise<Response> {
  return fetch(url, { ...init, signal: AbortSignal.timeout(ms) });
}

const clickjacking: SecurityTest = {
  test_id: 'WEB-004',
  name: 'Clickjacking Protection',
  version: '1.0.0',
  category: 'headers',
  severity: 'medium',
  confidence: 'confirmed',
  owasp_mapping: 'A05:2021',
  cwe: 'CWE-1021',
  safe_for_production: true,
  requires_active_testing: false,
  async run({ domain }: ScanContext): Promise<Finding> {
    const base = {
      test_id: this.test_id, name: this.name, category: this.category,
      severity: this.severity, confidence: this.confidence,
      owasp_mapping: this.owasp_mapping, cwe: this.cwe,
      detail: 'Without frame protection, attackers can embed your login page in a transparent iframe and trick users into clicking buttons they cannot see — submitting credentials to the attacker.',
      remediation: "Add `X-Frame-Options: DENY` or include `frame-ancestors 'none'` in your Content-Security-Policy. CSP frame-ancestors takes precedence over X-Frame-Options in modern browsers.",
      references: [
        { label: 'OWASP Clickjacking Defence', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html' },
        { label: 'MDN: X-Frame-Options', url: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options' },
      ],
    };
    try {
      const res = await fetchWithTimeout(`https://${domain}/`);
      const xfo = res.headers.get('x-frame-options');
      const csp = res.headers.get('content-security-policy') ?? '';
      if (xfo) return { ...base, status: 'pass', finding: `X-Frame-Options: ${xfo}` };
      if (/frame-ancestors/i.test(csp)) return { ...base, status: 'pass', finding: 'CSP frame-ancestors directive is present' };
      return { ...base, status: 'fail', finding: 'No X-Frame-Options or CSP frame-ancestors directive found' };
    } catch {
      return { ...base, status: 'error', finding: 'Could not fetch headers to check clickjacking protection', errorReason: 'Domain unreachable or request timed out.' };
    }
  },
};

const cspQuality: SecurityTest = {
  test_id: 'EXT-003a',
  name: 'Content-Security-Policy Strength',
  version: '1.0.0',
  category: 'headers',
  severity: 'high',
  confidence: 'high',
  owasp_mapping: 'A05:2021',
  cwe: 'CWE-693',
  safe_for_production: true,
  requires_active_testing: false,
  async run({ domain }: ScanContext): Promise<Finding> {
    const base = {
      test_id: this.test_id, name: this.name, category: this.category,
      severity: this.severity, confidence: this.confidence,
      owasp_mapping: this.owasp_mapping, cwe: this.cwe,
      detail: "A weak CSP with unsafe-inline or unsafe-eval negates XSS protection. Wildcard sources (*) allow loading from any origin. A missing CSP means the browser applies no source restrictions.",
      remediation: "Build a strict CSP: `default-src 'self'; script-src 'self' 'nonce-{random}'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; frame-ancestors 'none'`. Use a nonce for inline scripts rather than unsafe-inline.",
      references: [
        { label: 'MDN: Content-Security-Policy', url: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP' },
        { label: 'OWASP CSP Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html' },
        { label: 'W3C CSP Level 3', url: 'https://www.w3.org/TR/CSP3/' },
      ],
    };
    try {
      const res = await fetchWithTimeout(`https://${domain}/`);
      const csp = res.headers.get('content-security-policy');
      if (!csp) return { ...base, status: 'fail', finding: 'No Content-Security-Policy header found' };
      const issues: string[] = [];
      if (/unsafe-inline/i.test(csp)) issues.push("'unsafe-inline'");
      if (/unsafe-eval/i.test(csp)) issues.push("'unsafe-eval'");
      if (/\*\s*(;|$)/.test(csp) || /src\s+\*/i.test(csp)) issues.push('wildcard source (*)');
      if (issues.length > 0) return { ...base, status: 'warn', finding: `CSP present but contains weakening directives: ${issues.join(', ')}`, confidence: 'high' };
      return { ...base, status: 'pass', finding: 'CSP present with no detected unsafe directives' };
    } catch {
      return { ...base, status: 'error', finding: 'Could not fetch CSP header', errorReason: 'Domain unreachable or request timed out.' };
    }
  },
};

const referrerPolicy: SecurityTest = {
  test_id: 'EXT-003b',
  name: 'Referrer-Policy',
  version: '1.0.0',
  category: 'headers',
  severity: 'medium',
  confidence: 'confirmed',
  owasp_mapping: 'A05:2021',
  cwe: 'CWE-200',
  safe_for_production: true,
  requires_active_testing: false,
  async run({ domain }: ScanContext): Promise<Finding> {
    const base = {
      test_id: this.test_id, name: this.name, category: this.category,
      severity: this.severity, confidence: this.confidence,
      owasp_mapping: this.owasp_mapping, cwe: this.cwe,
      detail: 'Without a Referrer-Policy, browsers may include full URLs (including query params with tokens) in the Referer header when navigating away. This can leak session IDs and OAuth state to third-party analytics.',
      remediation: 'Add `Referrer-Policy: strict-origin-when-cross-origin` or `no-referrer`. Avoid `unsafe-url` which sends full URLs including fragments and query strings.',
      references: [
        { label: 'MDN: Referrer-Policy', url: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy' },
        { label: 'W3C Referrer Policy', url: 'https://www.w3.org/TR/referrer-policy/' },
      ],
    };
    try {
      const res = await fetchWithTimeout(`https://${domain}/`);
      const rp = res.headers.get('referrer-policy');
      if (!rp) return { ...base, status: 'warn', finding: 'Referrer-Policy header is missing — browsers default to no-referrer-when-downgrade', confidence: 'medium' };
      if (/unsafe-url/i.test(rp)) return { ...base, status: 'fail', finding: `Referrer-Policy is set to unsafe-url — full URLs including query strings are sent` };
      return { ...base, status: 'pass', finding: `Referrer-Policy: ${rp}` };
    } catch {
      return { ...base, status: 'error', finding: 'Could not check Referrer-Policy', errorReason: 'Domain unreachable or request timed out.' };
    }
  },
};

const permissionsPolicy: SecurityTest = {
  test_id: 'EXT-003c',
  name: 'Permissions-Policy',
  version: '1.0.0',
  category: 'headers',
  severity: 'low',
  confidence: 'confirmed',
  owasp_mapping: 'A05:2021',
  cwe: 'CWE-693',
  safe_for_production: true,
  requires_active_testing: false,
  async run({ domain }: ScanContext): Promise<Finding> {
    const base = {
      test_id: this.test_id, name: this.name, category: this.category,
      severity: this.severity, confidence: this.confidence,
      owasp_mapping: this.owasp_mapping, cwe: this.cwe,
      detail: 'Permissions-Policy restricts browser features (camera, microphone, geolocation) on auth pages. Without it, third-party scripts embedded in the page can request sensitive device access.',
      remediation: 'Add `Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()` to restrict features not needed on auth pages.',
      references: [
        { label: 'MDN: Permissions-Policy', url: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy' },
        { label: 'W3C Permissions Policy', url: 'https://www.w3.org/TR/permissions-policy/' },
      ],
    };
    try {
      const res = await fetchWithTimeout(`https://${domain}/`);
      const pp = res.headers.get('permissions-policy');
      if (!pp) return { ...base, status: 'warn', finding: 'Permissions-Policy header is absent — browser features are unrestricted', confidence: 'medium' };
      return { ...base, status: 'pass', finding: `Permissions-Policy is configured` };
    } catch {
      return { ...base, status: 'error', finding: 'Could not check Permissions-Policy', errorReason: 'Domain unreachable or request timed out.' };
    }
  },
};

const coop: SecurityTest = {
  test_id: 'EXT-003d',
  name: 'Cross-Origin Isolation',
  version: '1.0.0',
  category: 'headers',
  severity: 'medium',
  confidence: 'confirmed',
  owasp_mapping: 'A05:2021',
  cwe: 'CWE-693',
  safe_for_production: true,
  requires_active_testing: false,
  async run({ domain }: ScanContext): Promise<Finding> {
    const base = {
      test_id: this.test_id, name: this.name, category: this.category,
      severity: this.severity, confidence: this.confidence,
      owasp_mapping: this.owasp_mapping, cwe: this.cwe,
      detail: 'Cross-Origin-Opener-Policy (COOP) prevents other origins from getting a reference to your window object, blocking cross-origin attacks like Spectre variants. CORP restricts which origins can load your resources.',
      remediation: 'Add `Cross-Origin-Opener-Policy: same-origin` on auth pages. For APIs serving resources to specific origins, add `Cross-Origin-Resource-Policy: same-site`.',
      references: [
        { label: 'MDN: Cross-Origin-Opener-Policy', url: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy' },
        { label: 'MDN: Cross-Origin-Resource-Policy', url: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Resource-Policy' },
      ],
    };
    try {
      const res = await fetchWithTimeout(`https://${domain}/`);
      const coopH = res.headers.get('cross-origin-opener-policy');
      const corpH = res.headers.get('cross-origin-resource-policy');
      if (!coopH && !corpH) return { ...base, status: 'warn', finding: 'Neither COOP nor CORP headers are set', confidence: 'medium' };
      const parts: string[] = [];
      if (coopH) parts.push(`COOP: ${coopH}`);
      if (corpH) parts.push(`CORP: ${corpH}`);
      return { ...base, status: 'pass', finding: parts.join(' · ') };
    } catch {
      return { ...base, status: 'error', finding: 'Could not check cross-origin isolation headers', errorReason: 'Domain unreachable or request timed out.' };
    }
  },
};

const corsPolicy: SecurityTest = {
  test_id: 'API-008',
  name: 'CORS Policy',
  version: '1.0.0',
  category: 'headers',
  severity: 'high',
  confidence: 'high',
  owasp_mapping: 'A05:2021',
  cwe: 'CWE-942',
  safe_for_production: true,
  requires_active_testing: false,
  async run({ domain }: ScanContext): Promise<Finding> {
    const base = {
      test_id: this.test_id, name: this.name, category: this.category,
      severity: this.severity, confidence: this.confidence,
      owasp_mapping: this.owasp_mapping, cwe: this.cwe,
      detail: 'A wildcard CORS policy (Access-Control-Allow-Origin: *) with credentials enabled allows any website to make authenticated cross-origin requests on behalf of the user.',
      remediation: 'Replace wildcard origins with an explicit allowlist. Never combine `Access-Control-Allow-Origin: *` with `Access-Control-Allow-Credentials: true`. Validate the Origin header server-side against an allowlist.',
      references: [
        { label: 'MDN: CORS', url: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS' },
        { label: 'OWASP CORS Security', url: 'https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html#cross-origin-resource-sharing' },
        { label: 'Fetch Living Standard', url: 'https://fetch.spec.whatwg.org/#http-cors-protocol' },
      ],
    };
    try {
      const res = await fetchWithTimeout(`https://${domain}/`, {
        headers: { Origin: 'https://evil.example.com' },
      });
      const acao = res.headers.get('access-control-allow-origin');
      const acac = res.headers.get('access-control-allow-credentials');
      if (!acao) return { ...base, status: 'pass', finding: 'No CORS headers returned for cross-origin request — expected for most sites', confidence: 'medium' };
      if (acao === '*' && acac === 'true') return { ...base, status: 'fail', finding: 'CORS wildcard (*) with credentials:true — any origin can make authenticated requests' };
      if (acao === '*') return { ...base, status: 'warn', finding: 'CORS Access-Control-Allow-Origin: * is set — acceptable only for fully public APIs without credentials', confidence: 'high' };
      return { ...base, status: 'pass', finding: `CORS allows specific origin: ${acao}` };
    } catch {
      return { ...base, status: 'error', finding: 'Could not test CORS policy', errorReason: 'Domain unreachable or request timed out.' };
    }
  },
};

export const HEADER_TESTS: SecurityTest[] = [
  clickjacking, cspQuality, referrerPolicy, permissionsPolicy, coop, corsPolicy,
];
