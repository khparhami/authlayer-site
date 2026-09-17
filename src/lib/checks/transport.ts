import type { SecurityTest, Finding, ScanContext } from './types.js';

async function fetchWithTimeout(url: string, init: RequestInit = {}, ms = 8000): Promise<Response> {
  return fetch(url, { ...init, signal: AbortSignal.timeout(ms) });
}

const sslValid: SecurityTest = {
  test_id: 'EXT-002a',
  name: 'SSL Certificate',
  version: '1.0.0',
  category: 'transport',
  severity: 'critical',
  confidence: 'high',
  owasp_mapping: 'A02:2021',
  cwe: 'CWE-295',
  safe_for_production: true,
  requires_active_testing: false,
  async run({ domain }: ScanContext): Promise<Finding> {
    const base = {
      test_id: this.test_id, name: this.name, category: this.category,
      severity: this.severity, confidence: this.confidence,
      owasp_mapping: this.owasp_mapping, cwe: this.cwe,
      detail: 'A valid TLS certificate is the foundation of transport security. An expired or missing certificate means all data between users and the server is unencrypted or the browser blocks access entirely.',
      remediation: "Renew the certificate through your CA or enable auto-renewal (Let's Encrypt certbot, Cloudflare managed certs). Ensure the cert covers the bare domain and www subdomain.",
      references: [
        { label: 'RFC 8446 — TLS 1.3', url: 'https://tools.ietf.org/html/rfc8446' },
        { label: 'NIST SP 800-52r2', url: 'https://csrc.nist.gov/pubs/sp/800/52/r2/final' },
      ],
    };
    try {
      const res = await fetchWithTimeout(`https://${domain}/`, {}, 8000);
      return { ...base, status: 'pass', finding: `Certificate valid — ${res.status} response received over HTTPS` };
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : String(e);
      if (msg.includes('certificate') || msg.includes('SSL') || msg.includes('TLS')) {
        return { ...base, status: 'fail', finding: 'SSL/TLS error — certificate may be invalid, expired, or misconfigured' };
      }
      return { ...base, status: 'error', finding: 'Could not reach domain over HTTPS — unreachable or timed out', errorReason: 'The domain may be unreachable, the request timed out, or no HTTPS listener exists.' };
    }
  },
};

const httpsRedirect: SecurityTest = {
  test_id: 'EXT-002b',
  name: 'HTTPS Enforced',
  version: '1.0.0',
  category: 'transport',
  severity: 'high',
  confidence: 'confirmed',
  owasp_mapping: 'A02:2021',
  cwe: 'CWE-319',
  safe_for_production: true,
  requires_active_testing: false,
  async run({ domain }: ScanContext): Promise<Finding> {
    const base = {
      test_id: this.test_id, name: this.name, category: this.category,
      severity: this.severity, confidence: this.confidence,
      owasp_mapping: this.owasp_mapping, cwe: this.cwe,
      detail: 'HTTP requests must redirect to HTTPS so users who type the domain without a scheme are automatically protected. Without this redirect, cookies, session tokens, and form data travel unencrypted.',
      remediation: 'Add a 301 redirect from http:// to https:// at the load balancer or CDN level. In Cloudflare: SSL/TLS → Edge Certificates → Always Use HTTPS.',
      references: [
        { label: 'OWASP TLS Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html' },
        { label: 'RFC 7231 — HTTP Redirects', url: 'https://tools.ietf.org/html/rfc7231#section-6.4' },
      ],
    };
    try {
      const res = await fetchWithTimeout(`http://${domain}/`, { redirect: 'manual' }, 8000);
      const loc = res.headers.get('location') ?? '';
      if ([301, 302, 307, 308].includes(res.status) && loc.startsWith('https://')) {
        return { ...base, status: 'pass', finding: `HTTP redirects to HTTPS (${res.status})` };
      }
      if (res.status >= 200 && res.status < 400) {
        return { ...base, status: 'fail', finding: 'HTTP responds without redirecting to HTTPS — plain HTTP is served' };
      }
      return { ...base, status: 'warn', finding: `Unexpected response on HTTP (status ${res.status}) — verify redirect is configured` };
    } catch {
      return { ...base, status: 'error', finding: 'Could not connect over HTTP to test redirect', errorReason: 'Connection refused or timed out on port 80.' };
    }
  },
};

const hsts: SecurityTest = {
  test_id: 'EXT-002c',
  name: 'HSTS Header',
  version: '1.0.0',
  category: 'transport',
  severity: 'high',
  confidence: 'confirmed',
  owasp_mapping: 'A02:2021',
  cwe: 'CWE-319',
  safe_for_production: true,
  requires_active_testing: false,
  async run({ domain }: ScanContext): Promise<Finding> {
    const base = {
      test_id: this.test_id, name: this.name, category: this.category,
      severity: this.severity, confidence: this.confidence,
      owasp_mapping: this.owasp_mapping, cwe: this.cwe,
      detail: 'HTTP Strict Transport Security (HSTS) tells browsers to always use HTTPS for this domain, even on the first visit. Without it, users are vulnerable to SSL stripping attacks on their first request.',
      remediation: 'Add: `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`. Start with max-age=86400, verify nothing breaks, then increase to 31536000 and submit to the HSTS preload list.',
      references: [
        { label: 'RFC 6797 — HSTS', url: 'https://tools.ietf.org/html/rfc6797' },
        { label: 'HSTS Preload List', url: 'https://hstspreload.org' },
        { label: 'MDN: Strict-Transport-Security', url: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security' },
      ],
    };
    try {
      const res = await fetchWithTimeout(`https://${domain}/`, {}, 8000);
      const hstsHeader = res.headers.get('strict-transport-security');
      if (!hstsHeader) return { ...base, status: 'fail', finding: 'Strict-Transport-Security header is missing' };
      const maxAgeMatch = hstsHeader.match(/max-age=(\d+)/i);
      const maxAge = maxAgeMatch ? parseInt(maxAgeMatch[1]) : 0;
      if (maxAge < 31536000) {
        return { ...base, status: 'warn', finding: `HSTS present but max-age is only ${maxAge}s — recommend ≥ 31536000 (1 year)` };
      }
      const flags: string[] = [];
      if (/includeSubDomains/i.test(hstsHeader)) flags.push('includeSubDomains');
      if (/preload/i.test(hstsHeader)) flags.push('preload');
      return { ...base, status: 'pass', finding: `HSTS set — max-age=${maxAge}${flags.length ? ', ' + flags.join(', ') : ''}` };
    } catch {
      return { ...base, status: 'error', finding: 'Could not fetch HTTPS headers', errorReason: 'Domain unreachable or certificate error prevented header inspection.' };
    }
  },
};

export const TRANSPORT_TESTS: SecurityTest[] = [sslValid, httpsRedirect, hsts];
