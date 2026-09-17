import type { SecurityTest, Finding, ScanContext } from './types.js';

async function fetchWithTimeout(url: string, init: RequestInit = {}, ms = 6000): Promise<Response> {
  return fetch(url, { ...init, signal: AbortSignal.timeout(ms) });
}

interface DnsAnswer { data: string; }
interface DnsResponse { Status: number; Answer?: DnsAnswer[]; }

async function dnsQuery(name: string, type: string): Promise<DnsResponse> {
  const res = await fetch(
    `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${type}`,
    { headers: { Accept: 'application/dns-json' }, signal: AbortSignal.timeout(5000) },
  );
  if (!res.ok) return { Status: 2 };
  return res.json() as Promise<DnsResponse>;
}

const adminExposure: SecurityTest = {
  test_id: 'INFO-001a',
  name: 'Admin Panel Exposure',
  version: '1.0.0',
  category: 'exposure',
  severity: 'high',
  confidence: 'confirmed',
  owasp_mapping: 'A05:2021',
  cwe: 'CWE-284',
  safe_for_production: true,
  requires_active_testing: false,
  async run({ domain }: ScanContext): Promise<Finding> {
    const base = {
      test_id: this.test_id, name: this.name, category: this.category,
      severity: this.severity, confidence: this.confidence,
      owasp_mapping: this.owasp_mapping, cwe: this.cwe,
      detail: 'Publicly accessible admin panels are a high-value target. Many credential stuffing and brute-force campaigns specifically target /admin, /wp-admin, and /administrator paths.',
      remediation: 'Restrict admin paths by IP allowlist, move them to a non-standard path, require VPN access, or serve them on a separate internal domain.',
      references: [{ label: 'OWASP A05 — Security Misconfiguration', url: 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/' }],
    };
    const adminPaths = ['/admin', '/wp-admin', '/administrator', '/dashboard', '/panel'];
    const adminKeywords = /login|sign.?in|admin|dashboard|password|username|user.?name|wp-login|control.?panel/i;
    try {
      const results = await Promise.allSettled(
        adminPaths.map(p =>
          fetchWithTimeout(`https://${domain}${p}`, { redirect: 'manual' }, 5000)
            .then(async r => ({ path: p, status: r.status, body: r.status === 200 ? await r.text().catch(() => '') : '' }))
        )
      );
      const exposed: string[] = [];
      let countOk = 0;
      for (const r of results) {
        if (r.status !== 'fulfilled') continue;
        const { path, status, body } = r.value;
        if (status === 401 || status === 403) { countOk++; continue; }
        if (status === 200 && adminKeywords.test(body)) exposed.push(path);
      }
      if (exposed.length > 0) return { ...base, status: 'fail', finding: `Admin path(s) serving content without auth gate: ${exposed.join(', ')}` };
      if (countOk > 0) return { ...base, status: 'pass', finding: 'Admin paths return 401/403 — access control is active' };
      return { ...base, status: 'pass', finding: 'Admin paths redirect or return non-200 — no exposed panels detected', confidence: 'medium' };
    } catch {
      return { ...base, status: 'error', finding: 'Could not check admin path exposure', errorReason: 'Request failed or timed out.' };
    }
  },
};

const authEndpointProtection: SecurityTest = {
  test_id: 'AUTH-001b',
  name: 'Auth Endpoint Protection',
  version: '1.0.0',
  category: 'exposure',
  severity: 'high',
  confidence: 'medium',
  owasp_mapping: 'A07:2021',
  cwe: 'CWE-307',
  safe_for_production: true,
  requires_active_testing: false,
  async run({ domain, authUrl }: ScanContext): Promise<Finding> {
    const base = {
      test_id: this.test_id, name: this.name, category: this.category,
      severity: this.severity, confidence: this.confidence,
      owasp_mapping: this.owasp_mapping, cwe: this.cwe,
      detail: 'Authentication endpoints (/login, /signin, /api/auth) are primary targets for credential stuffing and brute-force attacks. Rate limiting headers and bot protection signals indicate active defences.',
      remediation: 'Enforce rate limiting on all login and password-reset endpoints. Return 429 Too Many Requests after threshold. Add CAPTCHA (Turnstile, hCaptcha) as a second layer.',
      references: [
        { label: 'OWASP — Credential Stuffing', url: 'https://owasp.org/www-community/attacks/Credential_stuffing' },
        { label: 'RFC 6585 — 429 Too Many Requests', url: 'https://tools.ietf.org/html/rfc6585' },
      ],
    };
    const authPaths = ['/login', '/signin', '/auth', '/api/auth/login', '/api/login', '/account/login'];
    const urlsToCheck = authUrl
      ? [authUrl, ...authPaths.map(p => `https://${domain}${p}`)]
      : authPaths.map(p => `https://${domain}${p}`);
    try {
      const responses = await Promise.allSettled(
        urlsToCheck.map(u =>
          fetchWithTimeout(u, { redirect: 'manual' }, 5000).then(r => ({
            path: u,
            status: r.status,
            rateLimitHeaders: [
              r.headers.get('x-ratelimit-limit'),
              r.headers.get('x-ratelimit-remaining'),
              r.headers.get('ratelimit-limit'),
              r.headers.get('retry-after'),
              r.headers.get('cf-mitigated'),
            ].filter(Boolean),
          }))
        )
      );
      const live = responses
        .filter((r): r is PromiseFulfilledResult<{ path: string; status: number; rateLimitHeaders: (string | null)[] }> =>
          r.status === 'fulfilled' && [200, 301, 302].includes(r.value.status))
        .map(r => r.value);
      if (live.length === 0) return { ...base, status: 'info', finding: 'No accessible auth endpoints found at common paths', confidence: 'low' };
      const protected_ = live.filter(r => r.rateLimitHeaders.length > 0);
      if (protected_.length > 0) {
        return { ...base, status: 'pass', finding: `Rate limiting headers detected on auth endpoint(s): ${protected_.map(r => r.path).join(', ')}` };
      }
      return { ...base, status: 'warn', finding: `Auth endpoint(s) accessible at ${live.map(r => r.path).join(', ')} but no rate limiting headers detected` };
    } catch {
      return { ...base, status: 'error', finding: 'Could not evaluate auth endpoint protection', errorReason: 'Request failed or timed out.' };
    }
  },
};

const subdomainSurface: SecurityTest = {
  test_id: 'EXT-006',
  name: 'Auth Subdomain Surface',
  version: '1.0.0',
  category: 'exposure',
  severity: 'informational',
  confidence: 'confirmed',
  owasp_mapping: 'A05:2021',
  safe_for_production: true,
  requires_active_testing: false,
  async run({ domain }: ScanContext): Promise<Finding> {
    const base = {
      test_id: this.test_id, name: this.name, category: this.category,
      severity: this.severity, confidence: this.confidence,
      owasp_mapping: this.owasp_mapping,
      detail: 'Auth-named subdomains (auth., sso., login., id.) represent your identity perimeter. Knowing which are live helps scope attack surface and ensures orphaned subdomains are not forgotten.',
      remediation: 'For each live auth subdomain: verify it is intentional, confirm it requires authentication before revealing any content, and ensure it inherits your HSTS and security header policies.',
      references: [{ label: 'OWASP — Subdomain Takeover', url: 'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/10-Test_for_Subdomain_Takeover' }],
    };
    const subdomains = ['auth', 'sso', 'login', 'id', 'identity', 'account', 'accounts'];
    try {
      const queries = await Promise.allSettled(subdomains.map(s => dnsQuery(`${s}.${domain}`, 'A')));
      const live = subdomains.filter((_, i) => {
        const r = queries[i];
        return r.status === 'fulfilled' && (r.value.Answer?.length ?? 0) > 0;
      });
      if (live.length === 0) return { ...base, status: 'info', finding: 'No auth-related subdomains found in DNS' };
      return { ...base, status: 'info', finding: `Auth subdomains found in DNS: ${live.map(s => s + '.' + domain).join(', ')}` };
    } catch {
      return { ...base, status: 'error', finding: 'Could not query subdomain DNS records', errorReason: 'DNS-over-HTTPS query timed out or returned an error.' };
    }
  },
};

const securityTxt: SecurityTest = {
  test_id: 'META-001',
  name: 'Security.txt',
  version: '1.0.0',
  category: 'exposure',
  severity: 'informational',
  confidence: 'confirmed',
  owasp_mapping: 'A05:2021',
  safe_for_production: true,
  requires_active_testing: false,
  async run({ domain }: ScanContext): Promise<Finding> {
    const base = {
      test_id: this.test_id, name: this.name, category: this.category,
      severity: this.severity, confidence: this.confidence,
      owasp_mapping: this.owasp_mapping,
      detail: 'security.txt (RFC 9116) provides a standard way for security researchers to report vulnerabilities. Its presence signals a mature security posture.',
      remediation: 'Create a file at /.well-known/security.txt with at minimum: `Contact: mailto:security@yourdomain.com` and `Expires: [date one year from now]`. Generator: securitytxt.org.',
      references: [
        { label: 'RFC 9116 — security.txt', url: 'https://tools.ietf.org/html/rfc9116' },
        { label: 'securitytxt.org Generator', url: 'https://securitytxt.org' },
      ],
    };
    try {
      const res = await fetchWithTimeout(`https://${domain}/.well-known/security.txt`, {}, 5000);
      if (res.ok) return { ...base, status: 'pass', finding: 'security.txt is present at /.well-known/security.txt' };
      return { ...base, status: 'info', finding: 'No security.txt found — consider adding one for responsible disclosure' };
    } catch {
      return { ...base, status: 'info', finding: 'Could not check for security.txt' };
    }
  },
};

export const EXPOSURE_TESTS: SecurityTest[] = [
  adminExposure, authEndpointProtection, subdomainSurface, securityTxt,
];
