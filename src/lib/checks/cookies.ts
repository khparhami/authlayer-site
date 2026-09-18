import type { SecurityTest, Finding, ScanContext } from './types.js';

async function fetchWithTimeout(url: string, init: RequestInit = {}, ms = 6000): Promise<Response> {
  return fetch(url, { ...init, signal: AbortSignal.timeout(ms) });
}

// Patterns for cookie names that are likely to be auth/session-sensitive
const SENSITIVE_NAME_PATTERNS: RegExp[] = [
  /^session/i, /^sess(?:ion)?[-_]?(?:id)?$/i,
  /^auth/i, /^jwt$/i, /^token$/i,
  /access[-_]?token/i, /refresh[-_]?token/i,
  /bearer[-_]?token/i, /id[-_]?token/i,
  /^sid$/i, /^uid$/i,
  /^login$/i, /^credential/i, /^identity[-_]?/i,
  /^remember[-_]?me$/i, /PHPSESSID/i, /JSESSIONID/i,
  /ASP\.NET_SessionId/i, /__session/i,
];

function isSensitiveCookie(name: string): boolean {
  return SENSITIVE_NAME_PATTERNS.some(p => p.test(name));
}

function cookieName(raw: string): string {
  return raw.split('=')[0].trim();
}

function hasCookieAttr(raw: string, attr: string): boolean {
  const re = new RegExp('(?:^|;)\\s*' + attr.replace(/-/, '[-]?') + '\\b', 'i');
  return re.test(raw);
}

function cookieEvidence(raw: string): string {
  const name = cookieName(raw);
  const secure   = hasCookieAttr(raw, 'Secure')   ? 'present' : 'missing';
  const httpOnly = hasCookieAttr(raw, 'HttpOnly')  ? 'present' : 'missing';
  const match = /samesite=([^\s;]+)/i.exec(raw);
  const sameSite = match ? match[1] : 'not set';
  return `Cookie: ${name}\nSecure: ${secure}\nHttpOnly: ${httpOnly}\nSameSite: ${sameSite}`;
}

function gatherCookies(domain: string, authUrl: string | null, extraPaths: string[]): Promise<string[]> {
  const urls = [...new Set([
    ...(authUrl ? [authUrl] : []),
    ...extraPaths.map(p => `https://${domain}${p}`),
  ])];
  return Promise.allSettled(urls.map(u => fetchWithTimeout(u, { redirect: 'manual' }))).then(results => {
    const cookies: string[] = [];
    for (const r of results) {
      if (r.status === 'fulfilled') {
        r.value.headers.getSetCookie?.()?.forEach((c: string) => cookies.push(c));
      }
    }
    return cookies;
  });
}

const cookieSecure: SecurityTest = {
  test_id: 'AUTH-003a',
  name: 'Session Cookie Flags',
  version: '1.0.0',
  category: 'cookies',
  severity: 'high',
  confidence: 'confirmed',
  owasp_mapping: 'A07:2021',
  cwe: 'CWE-614',
  safe_for_production: true,
  requires_active_testing: false,
  async run({ domain, authUrl }: ScanContext): Promise<Finding> {
    const base = {
      test_id: this.test_id, name: this.name, category: this.category,
      severity: this.severity, confidence: this.confidence,
      owasp_mapping: this.owasp_mapping, cwe: this.cwe,
      detail: 'Session cookies must carry `Secure` (HTTPS-only) and `HttpOnly` (no JS access) attributes. Missing `Secure` means cookies can be sent over HTTP. Missing `HttpOnly` exposes them to XSS attacks.',
      remediation: "Set all session cookies with `Secure; HttpOnly; SameSite=Lax`. In Express: `res.cookie(name, value, { secure: true, httpOnly: true, sameSite: 'lax' })`. In Django: `SESSION_COOKIE_SECURE=True`, `SESSION_COOKIE_HTTPONLY=True`.",
      references: [
        { label: 'RFC 6265 — HTTP Cookies', url: 'https://tools.ietf.org/html/rfc6265' },
        { label: 'OWASP Session Management', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html' },
      ],
    };
    try {
      const allCookies = await gatherCookies(domain, authUrl, ['/', '/login', '/signin', '/auth', '/account/login']);
      if (allCookies.length === 0) {
        return { ...base, status: 'info', finding: 'No Set-Cookie headers found on main page or common auth paths', confidence: 'informational' };
      }

      const sessionMissing: Array<{ name: string; missing: string[]; evidence: string }> = [];
      const otherMissing: Array<{ name: string; missing: string[] }> = [];

      for (const cookie of allCookies) {
        const name = cookieName(cookie);
        const missingFlags: string[] = [];
        if (!hasCookieAttr(cookie, 'Secure'))   missingFlags.push('Secure');
        if (!hasCookieAttr(cookie, 'HttpOnly'))  missingFlags.push('HttpOnly');
        if (missingFlags.length === 0) continue;

        if (isSensitiveCookie(name)) {
          sessionMissing.push({ name, missing: missingFlags, evidence: cookieEvidence(cookie) });
        } else {
          otherMissing.push({ name, missing: missingFlags });
        }
      }

      if (sessionMissing.length > 0) {
        const names = sessionMissing.map(c => c.name).join(', ');
        const flags = [...new Set(sessionMissing.flatMap(c => c.missing))];
        return {
          ...base, status: 'fail',
          finding: `Session/auth cookie(s) missing ${flags.join(', ')} flag${flags.length > 1 ? 's' : ''}: ${names}`,
          evidence: sessionMissing.map(c => c.evidence).join('\n\n'),
          reasonCode: 'AUTH_COOKIE_MISSING_FLAGS',
        };
      }
      if (otherMissing.length > 0) {
        const names = otherMissing.map(c => c.name).join(', ');
        return {
          ...base, status: 'warn',
          severity: 'low',
          confidence: 'low',
          finding: `Non-session cookie(s) missing security flags: ${names} — review if any carry sensitive data`,
          reasonCode: 'COOKIE_MISSING_FLAGS_ROLE_UNKNOWN',
        };
      }
      return { ...base, status: 'pass', finding: `All ${allCookies.length} cookie(s) have Secure and HttpOnly flags set` };
    } catch {
      return { ...base, status: 'inconclusive', finding: 'Could not fetch cookies from auth paths', errorReason: 'Request failed or timed out.', reasonCode: 'REQUEST_TIMEOUT' };
    }
  },
};

const cookieSamesite: SecurityTest = {
  test_id: 'AUTH-003b',
  name: 'SameSite Cookie Policy',
  version: '1.0.0',
  category: 'cookies',
  severity: 'high',
  confidence: 'confirmed',
  owasp_mapping: 'A01:2021',
  cwe: 'CWE-352',
  safe_for_production: true,
  requires_active_testing: false,
  async run({ domain, authUrl }: ScanContext): Promise<Finding> {
    const base = {
      test_id: this.test_id, name: this.name, category: this.category,
      severity: this.severity, confidence: this.confidence,
      owasp_mapping: this.owasp_mapping, cwe: this.cwe,
      detail: 'SameSite=None without Strict/Lax allows cross-site requests to include the cookie, enabling CSRF attacks. SameSite=Lax is the modern default and prevents most CSRF vectors while keeping OAuth flows working.',
      remediation: "Set SameSite=Lax on session cookies (default in modern browsers). Only use SameSite=None with Secure if you specifically need cross-site cookie access (e.g. embedded third-party flows).",
      references: [
        { label: 'MDN: SameSite cookies', url: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#samesite_attribute' },
        { label: 'OWASP CSRF Prevention', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html' },
      ],
    };
    try {
      const allCookies = await gatherCookies(domain, authUrl, ['/', '/login', '/signin']);
      if (allCookies.length === 0) return { ...base, status: 'info', finding: 'No cookies found to evaluate SameSite policy', confidence: 'informational' };
      const noneUnsafe = allCookies.filter(c => {
        const lower = c.toLowerCase();
        return lower.includes('samesite=none') && !lower.includes('secure');
      });
      if (noneUnsafe.length > 0) {
        return { ...base, status: 'fail', severity: 'medium', finding: `${noneUnsafe.length} cookie(s) use SameSite=None without Secure — cross-site requests will include these cookies`, reasonCode: 'SAMESITE_NONE_WITHOUT_SECURE' };
      }
      const noSameSite = allCookies.filter(c => !/samesite=/i.test(c));
      if (noSameSite.length > 0) {
        return {
          ...base, status: 'warn', severity: 'low', confidence: 'medium',
          finding: `${noSameSite.length} cookie${noSameSite.length > 1 ? 's' : ''} do not explicitly specify a SameSite attribute. Modern browsers commonly default omitted SameSite to Lax. Explicitly setting SameSite makes the intended cross-site behaviour clearer and provides additional defence in depth.`,
          reasonCode: 'SAMESITE_NOT_EXPLICIT',
        };
      }
      return { ...base, status: 'pass', finding: 'All cookies have explicit SameSite attribute set appropriately' };
    } catch {
      return { ...base, status: 'inconclusive', finding: 'Could not evaluate SameSite policy', errorReason: 'Request failed or timed out.', reasonCode: 'REQUEST_TIMEOUT' };
    }
  },
};

const cookiePrefixes: SecurityTest = {
  test_id: 'AUTH-003c',
  name: 'Secure Cookie Prefixes',
  version: '1.0.0',
  category: 'cookies',
  severity: 'low',
  confidence: 'confirmed',
  owasp_mapping: 'A07:2021',
  cwe: 'CWE-565',
  safe_for_production: true,
  requires_active_testing: false,
  async run({ domain, authUrl }: ScanContext): Promise<Finding> {
    const base = {
      test_id: this.test_id, name: this.name, category: this.category,
      severity: this.severity, confidence: this.confidence,
      owasp_mapping: this.owasp_mapping, cwe: this.cwe,
      detail: '__Secure- prefix requires the cookie to be set over HTTPS and have the Secure flag. __Host- additionally requires no Domain attribute and Path=/, preventing subdomain fixation attacks.',
      remediation: 'Rename session cookies to use __Host- prefix: `Set-Cookie: __Host-session=value; Secure; HttpOnly; SameSite=Lax; Path=/`. This is a defence-in-depth measure, not a standalone fix.',
      references: [
        { label: 'MDN: Cookie prefixes', url: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#cookie_prefixes' },
      ],
    };
    try {
      const urlToCheck = authUrl ?? `https://${domain}/`;
      const res = await fetchWithTimeout(urlToCheck, { redirect: 'manual' });
      const cookies = res.headers.getSetCookie?.() ?? [];
      if (cookies.length === 0) return { ...base, status: 'info', finding: 'No cookies found on main page to evaluate', confidence: 'informational' };
      const prefixed = cookies.filter(c => c.startsWith('__Secure-') || c.startsWith('__Host-'));
      if (prefixed.length > 0) return { ...base, status: 'pass', finding: `${prefixed.length}/${cookies.length} cookie(s) use __Secure- or __Host- prefix` };
      return { ...base, status: 'warn', finding: `None of the ${cookies.length} cookie(s) use __Secure- or __Host- prefixes`, confidence: 'medium' };
    } catch {
      return { ...base, status: 'error', finding: 'Could not evaluate cookie prefixes', errorReason: 'Request failed or timed out.' };
    }
  },
};

export const COOKIE_TESTS: SecurityTest[] = [cookieSecure, cookieSamesite, cookiePrefixes];
