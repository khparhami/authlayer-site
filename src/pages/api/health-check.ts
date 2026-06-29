export const prerender = false;

import type { APIRoute } from 'astro';

type Status = 'pass' | 'fail' | 'warn' | 'info' | 'error';
type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
type Category = 'transport' | 'cookies' | 'headers' | 'email' | 'oauth' | 'exposure';

interface Reference { label: string; url: string; }

interface CheckResult {
  id: string;
  name: string;
  category: Category;
  status: Status;
  severity: Severity;
  finding: string;
  detail?: string;
  remediation?: string;
  references?: Reference[];
  errorReason?: string;
}

const REFS: Record<string, Reference[]> = {
  ssl_valid: [
    { label: 'RFC 8446 — TLS 1.3', url: 'https://tools.ietf.org/html/rfc8446' },
    { label: 'NIST SP 800-52r2', url: 'https://csrc.nist.gov/pubs/sp/800/52/r2/final' },
  ],
  https_redirect: [
    { label: 'OWASP TLS Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html' },
    { label: 'RFC 7231 — HTTP Redirects', url: 'https://tools.ietf.org/html/rfc7231#section-6.4' },
  ],
  hsts: [
    { label: 'RFC 6797 — HSTS', url: 'https://tools.ietf.org/html/rfc6797' },
    { label: 'HSTS Preload List', url: 'https://hstspreload.org' },
    { label: 'MDN: Strict-Transport-Security', url: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security' },
  ],
  cookie_secure: [
    { label: 'RFC 6265 — HTTP Cookies', url: 'https://tools.ietf.org/html/rfc6265' },
    { label: 'OWASP Session Management', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html' },
  ],
  spf_exists: [
    { label: 'RFC 7208 — SPF', url: 'https://tools.ietf.org/html/rfc7208' },
  ],
  dmarc_exists: [
    { label: 'RFC 7489 — DMARC', url: 'https://tools.ietf.org/html/rfc7489' },
  ],
  clickjacking: [
    { label: 'OWASP Clickjacking Defence', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html' },
    { label: 'MDN: X-Frame-Options', url: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options' },
  ],
  admin_exposure: [
    { label: 'OWASP A05 — Security Misconfiguration', url: 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/' },
  ],
  cookie_samesite: [
    { label: 'MDN: SameSite cookies', url: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#samesite_attribute' },
    { label: 'OWASP CSRF Prevention', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html' },
  ],
  cookie_prefixes: [
    { label: 'MDN: Cookie prefixes', url: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#cookie_prefixes' },
  ],
  csp_quality: [
    { label: 'MDN: Content-Security-Policy', url: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP' },
    { label: 'OWASP CSP Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html' },
    { label: 'W3C CSP Level 3', url: 'https://www.w3.org/TR/CSP3/' },
  ],
  referrer_policy: [
    { label: 'MDN: Referrer-Policy', url: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy' },
    { label: 'W3C Referrer Policy', url: 'https://www.w3.org/TR/referrer-policy/' },
  ],
  permissions_policy: [
    { label: 'MDN: Permissions-Policy', url: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy' },
    { label: 'W3C Permissions Policy', url: 'https://www.w3.org/TR/permissions-policy/' },
  ],
  coop: [
    { label: 'MDN: Cross-Origin-Opener-Policy', url: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy' },
    { label: 'MDN: Cross-Origin-Resource-Policy', url: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Resource-Policy' },
  ],
  oidc_discovery: [
    { label: 'OpenID Connect Discovery 1.0', url: 'https://openid.net/specs/openid-connect-discovery-1_0.html' },
  ],
  pkce_support: [
    { label: 'RFC 7636 — PKCE', url: 'https://tools.ietf.org/html/rfc7636' },
    { label: 'OAuth 2.1 Draft', url: 'https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1' },
  ],
  grant_types: [
    { label: 'OAuth 2.1 — Removed Flows', url: 'https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1#section-1.3' },
    { label: 'RFC 6749 — OAuth 2.0', url: 'https://tools.ietf.org/html/rfc6749' },
  ],
  webauthn_support: [
    { label: 'W3C Web Authentication', url: 'https://www.w3.org/TR/webauthn-3/' },
    { label: 'FIDO2 Overview', url: 'https://fidoalliance.org/fido2/' },
    { label: 'NIST SP 800-63B-4', url: 'https://pages.nist.gov/800-63-4/sp800-63b.html' },
  ],
  phishing_resistance: [
    { label: 'W3C Web Authentication', url: 'https://www.w3.org/TR/webauthn-3/' },
    { label: 'FIDO2 Overview', url: 'https://fidoalliance.org/fido2/' },
    { label: 'NIST SP 800-63B-4 — AAL2', url: 'https://pages.nist.gov/800-63-4/sp800-63b.html#aal2' },
  ],
  dkim_record: [
    { label: 'RFC 6376 — DKIM', url: 'https://tools.ietf.org/html/rfc6376' },
  ],
  dmarc_policy: [
    { label: 'RFC 7489 — DMARC', url: 'https://tools.ietf.org/html/rfc7489' },
    { label: 'DMARC.org Guide', url: 'https://dmarc.org/overview/' },
  ],
  spf_strength: [
    { label: 'RFC 7208 — SPF Qualifiers', url: 'https://tools.ietf.org/html/rfc7208#section-4.6.2' },
  ],
  subdomain_surface: [
    { label: 'OWASP — Subdomain Takeover', url: 'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/10-Test_for_Subdomain_Takeover' },
  ],
  cors_headers: [
    { label: 'MDN: CORS', url: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS' },
    { label: 'OWASP CORS Security', url: 'https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html#cross-origin-resource-sharing' },
    { label: 'Fetch Living Standard', url: 'https://fetch.spec.whatwg.org/#http-cors-protocol' },
  ],
  security_txt: [
    { label: 'RFC 9116 — security.txt', url: 'https://tools.ietf.org/html/rfc9116' },
    { label: 'securitytxt.org Generator', url: 'https://securitytxt.org' },
  ],
  oauth_usage: [
    { label: 'RFC 6749 — OAuth 2.0', url: 'https://tools.ietf.org/html/rfc6749' },
    { label: 'OpenID Connect Core 1.0', url: 'https://openid.net/specs/openid-connect-core-1_0.html' },
  ],
  auth_endpoint_protection: [
    { label: 'OWASP — Credential Stuffing', url: 'https://owasp.org/www-community/attacks/Credential_stuffing' },
    { label: 'RFC 6585 — 429 Too Many Requests', url: 'https://tools.ietf.org/html/rfc6585' },
    { label: 'OWASP Authentication Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html' },
  ],
};

// ─── helpers ────────────────────────────────────────────────────────────────

async function fetchWithTimeout(url: string, init: RequestInit = {}, ms = 8000): Promise<Response> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), ms);
  try {
    return await fetch(url, { ...init, signal: ctrl.signal });
  } finally {
    clearTimeout(timer);
  }
}

interface DnsAnswer { name: string; type: number; TTL: number; data: string; }
interface DnsResponse { Status: number; Answer?: DnsAnswer[]; }

async function dnsQuery(name: string, type: string): Promise<DnsResponse> {
  const res = await fetchWithTimeout(
    `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${type}`,
    { headers: { Accept: 'application/dns-json' } },
    6000,
  );
  if (!res.ok) return { Status: 2 };
  return res.json() as Promise<DnsResponse>;
}

function sanitizeDomain(input: string): string | null {
  if (!input) return null;
  let d = input.trim().toLowerCase();
  d = d.replace(/^https?:\/\//, '').replace(/\/.*$/, '');
  if (!d) return null;

  const validDomain = /^[a-z0-9]([a-z0-9\-.]{0,251}[a-z0-9])?$/.test(d);
  if (!validDomain) return null;

  // Block SSRF targets
  const blocked = [
    /^localhost$/,
    /^127\./,
    /^10\./,
    /^172\.(1[6-9]|2\d|3[01])\./,
    /^192\.168\./,
    /^169\.254\./,
    /^0\./,
    /\.local$/,
    /^::1$/,
  ];
  if (blocked.some(r => r.test(d))) return null;
  return d;
}

function calculateScore(results: CheckResult[]): number {
  const weights: Record<Severity, number> = { critical: 25, high: 15, medium: 10, low: 5, info: 0 };
  let score = 100;
  for (const r of results) {
    if (r.status === 'fail') score -= weights[r.severity];
    if (r.status === 'warn') score -= Math.floor(weights[r.severity] / 2);
  }
  return Math.max(0, score);
}

function calculateGrade(score: number): string {
  if (score >= 90) return 'A';
  if (score >= 75) return 'B';
  if (score >= 60) return 'C';
  if (score >= 45) return 'D';
  return 'F';
}

// ─── free checks ────────────────────────────────────────────────────────────

async function checkSslValid(domain: string): Promise<CheckResult> {
  const base: Omit<CheckResult, 'status' | 'finding'> = {
    id: 'ssl_valid', name: 'SSL Certificate', category: 'transport', severity: 'critical',
    detail: 'A valid TLS certificate is the foundation of transport security. An expired or missing certificate means all data between users and the server is unencrypted or the browser blocks access entirely.',
    remediation: 'Renew the certificate through your CA or enable auto-renewal (Let\'s Encrypt certbot, Cloudflare managed certs). Ensure the cert covers the bare domain and www subdomain.',
  };
  try {
    const res = await fetchWithTimeout(`https://${domain}/`, {}, 8000);
    return { ...base, status: 'pass', finding: `Certificate valid — ${res.status} response received over HTTPS` };
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    if (msg.includes('certificate') || msg.includes('SSL') || msg.includes('TLS')) {
      return { ...base, status: 'fail', finding: 'SSL/TLS error — certificate may be invalid, expired, or misconfigured' };
    }
    return { ...base, status: 'error', finding: 'Could not reach domain over HTTPS — unreachable or timed out' };
  }
}

async function checkHttpsRedirect(domain: string): Promise<CheckResult> {
  const base: Omit<CheckResult, 'status' | 'finding'> = {
    id: 'https_redirect', name: 'HTTPS Enforced', category: 'transport', severity: 'high',
    detail: 'HTTP requests must redirect to HTTPS so users who type the domain without a scheme are automatically protected. Without this redirect, cookies, session tokens, and form data travel unencrypted.',
    remediation: 'Add a 301 redirect from http:// to https:// at the load balancer or CDN level. In Cloudflare: SSL/TLS → Edge Certificates → Always Use HTTPS.',
  };
  try {
    const res = await fetchWithTimeout(`http://${domain}/`, { redirect: 'manual' }, 8000);
    const loc = res.headers.get('location') ?? '';
    if ((res.status === 301 || res.status === 302 || res.status === 307 || res.status === 308) && loc.startsWith('https://')) {
      return { ...base, status: 'pass', finding: `HTTP redirects to HTTPS (${res.status})` };
    }
    if (res.status >= 200 && res.status < 400) {
      return { ...base, status: 'fail', finding: 'HTTP responds without redirecting to HTTPS — plain HTTP is served' };
    }
    return { ...base, status: 'warn', finding: `Unexpected response on HTTP (status ${res.status}) — verify redirect is configured` };
  } catch {
    return { ...base, status: 'error', finding: 'Could not connect over HTTP to test redirect' };
  }
}

async function checkHsts(domain: string): Promise<CheckResult> {
  const base: Omit<CheckResult, 'status' | 'finding'> = {
    id: 'hsts', name: 'HSTS Header', category: 'transport', severity: 'high',
    detail: 'HTTP Strict Transport Security (HSTS) tells browsers to always use HTTPS for this domain, even on the first visit. Without it, users are vulnerable to SSL stripping attacks on their first request.',
    remediation: 'Add: `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`. Start with max-age=86400, verify nothing breaks, then increase to 31536000 and submit to the HSTS preload list.',
  };
  try {
    const res = await fetchWithTimeout(`https://${domain}/`, {}, 8000);
    const hsts = res.headers.get('strict-transport-security');
    if (!hsts) return { ...base, status: 'fail', finding: 'Strict-Transport-Security header is missing' };
    const maxAgeMatch = hsts.match(/max-age=(\d+)/i);
    const maxAge = maxAgeMatch ? parseInt(maxAgeMatch[1]) : 0;
    if (maxAge < 31536000) {
      return { ...base, status: 'warn', finding: `HSTS present but max-age is only ${maxAge}s — recommend ≥ 31536000 (1 year)` };
    }
    const flags: string[] = [];
    if (/includeSubDomains/i.test(hsts)) flags.push('includeSubDomains');
    if (/preload/i.test(hsts)) flags.push('preload');
    return { ...base, status: 'pass', finding: `HSTS set — max-age=${maxAge}${flags.length ? ', ' + flags.join(', ') : ''}` };
  } catch {
    return { ...base, status: 'error', finding: 'Could not fetch HTTPS headers' };
  }
}

async function checkCookieSecurity(domain: string): Promise<CheckResult> {
  const base: Omit<CheckResult, 'status' | 'finding'> = {
    id: 'cookie_secure', name: 'Session Cookie Flags', category: 'cookies', severity: 'high',
    detail: 'Session cookies must carry `Secure` (HTTPS-only) and `HttpOnly` (no JS access) attributes. Missing `Secure` means cookies can be sent over HTTP. Missing `HttpOnly` exposes them to XSS attacks.',
    remediation: 'Set all session cookies with `Secure; HttpOnly; SameSite=Lax`. In Express: `res.cookie(name, value, { secure: true, httpOnly: true, sameSite: \'lax\' })`. In Django: `SESSION_COOKIE_SECURE=True`, `SESSION_COOKIE_HTTPONLY=True`.',
  };
  const paths = ['/', '/login', '/signin', '/auth', '/account/login'];
  try {
    const responses = await Promise.allSettled(
      paths.map(p => fetchWithTimeout(`https://${domain}${p}`, { redirect: 'manual' }, 6000))
    );
    const allCookies: string[] = [];
    for (const r of responses) {
      if (r.status === 'fulfilled') {
        r.value.headers.getSetCookie?.()?.forEach((c: string) => allCookies.push(c));
      }
    }
    if (allCookies.length === 0) {
      return { ...base, status: 'info', finding: 'No Set-Cookie headers found on main page or common auth paths' };
    }
    const missing: string[] = [];
    for (const cookie of allCookies) {
      const lower = cookie.toLowerCase();
      if (!lower.includes('secure')) missing.push('Secure');
      if (!lower.includes('httponly')) missing.push('HttpOnly');
    }
    const unique = [...new Set(missing)];
    if (unique.length > 0) {
      return { ...base, status: 'fail', finding: `Cookies found missing: ${unique.join(', ')} flag${unique.length > 1 ? 's' : ''}` };
    }
    return { ...base, status: 'pass', finding: `All ${allCookies.length} cookie(s) have Secure and HttpOnly flags set` };
  } catch {
    return { ...base, status: 'error', finding: 'Could not fetch cookies from auth paths' };
  }
}

async function checkSpfExists(domain: string): Promise<CheckResult> {
  const base: Omit<CheckResult, 'status' | 'finding'> = {
    id: 'spf_exists', name: 'SPF Record', category: 'email', severity: 'medium',
    detail: 'Sender Policy Framework (SPF) declares which mail servers are authorised to send email for this domain. Without it, anyone can spoof your domain in phishing emails targeting your users.',
    remediation: 'Add a TXT record: `v=spf1 include:_spf.yourmailprovider.com -all`. Use `-all` (hard fail) rather than `~all` (soft fail) for production domains.',
  };
  try {
    const data = await dnsQuery(domain, 'TXT');
    const spf = data.Answer?.find(r => r.data.replace(/"/g, '').startsWith('v=spf1'));
    if (!spf) return { ...base, status: 'fail', finding: 'No SPF record found for this domain' };
    return { ...base, status: 'pass', finding: `SPF record found: ${spf.data.replace(/"/g, '').slice(0, 80)}` };
  } catch {
    return { ...base, status: 'error', finding: 'DNS query failed — could not check SPF record' };
  }
}

async function checkDmarcExists(domain: string): Promise<CheckResult> {
  const base: Omit<CheckResult, 'status' | 'finding'> = {
    id: 'dmarc_exists', name: 'DMARC Record', category: 'email', severity: 'medium',
    detail: 'DMARC (Domain-based Message Authentication, Reporting & Conformance) tells receiving mail servers what to do when SPF or DKIM fails. Without it, spoofed emails from your domain reach inboxes unchallenged.',
    remediation: 'Add a TXT record at `_dmarc.yourdomain.com`: `v=DMARC1; p=quarantine; rua=mailto:dmarc@yourdomain.com`. Start with `p=none` for monitoring, then move to `quarantine` or `reject`.',
  };
  try {
    const data = await dnsQuery(`_dmarc.${domain}`, 'TXT');
    const dmarc = data.Answer?.find(r => r.data.replace(/"/g, '').startsWith('v=DMARC1'));
    if (!dmarc) return { ...base, status: 'fail', finding: 'No DMARC record found at _dmarc.' + domain };
    return { ...base, status: 'pass', finding: `DMARC record found: ${dmarc.data.replace(/"/g, '').slice(0, 80)}` };
  } catch {
    return { ...base, status: 'error', finding: 'DNS query failed — could not check DMARC record' };
  }
}

async function checkClickjacking(domain: string): Promise<CheckResult> {
  const base: Omit<CheckResult, 'status' | 'finding'> = {
    id: 'clickjacking', name: 'Clickjacking Protection', category: 'headers', severity: 'medium',
    detail: 'Without frame protection, attackers can embed your login page in a transparent iframe and trick users into clicking buttons they cannot see — submitting credentials to the attacker.',
    remediation: 'Add `X-Frame-Options: DENY` or include `frame-ancestors \'none\'` in your Content-Security-Policy. CSP frame-ancestors takes precedence over X-Frame-Options in modern browsers.',
  };
  try {
    const res = await fetchWithTimeout(`https://${domain}/`, {}, 8000);
    const xfo = res.headers.get('x-frame-options');
    const csp = res.headers.get('content-security-policy') ?? '';
    if (xfo) return { ...base, status: 'pass', finding: `X-Frame-Options: ${xfo}` };
    if (/frame-ancestors/i.test(csp)) return { ...base, status: 'pass', finding: 'CSP frame-ancestors directive is present' };
    return { ...base, status: 'fail', finding: 'No X-Frame-Options or CSP frame-ancestors directive found' };
  } catch {
    return { ...base, status: 'error', finding: 'Could not fetch headers to check clickjacking protection' };
  }
}

async function checkAdminExposure(domain: string): Promise<CheckResult> {
  const base: Omit<CheckResult, 'status' | 'finding'> = {
    id: 'admin_exposure', name: 'Admin Panel Exposure', category: 'exposure', severity: 'high',
    detail: 'Publicly accessible admin panels are a high-value target. Many credential stuffing and brute-force campaigns specifically target /admin, /wp-admin, and /administrator paths.',
    remediation: 'Restrict admin paths by IP allowlist, move them to a non-standard path, require VPN access, or serve them on a separate internal domain. Never leave admin panels publicly accessible without strong authentication and rate limiting.',
  };
  const adminPaths = ['/admin', '/wp-admin', '/administrator', '/dashboard', '/panel'];
  try {
    const results = await Promise.allSettled(
      adminPaths.map(p => fetchWithTimeout(`https://${domain}${p}`, { redirect: 'manual' }, 5000)
        .then(async r => ({ path: p, status: r.status, body: r.status === 200 ? await r.text().catch(() => '') : '' }))
      )
    );

    const exposed: string[] = [];
    let countOk = 0;
    const adminKeywords = /login|sign.?in|admin|dashboard|password|username|user.?name|wp-login|control.?panel/i;

    for (const r of results) {
      if (r.status !== 'fulfilled') continue;
      const { path, status, body } = r.value;
      if (status === 401 || status === 403) { countOk++; continue; }
      if (status === 200 && adminKeywords.test(body)) {
        exposed.push(path);
      }
    }

    if (exposed.length > 0) {
      return { ...base, status: 'fail', finding: `Admin path(s) serving content without auth gate: ${exposed.join(', ')}` };
    }
    if (countOk > 0) {
      return { ...base, status: 'pass', finding: `Admin paths return 401/403 — access control is active` };
    }
    return { ...base, status: 'pass', finding: 'Admin paths redirect or return non-200 — no exposed panels detected' };
  } catch {
    return { ...base, status: 'error', finding: 'Could not check admin path exposure' };
  }
}

// ─── paid checks ────────────────────────────────────────────────────────────

async function checkCookieSameSite(domain: string): Promise<CheckResult> {
  const base: Omit<CheckResult, 'status' | 'finding'> = {
    id: 'cookie_samesite', name: 'SameSite Cookie Policy', category: 'cookies', severity: 'high',
    detail: 'SameSite=None without Strict/Lax allows cross-site requests to include the cookie, enabling CSRF attacks. SameSite=Lax is the modern default and prevents most CSRF vectors while keeping OAuth flows working.',
    remediation: 'Set SameSite=Lax on session cookies (default in modern browsers). Only use SameSite=None with Secure if you specifically need cross-site cookie access (e.g. embedded third-party flows).',
  };
  const paths = ['/', '/login', '/signin'];
  try {
    const responses = await Promise.allSettled(
      paths.map(p => fetchWithTimeout(`https://${domain}${p}`, { redirect: 'manual' }, 6000))
    );
    const allCookies: string[] = [];
    for (const r of responses) {
      if (r.status === 'fulfilled') {
        r.value.headers.getSetCookie?.()?.forEach((c: string) => allCookies.push(c));
      }
    }
    if (allCookies.length === 0) return { ...base, status: 'info', finding: 'No cookies found to evaluate SameSite policy' };
    const noneUnsafe = allCookies.filter(c => {
      const lower = c.toLowerCase();
      return lower.includes('samesite=none') && !lower.includes('secure');
    });
    if (noneUnsafe.length > 0) {
      return { ...base, status: 'fail', finding: `${noneUnsafe.length} cookie(s) use SameSite=None without Secure — CSRF risk` };
    }
    const noSameSite = allCookies.filter(c => !/samesite=/i.test(c));
    if (noSameSite.length > 0) {
      return { ...base, status: 'warn', finding: `${noSameSite.length} cookie(s) have no explicit SameSite attribute — browsers default to Lax but explicit is better` };
    }
    return { ...base, status: 'pass', finding: 'All cookies have explicit SameSite attribute set appropriately' };
  } catch {
    return { ...base, status: 'error', finding: 'Could not evaluate SameSite policy' };
  }
}

async function checkCookiePrefixes(domain: string): Promise<CheckResult> {
  const base: Omit<CheckResult, 'status' | 'finding'> = {
    id: 'cookie_prefixes', name: 'Secure Cookie Prefixes', category: 'cookies', severity: 'low',
    detail: '__Secure- prefix requires the cookie to be set over HTTPS and have the Secure flag. __Host- additionally requires no Domain attribute and Path=/, preventing subdomain fixation attacks.',
    remediation: 'Rename session cookies to use __Host- prefix: `Set-Cookie: __Host-session=value; Secure; HttpOnly; SameSite=Lax; Path=/`. This is a defence-in-depth measure, not a standalone fix.',
  };
  try {
    const res = await fetchWithTimeout(`https://${domain}/`, { redirect: 'manual' }, 6000);
    const cookies = res.headers.getSetCookie?.() ?? [];
    if (cookies.length === 0) return { ...base, status: 'info', finding: 'No cookies found on main page to evaluate' };
    const prefixed = cookies.filter(c => c.startsWith('__Secure-') || c.startsWith('__Host-'));
    if (prefixed.length > 0) return { ...base, status: 'pass', finding: `${prefixed.length}/${cookies.length} cookie(s) use __Secure- or __Host- prefix` };
    return { ...base, status: 'warn', finding: `None of the ${cookies.length} cookie(s) use __Secure- or __Host- prefixes` };
  } catch {
    return { ...base, status: 'error', finding: 'Could not evaluate cookie prefixes' };
  }
}

async function checkCspQuality(domain: string): Promise<CheckResult> {
  const base: Omit<CheckResult, 'status' | 'finding'> = {
    id: 'csp_quality', name: 'Content-Security-Policy Strength', category: 'headers', severity: 'high',
    detail: 'A weak CSP with unsafe-inline or unsafe-eval negates XSS protection. Wildcard sources (*) allow loading from any origin. A missing CSP means the browser applies no source restrictions.',
    remediation: 'Build a strict CSP: `default-src \'self\'; script-src \'self\' \'nonce-{random}\'; style-src \'self\' \'unsafe-inline\'; img-src \'self\' data: https:; frame-ancestors \'none\'`. Use a nonce for inline scripts rather than unsafe-inline.',
  };
  try {
    const res = await fetchWithTimeout(`https://${domain}/`, {}, 8000);
    const csp = res.headers.get('content-security-policy');
    if (!csp) return { ...base, status: 'fail', finding: 'No Content-Security-Policy header found' };
    const issues: string[] = [];
    if (/unsafe-inline/i.test(csp)) issues.push("'unsafe-inline'");
    if (/unsafe-eval/i.test(csp)) issues.push("'unsafe-eval'");
    if (/\*\s*(;|$)/.test(csp) || /src\s+\*/i.test(csp)) issues.push('wildcard source (*)');
    if (issues.length > 0) return { ...base, status: 'warn', finding: `CSP present but contains weakening directives: ${issues.join(', ')}` };
    return { ...base, status: 'pass', finding: 'CSP present with no detected unsafe directives' };
  } catch {
    return { ...base, status: 'error', finding: 'Could not fetch CSP header' };
  }
}

async function checkReferrerPolicy(domain: string): Promise<CheckResult> {
  const base: Omit<CheckResult, 'status' | 'finding'> = {
    id: 'referrer_policy', name: 'Referrer-Policy', category: 'headers', severity: 'medium',
    detail: 'Without a Referrer-Policy, browsers may include full URLs (including query params with tokens) in the Referer header when navigating away from your site. This can leak session IDs and OAuth state to third-party analytics.',
    remediation: 'Add `Referrer-Policy: strict-origin-when-cross-origin` or `no-referrer`. Avoid `unsafe-url` which sends full URLs including fragments and query strings.',
  };
  try {
    const res = await fetchWithTimeout(`https://${domain}/`, {}, 8000);
    const rp = res.headers.get('referrer-policy');
    if (!rp) return { ...base, status: 'warn', finding: 'Referrer-Policy header is missing — browsers default to no-referrer-when-downgrade' };
    if (/unsafe-url/i.test(rp)) return { ...base, status: 'fail', finding: `Referrer-Policy is set to unsafe-url — full URLs including query strings are sent` };
    return { ...base, status: 'pass', finding: `Referrer-Policy: ${rp}` };
  } catch {
    return { ...base, status: 'error', finding: 'Could not check Referrer-Policy' };
  }
}

async function checkPermissionsPolicy(domain: string): Promise<CheckResult> {
  const base: Omit<CheckResult, 'status' | 'finding'> = {
    id: 'permissions_policy', name: 'Permissions-Policy', category: 'headers', severity: 'low',
    detail: 'Permissions-Policy restricts browser features (camera, microphone, geolocation) on auth pages. Without it, third-party scripts embedded in the page can request sensitive device access.',
    remediation: 'Add `Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()` to restrict features not needed on auth pages.',
  };
  try {
    const res = await fetchWithTimeout(`https://${domain}/`, {}, 8000);
    const pp = res.headers.get('permissions-policy');
    if (!pp) return { ...base, status: 'warn', finding: 'Permissions-Policy header is absent — browser features are unrestricted' };
    return { ...base, status: 'pass', finding: `Permissions-Policy is configured` };
  } catch {
    return { ...base, status: 'error', finding: 'Could not check Permissions-Policy' };
  }
}

async function checkCoop(domain: string): Promise<CheckResult> {
  const base: Omit<CheckResult, 'status' | 'finding'> = {
    id: 'coop', name: 'Cross-Origin Isolation', category: 'headers', severity: 'medium',
    detail: 'Cross-Origin-Opener-Policy (COOP) prevents other origins from getting a reference to your window object, blocking cross-origin attacks like Spectre variants. CORP restricts which origins can load your resources.',
    remediation: 'Add `Cross-Origin-Opener-Policy: same-origin` on auth pages. For APIs serving resources to specific origins, add `Cross-Origin-Resource-Policy: same-site`.',
  };
  try {
    const res = await fetchWithTimeout(`https://${domain}/`, {}, 8000);
    const coop = res.headers.get('cross-origin-opener-policy');
    const corp = res.headers.get('cross-origin-resource-policy');
    if (!coop && !corp) return { ...base, status: 'warn', finding: 'Neither COOP nor CORP headers are set' };
    const parts: string[] = [];
    if (coop) parts.push(`COOP: ${coop}`);
    if (corp) parts.push(`CORP: ${corp}`);
    return { ...base, status: 'pass', finding: parts.join(' · ') };
  } catch {
    return { ...base, status: 'error', finding: 'Could not check cross-origin isolation headers' };
  }
}

async function checkOidcDiscovery(domain: string): Promise<CheckResult> {
  const base: Omit<CheckResult, 'status' | 'finding'> = {
    id: 'oidc_discovery', name: 'OIDC Discovery Endpoint', category: 'oauth', severity: 'info',
    detail: 'The OpenID Connect discovery document at /.well-known/openid-configuration exposes the authorization server\'s metadata including supported flows, scopes, and endpoints. It is informational — its presence tells us this domain operates an identity provider.',
    remediation: 'No action required if found. Review the metadata to ensure deprecated grant types are not advertised (see Grant Types check). Restrict the endpoint if it should not be publicly accessible.',
  };
  try {
    const res = await fetchWithTimeout(`https://${domain}/.well-known/openid-configuration`, {}, 6000);
    if (!res.ok) return { ...base, status: 'info', finding: 'No OIDC discovery endpoint found (not an identity provider, or hosted elsewhere)' };
    const meta = await res.json() as Record<string, unknown>;
    const issuer = typeof meta.issuer === 'string' ? meta.issuer : 'unknown';
    return { ...base, status: 'info', finding: `OIDC discovery found — issuer: ${issuer}` };
  } catch {
    return { ...base, status: 'info', finding: 'No OIDC discovery endpoint found or request failed' };
  }
}

async function checkPkceSupport(domain: string): Promise<CheckResult> {
  const base: Omit<CheckResult, 'status' | 'finding'> = {
    id: 'pkce_support', name: 'PKCE Enforcement', category: 'oauth', severity: 'high',
    detail: 'PKCE (Proof Key for Code Exchange) prevents authorization code interception attacks. For public clients (SPAs, mobile apps) PKCE is mandatory per OAuth 2.1. An authorization server that does not advertise PKCE may allow code injection.',
    remediation: 'Require PKCE for all public clients. In the OIDC metadata, code_challenge_methods_supported should include S256. In Auth0: Applications → Advanced → PKCE Enabled. In Cognito: app client settings → Enable PKCE.',
  };
  try {
    const res = await fetchWithTimeout(`https://${domain}/.well-known/openid-configuration`, {}, 6000);
    if (!res.ok) return { ...base, status: 'info', finding: 'No OIDC discovery endpoint — PKCE check not applicable' };
    const meta = await res.json() as { code_challenge_methods_supported?: string[] };
    const methods = meta.code_challenge_methods_supported ?? [];
    if (methods.includes('S256')) return { ...base, status: 'pass', finding: 'PKCE S256 is listed in supported code challenge methods' };
    if (methods.length > 0) return { ...base, status: 'warn', finding: `PKCE methods found but S256 not listed: ${methods.join(', ')}` };
    return { ...base, status: 'fail', finding: 'OIDC metadata does not advertise PKCE support (code_challenge_methods_supported absent)' };
  } catch {
    return { ...base, status: 'error', finding: 'Could not evaluate PKCE support' };
  }
}

async function checkGrantTypes(domain: string): Promise<CheckResult> {
  const base: Omit<CheckResult, 'status' | 'finding'> = {
    id: 'grant_types', name: 'Deprecated OAuth Grant Types', category: 'oauth', severity: 'high',
    detail: 'The implicit grant and password grant (Resource Owner Password Credentials) are deprecated in OAuth 2.1. Implicit flow exposes tokens in URL fragments; the password grant requires clients to handle user credentials directly.',
    remediation: 'Migrate implicit flow clients to Authorization Code + PKCE. Replace password grant with device authorization flow or Authorization Code flow. Remove deprecated grants from the authorization server\'s supported list.',
  };
  try {
    const res = await fetchWithTimeout(`https://${domain}/.well-known/openid-configuration`, {}, 6000);
    if (!res.ok) return { ...base, status: 'info', finding: 'No OIDC discovery endpoint — grant type check not applicable' };
    const meta = await res.json() as { grant_types_supported?: string[] };
    const grants = meta.grant_types_supported ?? [];
    const deprecated = grants.filter(g => g === 'implicit' || g === 'password');
    if (deprecated.length > 0) return { ...base, status: 'fail', finding: `Deprecated grant type(s) advertised: ${deprecated.join(', ')}` };
    return { ...base, status: 'pass', finding: `Supported grants: ${grants.join(', ') || 'not specified'} — no deprecated flows detected` };
  } catch {
    return { ...base, status: 'error', finding: 'Could not evaluate OAuth grant types' };
  }
}

async function checkWebauthnSupport(domain: string): Promise<CheckResult> {
  const base: Omit<CheckResult, 'status' | 'finding'> = {
    id: 'webauthn_support', name: 'Passkey / WebAuthn Support', category: 'oauth', severity: 'info',
    detail: 'Passkeys (FIDO2/WebAuthn) are phishing-resistant authenticators that cannot be stolen via standard phishing or replayed across origins. NIST SP 800-63-4 classifies synced passkeys as meeting AAL2.',
    remediation: 'Implement WebAuthn using the browser Credential Management API. Libraries: SimpleWebAuthn (Node.js), py_webauthn (Python), java-webauthn-server. For hosted identity: Okta, Auth0, and Microsoft Entra support passkeys natively.',
  };
  try {
    const res = await fetchWithTimeout(`https://${domain}/.well-known/webauthn`, {}, 5000);
    if (res.ok) return { ...base, status: 'pass', finding: 'WebAuthn /.well-known/webauthn endpoint is present' };
    return { ...base, status: 'info', finding: 'No WebAuthn well-known endpoint detected — passkey support may still exist in the application' };
  } catch {
    return { ...base, status: 'info', finding: 'Could not check WebAuthn endpoint' };
  }
}

async function checkDkimRecord(domain: string): Promise<CheckResult> {
  const base: Omit<CheckResult, 'status' | 'finding'> = {
    id: 'dkim_record', name: 'DKIM Record', category: 'email', severity: 'medium',
    detail: 'DKIM (DomainKeys Identified Mail) adds a cryptographic signature to outgoing email that receiving servers can verify. Combined with DMARC, it prevents email spoofing. Without DKIM, DMARC alignment via DKIM is impossible.',
    remediation: 'Configure DKIM with your email provider and publish the public key as a TXT record at `selector._domainkey.yourdomain.com`. Common selectors: default, google, mail, dkim1.',
  };
  const selectors = ['default', 'google', 'mail', 'dkim1', 's1', 's2'];
  try {
    const queries = await Promise.allSettled(
      selectors.map(s => dnsQuery(`${s}._domainkey.${domain}`, 'TXT'))
    );
    const found = selectors.filter((s, i) => {
      const r = queries[i];
      return r.status === 'fulfilled' && (r.value.Answer?.length ?? 0) > 0;
    });
    if (found.length > 0) return { ...base, status: 'pass', finding: `DKIM record found for selector(s): ${found.join(', ')}` };
    return { ...base, status: 'warn', finding: `No DKIM record found for common selectors (${selectors.join(', ')}) — custom selector may be in use` };
  } catch {
    return { ...base, status: 'error', finding: 'Could not query DKIM records' };
  }
}

async function checkDmarcPolicy(domain: string): Promise<CheckResult> {
  const base: Omit<CheckResult, 'status' | 'finding'> = {
    id: 'dmarc_policy', name: 'DMARC Policy Level', category: 'email', severity: 'high',
    detail: 'p=none only monitors DMARC failures — it does not quarantine or reject spoofed emails. p=quarantine sends failing messages to spam. p=reject is the gold standard: spoofed emails are dropped at the receiving server.',
    remediation: 'Progress from p=none (monitoring) → p=quarantine (partial enforcement) → p=reject (full enforcement). Review rua/ruf aggregate reports before each step. Allow 2–4 weeks at each level to catch legitimate sending sources.',
  };
  try {
    const data = await dnsQuery(`_dmarc.${domain}`, 'TXT');
    const record = data.Answer?.find(r => r.data.replace(/"/g, '').startsWith('v=DMARC1'));
    if (!record) return { ...base, status: 'fail', finding: 'No DMARC record — policy check not possible' };
    const text = record.data.replace(/"/g, '');
    const pMatch = text.match(/\bp=([a-z]+)/i);
    const policy = pMatch?.[1]?.toLowerCase() ?? 'none';
    if (policy === 'reject') return { ...base, status: 'pass', finding: 'DMARC policy is p=reject — maximum enforcement' };
    if (policy === 'quarantine') return { ...base, status: 'warn', finding: 'DMARC policy is p=quarantine — consider upgrading to p=reject' };
    return { ...base, status: 'fail', finding: 'DMARC policy is p=none — monitoring only, spoofed emails are not blocked' };
  } catch {
    return { ...base, status: 'error', finding: 'Could not evaluate DMARC policy' };
  }
}

async function checkSpfStrength(domain: string): Promise<CheckResult> {
  const base: Omit<CheckResult, 'status' | 'finding'> = {
    id: 'spf_strength', name: 'SPF Enforcement Level', category: 'email', severity: 'high',
    detail: '~all (soft fail) marks unauthorised senders as suspicious but still delivers the email. +all permits any server to send mail. Only -all (hard fail) instructs receiving servers to reject unauthorised mail.',
    remediation: 'Change the SPF record to end with `-all` after verifying all legitimate sending sources are included (e.g. Google Workspace, SendGrid, Mailchimp). Test with mail-tester.com before switching.',
  };
  try {
    const data = await dnsQuery(domain, 'TXT');
    const spf = data.Answer?.find(r => r.data.replace(/"/g, '').startsWith('v=spf1'));
    if (!spf) return { ...base, status: 'fail', finding: 'No SPF record found' };
    const text = spf.data.replace(/"/g, '');
    if (text.includes('-all')) return { ...base, status: 'pass', finding: 'SPF ends with -all (hard fail) — strongest enforcement' };
    if (text.includes('~all')) return { ...base, status: 'warn', finding: 'SPF ends with ~all (soft fail) — consider upgrading to -all' };
    if (text.includes('+all')) return { ...base, status: 'fail', finding: 'SPF ends with +all — any server is permitted to send on behalf of this domain' };
    return { ...base, status: 'warn', finding: 'SPF record has no explicit all qualifier' };
  } catch {
    return { ...base, status: 'error', finding: 'Could not evaluate SPF strength' };
  }
}

async function checkSubdomainSurface(domain: string): Promise<CheckResult> {
  const base: Omit<CheckResult, 'status' | 'finding'> = {
    id: 'subdomain_surface', name: 'Auth Subdomain Surface', category: 'exposure', severity: 'info',
    detail: 'Auth-named subdomains (auth., sso., login., id.) represent your identity perimeter. Knowing which are live helps scope attack surface and ensures orphaned subdomains are not forgotten.',
    remediation: 'For each live auth subdomain: verify it is intentional, confirm it requires authentication before revealing any content, and ensure it inherits your HSTS and security header policies.',
  };
  const subdomains = ['auth', 'sso', 'login', 'id', 'identity', 'account', 'accounts'];
  try {
    const queries = await Promise.allSettled(
      subdomains.map(s => dnsQuery(`${s}.${domain}`, 'A'))
    );
    const live = subdomains.filter((s, i) => {
      const r = queries[i];
      return r.status === 'fulfilled' && (r.value.Answer?.length ?? 0) > 0;
    });
    if (live.length === 0) return { ...base, status: 'info', finding: 'No auth-related subdomains found in DNS' };
    return { ...base, status: 'info', finding: `Auth subdomains found in DNS: ${live.map(s => s + '.' + domain).join(', ')}` };
  } catch {
    return { ...base, status: 'error', finding: 'Could not query subdomain DNS records' };
  }
}

async function checkCorsPolicy(domain: string): Promise<CheckResult> {
  const base: Omit<CheckResult, 'status' | 'finding'> = {
    id: 'cors_headers', name: 'CORS Policy', category: 'headers', severity: 'high',
    detail: 'A wildcard CORS policy (Access-Control-Allow-Origin: *) with credentials enabled allows any website to make authenticated cross-origin requests on behalf of the user. This can expose session data and API responses to malicious origins.',
    remediation: 'Replace wildcard origins with an explicit allowlist. Never combine `Access-Control-Allow-Origin: *` with `Access-Control-Allow-Credentials: true`. Validate the Origin header server-side against an allowlist.',
  };
  try {
    const res = await fetchWithTimeout(`https://${domain}/`, {
      headers: { Origin: 'https://evil.example.com' },
    }, 8000);
    const acao = res.headers.get('access-control-allow-origin');
    const acac = res.headers.get('access-control-allow-credentials');
    if (!acao) return { ...base, status: 'pass', finding: 'No CORS headers returned for cross-origin request — expected for most sites' };
    if (acao === '*' && acac === 'true') return { ...base, status: 'fail', finding: 'CORS wildcard (*) with credentials:true — any origin can make authenticated requests' };
    if (acao === '*') return { ...base, status: 'warn', finding: 'CORS Access-Control-Allow-Origin: * is set — acceptable only for fully public APIs without credentials' };
    return { ...base, status: 'pass', finding: `CORS allows specific origin: ${acao}` };
  } catch {
    return { ...base, status: 'error', finding: 'Could not test CORS policy' };
  }
}

async function checkSecurityTxt(domain: string): Promise<CheckResult> {
  const base: Omit<CheckResult, 'status' | 'finding'> = {
    id: 'security_txt', name: 'Security.txt', category: 'exposure', severity: 'info',
    detail: 'security.txt (RFC 9116) provides a standard way for security researchers to report vulnerabilities. Its presence signals a mature security posture and reduces the friction for responsible disclosure.',
    remediation: 'Create a file at /.well-known/security.txt with at minimum: `Contact: mailto:security@yourdomain.com` and `Expires: [date one year from now]`. Generator: securitytxt.org.',
  };
  try {
    const res = await fetchWithTimeout(`https://${domain}/.well-known/security.txt`, {}, 5000);
    if (res.ok) return { ...base, status: 'pass', finding: 'security.txt is present at /.well-known/security.txt' };
    return { ...base, status: 'info', finding: 'No security.txt found — consider adding one for responsible disclosure' };
  } catch {
    return { ...base, status: 'info', finding: 'Could not check for security.txt' };
  }
}

async function checkOAuthUsage(domain: string): Promise<CheckResult> {
  const base: Omit<CheckResult, 'status' | 'finding'> = {
    id: 'oauth_usage', name: 'OAuth / OIDC Usage', category: 'oauth', severity: 'info',
    detail: 'Detecting whether the site uses OAuth 2.0 or OpenID Connect helps understand the overall authentication architecture. Sites using OAuth delegate identity decisions to an authorization server, which changes the attack surface relative to home-grown auth.',
    remediation: 'If OAuth is in use, ensure you are using Authorization Code + PKCE (not implicit flow), validate state and nonce parameters, and bind tokens to the client that requested them.',
  };
  try {
    const [discoveryRes, ...pageResponses] = await Promise.allSettled([
      fetchWithTimeout(`https://${domain}/.well-known/openid-configuration`, {}, 5000),
      fetchWithTimeout(`https://${domain}/`, {}, 6000),
      fetchWithTimeout(`https://${domain}/login`, { redirect: 'manual' }, 5000),
      fetchWithTimeout(`https://${domain}/signin`, { redirect: 'manual' }, 5000),
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

    return { ...base, status: 'info', finding: 'No OAuth or OIDC usage detected — may use session-based or custom authentication' };
  } catch {
    return { ...base, status: 'error', finding: 'Could not determine OAuth usage' };
  }
}

const IDP_SIGNATURES: Array<{ name: string; patterns: RegExp[] }> = [
  { name: 'Auth0',             patterns: [/cdn\.auth0\.com|auth0\.js|\.auth0\.com/i] },
  { name: 'Okta',              patterns: [/\.okta\.com|\.okta-emea\.com|okta-auth-js|okta-core/i] },
  { name: 'Microsoft Entra / Azure AD', patterns: [/login\.microsoftonline\.com|aadcdn\.msftauth|msal\.js|\.b2clogin\.com/i] },
  { name: 'Google Identity',   patterns: [/accounts\.google\.com|gsi\/client|google-signin|accounts\.google/i] },
  { name: 'AWS Cognito',       patterns: [/cognito-idp\.|amazoncognito\.com|amazon-cognito/i] },
  { name: 'Ping Identity / PingOne', patterns: [/\.pingone\.com|\.pingidentity\.com|\.ping\.com/i] },
  { name: 'OneLogin',          patterns: [/\.onelogin\.com/i] },
  { name: 'Keycloak',          patterns: [/\/auth\/realms\/|keycloak\.js|keycloak/i] },
  { name: 'Firebase Auth',     patterns: [/identitytoolkit\.googleapis\.com|firebaseapp\.com\/__|firebase-auth/i] },
  { name: 'Cloudflare Access', patterns: [/cloudflareaccess\.com/i] },
  { name: 'ForgeRock / PingAM',patterns: [/forgerock\.com|\.forgerock\.io|openam/i] },
  { name: 'Salesforce Identity', patterns: [/salesforce\.com\/services\/auth|salesforce-identity/i] },
  { name: 'WorkOS',            patterns: [/workos\.com|authkit\.com/i] },
  { name: 'Clerk',             patterns: [/clerk\.dev|clerk\.com|\.clerk\.accounts/i] },
  { name: 'Stytch',            patterns: [/stytch\.com/i] },
  { name: 'Passage (1Password)', patterns: [/passage\.id|passageidentity\.com/i] },
];

async function checkIdpDetection(domain: string): Promise<CheckResult> {
  const base: Omit<CheckResult, 'status' | 'finding'> = {
    id: 'idp_detection', name: 'Identity Provider Detection', category: 'oauth', severity: 'info',
    detail: 'Identifying the identity provider in use helps understand the authentication architecture, dependency chain, and where to direct security configuration effort. It also surfaces whether a well-maintained hosted IdP is in use vs a custom implementation.',
    remediation: 'No action required from detection alone. Ensure your IdP is on a supported version, MFA enforcement is configured, and admin access to the IdP console itself is protected with phishing-resistant authentication.',
  };
  try {
    const pages = await Promise.allSettled([
      fetchWithTimeout(`https://${domain}/`, {}, 6000).then(r => r.text()),
      fetchWithTimeout(`https://${domain}/login`, { redirect: 'manual' }, 5000).then(r => r.text()),
      fetchWithTimeout(`https://${domain}/signin`, { redirect: 'manual' }, 5000).then(r => r.text()),
    ]);

    const corpus = pages
      .filter((r): r is PromiseFulfilledResult<string> => r.status === 'fulfilled')
      .map(r => r.value)
      .join('\n');

    // Also check OIDC issuer for IdP hints
    let oidcIssuer = '';
    try {
      const disc = await fetchWithTimeout(`https://${domain}/.well-known/openid-configuration`, {}, 4000);
      if (disc.ok) {
        const meta = await disc.json() as { issuer?: string };
        oidcIssuer = meta.issuer ?? '';
      }
    } catch { /* skip */ }

    const haystack = corpus + '\n' + oidcIssuer;
    const detected: string[] = [];

    for (const idp of IDP_SIGNATURES) {
      if (idp.patterns.some(p => p.test(haystack))) {
        detected.push(idp.name);
      }
    }

    if (detected.length === 0) {
      return { ...base, status: 'info', finding: 'No known identity provider fingerprint detected — may use a custom or less common IdP' };
    }
    return { ...base, status: 'pass', finding: `Identity provider detected: ${detected.join(', ')}` };
  } catch {
    return { ...base, status: 'error', finding: 'Could not scan for identity provider fingerprints' };
  }
}

async function checkPhishingResistance(domain: string): Promise<CheckResult> {
  const base: Omit<CheckResult, 'status' | 'finding'> = {
    id: 'phishing_resistance', name: 'Phishing-Resistant Authentication', category: 'oauth', severity: 'info',
    detail: 'Phishing-resistant authentication (passkeys, FIDO2 hardware keys) binds the credential to the origin domain at the cryptographic level. A passkey issued for app.example.com cannot be used on fake-app.example.com — the browser enforces this automatically. NIST SP 800-63-4 requires phishing-resistant MFA for AAL3 and endorses it for AAL2.',
    remediation: 'Implement WebAuthn via the browser Credential Management API or a hosted IdP with native passkey support (Okta, Auth0, Microsoft Entra, Google Identity). Libraries: SimpleWebAuthn (Node), py_webauthn (Python). Publish /.well-known/webauthn with your allowed origins.',
  };
  try {
    const [wellKnown, ...pages] = await Promise.allSettled([
      fetchWithTimeout(`https://${domain}/.well-known/webauthn`, {}, 5000),
      fetchWithTimeout(`https://${domain}/login`, { redirect: 'manual' }, 6000).then(r => r.text()),
      fetchWithTimeout(`https://${domain}/signin`, { redirect: 'manual' }, 5000).then(r => r.text()),
      fetchWithTimeout(`https://${domain}/`, {}, 6000).then(r => r.text()),
    ]);

    const wellKnownFound = wellKnown.status === 'fulfilled' && wellKnown.value.ok;

    const corpus = pages
      .filter((r): r is PromiseFulfilledResult<string> => r.status === 'fulfilled')
      .map(r => r.value)
      .join('\n');

    const webauthnApi = /navigator\.credentials|PublicKeyCredential|webauthn|authenticatorAttachment/i.test(corpus);
    const passkeyUi   = /passkey|use your fingerprint|face id|touch id|security key|sign in with a passkey|biometric/i.test(corpus);

    const signals: string[] = [];
    if (wellKnownFound) signals.push('/.well-known/webauthn endpoint');
    if (webauthnApi)    signals.push('WebAuthn API usage in page scripts');
    if (passkeyUi)      signals.push('passkey/biometric UI language detected');

    if (signals.length >= 2) return { ...base, status: 'pass', finding: `Strong phishing-resistant auth signals: ${signals.join(', ')}` };
    if (signals.length === 1) return { ...base, status: 'warn', finding: `Partial signal — ${signals[0]} detected but not confirmed end-to-end` };
    return { ...base, status: 'info', finding: 'No passkey or WebAuthn signals detected — phishing-resistant authentication may not be offered' };
  } catch {
    return { ...base, status: 'error', finding: 'Could not evaluate phishing-resistant authentication signals' };
  }
}

async function checkAuthEndpointProtection(domain: string): Promise<CheckResult> {
  const base: Omit<CheckResult, 'status' | 'finding'> = {
    id: 'auth_endpoint_protection', name: 'Auth Endpoint Protection', category: 'exposure', severity: 'high',
    detail: 'Authentication endpoints (/login, /signin, /api/auth) are primary targets for credential stuffing and brute-force attacks. Rate limiting headers (X-RateLimit-*, Retry-After) and bot protection signals (CAPTCHA, cf-mitigated) indicate active defences.',
    remediation: 'Enforce rate limiting on all login and password-reset endpoints. Use Cloudflare Rate Limiting rules, or middleware like express-rate-limit. Return 429 Too Many Requests after threshold. Add CAPTCHA (Turnstile, hCaptcha) as a second layer. Log and alert on repeated failures from the same IP.',
  };
  const authPaths = ['/login', '/signin', '/auth', '/api/auth/login', '/api/login', '/account/login'];
  try {
    const responses = await Promise.allSettled(
      authPaths.map(p =>
        fetchWithTimeout(`https://${domain}${p}`, { redirect: 'manual' }, 5000)
          .then(r => ({
            path: p,
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

    const live = responses.filter((r): r is PromiseFulfilledResult<{ path: string; status: number; rateLimitHeaders: string[] }> =>
      r.status === 'fulfilled' && (r.value.status === 200 || r.value.status === 302 || r.value.status === 301)
    ).map(r => r.value);

    if (live.length === 0) {
      return { ...base, status: 'info', finding: 'No accessible auth endpoints found at common paths' };
    }

    const protected_ = live.filter(r => r.rateLimitHeaders.length > 0);
    if (protected_.length > 0) {
      const paths = protected_.map(r => r.path).join(', ');
      return { ...base, status: 'pass', finding: `Rate limiting headers detected on auth endpoint(s): ${paths}` };
    }

    const livePaths = live.map(r => r.path).join(', ');
    return { ...base, status: 'warn', finding: `Auth endpoint(s) accessible at ${livePaths} but no rate limiting headers detected` };
  } catch {
    return { ...base, status: 'error', finding: 'Could not evaluate auth endpoint protection' };
  }
}

// ─── route handler ───────────────────────────────────────────────────────────

const FREE_CHECKS = [
  checkSslValid,
  checkHttpsRedirect,
  checkHsts,
  checkCookieSecurity,
  checkOAuthUsage,
  checkIdpDetection,
  checkSpfExists,
  checkDmarcExists,
  checkClickjacking,
  checkAdminExposure,
];

const PAID_CHECKS = [
  ...FREE_CHECKS,
  checkCookieSameSite,
  checkCookiePrefixes,
  checkCspQuality,
  checkReferrerPolicy,
  checkPermissionsPolicy,
  checkCoop,
  checkOidcDiscovery,
  checkPkceSupport,
  checkGrantTypes,
  checkPhishingResistance,
  checkAuthEndpointProtection,
  checkDkimRecord,
  checkDmarcPolicy,
  checkSpfStrength,
  checkSubdomainSurface,
  checkCorsPolicy,
  checkSecurityTxt,
];

export const GET: APIRoute = async ({ url }) => {
  const domainParam = url.searchParams.get('domain') ?? '';
  const report = url.searchParams.get('report') === 'paid' ? 'paid' : 'free';

  const domain = sanitizeDomain(domainParam);
  if (!domain) {
    return new Response(JSON.stringify({ error: 'Invalid or disallowed domain' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  const checks = report === 'paid' ? PAID_CHECKS : FREE_CHECKS;
  const settled = await Promise.allSettled(checks.map(fn => fn(domain)));

  const results: CheckResult[] = settled.map((r, i) => {
    if (r.status === 'fulfilled') {
      const result = r.value;
      return { ...result, references: REFS[result.id] };
    }
    const id = checks[i].name.toLowerCase().replace(/\s+/g, '_');
    return {
      id,
      name: checks[i].name,
      category: 'exposure' as Category,
      status: 'error' as Status,
      severity: 'info' as Severity,
      finding: 'Check threw an unexpected error',
      errorReason: 'An internal error prevented this check from running. This is not a security finding.',
      references: REFS[id],
    };
  });

  const score = calculateScore(results);
  const grade = calculateGrade(score);

  return new Response(JSON.stringify({ domain, report, score, grade, checks: results }), {
    headers: {
      'Content-Type': 'application/json',
      'Cache-Control': 'no-store',
    },
  });
};
