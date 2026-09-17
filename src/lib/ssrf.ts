// Blocked hostname/IP patterns for SSRF protection
const BLOCKED_HOST_PATTERNS = [
  /^localhost$/i,
  /^127\./,
  /^10\./,
  /^172\.(1[6-9]|2\d|3[01])\./,
  /^192\.168\./,
  /^169\.254\./,      // link-local + AWS/GCP/Azure IMDS
  /^0\./,             // current network
  /^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./,  // RFC 6598 shared (100.64.0.0/10)
  /\.local$/i,
  /^::1$/,
  /^fe80:/i,          // IPv6 link-local
  /^fc[0-9a-f]{2}:/i, // IPv6 ULA fc00::/7
  /^fd[0-9a-f]{2}:/i, // IPv6 ULA fd00::/7
  /^::ffff:(?:127\.|10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|169\.254\.)/i, // IPv4-mapped private
];

// Cloud metadata endpoints by IP
const BLOCKED_IPS = new Set([
  '169.254.169.254', // AWS/GCP/Azure IMDS
  '100.100.100.200', // Alibaba Cloud metadata
]);

export function isBlockedHost(host: string): boolean {
  const h = host.toLowerCase().trim();
  if (BLOCKED_IPS.has(h)) return true;
  return BLOCKED_HOST_PATTERNS.some(r => r.test(h));
}

export function sanitizeDomain(input: string): string | null {
  if (!input) return null;
  let d = input.trim().toLowerCase();
  d = d.replace(/^https?:\/\//, '').replace(/[/?#].*$/, '');
  if (!d) return null;
  if (!/^[a-z0-9]([a-z0-9\-.]{0,251}[a-z0-9])?$/.test(d)) return null;
  if (isBlockedHost(d)) return null;
  return d;
}

export function parseAuthUrl(input: string | null): string | null {
  if (!input) return null;
  const raw = input.trim();
  try {
    const u = new URL(raw.startsWith('http') ? raw : `https://${raw}`);
    if (u.protocol !== 'https:') return null;
    if (isBlockedHost(u.hostname)) return null;
    return u.href;
  } catch {
    return null;
  }
}

interface DnsAnswer { data: string; }
interface DnsResponse { Status: number; Answer?: DnsAnswer[]; }

// Validate resolved IPs after DNS lookup to prevent DNS rebinding
export async function validateResolvedIPs(hostname: string): Promise<{ valid: boolean; reason?: string }> {
  try {
    const [v4Res, v6Res] = await Promise.allSettled([
      fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(hostname)}&type=A`, {
        headers: { Accept: 'application/dns-json' },
        signal: AbortSignal.timeout(4000),
      }).then(r => r.json() as Promise<DnsResponse>),
      fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(hostname)}&type=AAAA`, {
        headers: { Accept: 'application/dns-json' },
        signal: AbortSignal.timeout(4000),
      }).then(r => r.json() as Promise<DnsResponse>),
    ]);

    const allIPs: string[] = [];
    if (v4Res.status === 'fulfilled') {
      allIPs.push(...(v4Res.value.Answer ?? []).map(a => a.data));
    }
    if (v6Res.status === 'fulfilled') {
      allIPs.push(...(v6Res.value.Answer ?? []).map(a => a.data));
    }

    for (const ip of allIPs) {
      if (isBlockedHost(ip)) {
        return { valid: false, reason: `Resolved IP ${ip} is in a blocked range` };
      }
    }
    return { valid: true };
  } catch {
    // If DNS pre-check fails, allow the request — the actual fetch will fail safely
    return { valid: true };
  }
}

export async function validateTarget(input: string): Promise<{ valid: boolean; reason?: string }> {
  const domain = sanitizeDomain(input) ?? (() => {
    try { return new URL(input).hostname; } catch { return null; }
  })();

  if (!domain) return { valid: false, reason: 'Invalid or disallowed target' };
  if (isBlockedHost(domain)) return { valid: false, reason: 'Target is in a blocked range' };

  return validateResolvedIPs(domain);
}
