export const prerender = false;

import type { APIRoute } from 'astro';
import { sanitizeDomain, parseAuthUrl, validateResolvedIPs } from '@/lib/ssrf.js';
import { FREE_TESTS, PAID_TESTS, runScan } from '@/lib/checks/registry.js';

// ─── Rate limiting ───────────────────────────────────────────────────────────

const RATE_LIMIT_MAX = 20;      // scans per window
const RATE_LIMIT_WINDOW = 3600; // seconds (1 hour)

interface KVNamespace {
  get(key: string): Promise<string | null>;
  put(key: string, value: string, opts?: { expirationTtl?: number }): Promise<void>;
}

async function checkRateLimit(kv: KVNamespace | undefined, ip: string): Promise<boolean> {
  if (!kv) return true; // no KV in local dev without binding — allow
  const key = `rl:${ip}`;
  const raw = await kv.get(key);
  const count = raw ? parseInt(raw, 10) : 0;
  if (count >= RATE_LIMIT_MAX) return false;
  await kv.put(key, String(count + 1), { expirationTtl: RATE_LIMIT_WINDOW });
  return true;
}

// ─── Route handler ───────────────────────────────────────────────────────────

export const GET: APIRoute = async ({ url, request, locals }) => {
  const ip = request.headers.get('cf-connecting-ip')
    ?? request.headers.get('x-forwarded-for')?.split(',')[0]?.trim()
    ?? 'unknown';

  // Rate limiting via Cloudflare KV (gracefully skipped if binding absent)
  const kv = (locals as Record<string, unknown>)?.runtime
    ? ((locals as { runtime: { env: Record<string, KVNamespace> } }).runtime.env?.RATE_LIMIT_KV)
    : undefined;

  const allowed = await checkRateLimit(kv, ip);
  if (!allowed) {
    return new Response(JSON.stringify({ error: 'Rate limit exceeded. Try again in an hour.' }), {
      status: 429,
      headers: { 'Content-Type': 'application/json', 'Retry-After': '3600' },
    });
  }

  // Parse and validate inputs
  const domainParam     = url.searchParams.get('domain') ?? '';
  const reportParam     = url.searchParams.get('report') === 'paid' ? 'paid' : 'free';
  const authUrlParam    = url.searchParams.get('authUrl');
  const additionalParam = url.searchParams.get('additionalAssets') ?? '';
  const scopeParam      = url.searchParams.get('scope') ?? '';

  const domain = sanitizeDomain(domainParam);
  if (!domain) {
    return new Response(JSON.stringify({ error: 'Invalid or disallowed domain' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  // Post-DNS SSRF check
  const ipCheck = await validateResolvedIPs(domain);
  if (!ipCheck.valid) {
    return new Response(JSON.stringify({ error: `Scope violation: ${ipCheck.reason}` }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  const authUrl = parseAuthUrl(authUrlParam);
  const additionalAssets = additionalParam
    .split('\n')
    .map(s => s.trim())
    .filter(Boolean)
    .map(u => parseAuthUrl(u))
    .filter((u): u is string => u !== null);

  const scope = scopeParam
    .split('\n')
    .map(s => s.trim())
    .filter(Boolean);

  const ctx = { domain, authUrl, additionalAssets, scope };
  const tests = reportParam === 'paid' ? PAID_TESTS : FREE_TESTS;
  const result = await runScan(ctx, tests);

  return new Response(JSON.stringify(result), {
    headers: {
      'Content-Type': 'application/json',
      'Cache-Control': 'no-store',
    },
  });
};
