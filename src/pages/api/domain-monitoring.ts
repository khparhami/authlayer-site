export const prerender = false;

import type { APIRoute } from 'astro';
import { sanitizeDomain } from '@/lib/ssrf.js';
import { runDomainMonitoring } from '@/lib/checks/domain-monitoring.js';

// ─── Rate limiting ────────────────────────────────────────────────────────────

const RATE_LIMIT_MAX = 10;      // scans per window (domain scan is expensive: 60+ DNS + crt.sh)
const RATE_LIMIT_WINDOW = 3600; // seconds

interface KVNamespace {
  get(key: string): Promise<string | null>;
  put(key: string, value: string, opts?: { expirationTtl?: number }): Promise<void>;
}

async function checkRateLimit(kv: KVNamespace | undefined, ip: string): Promise<boolean> {
  if (!kv) return true;
  const key = `rl:dm:${ip}`;
  const raw = await kv.get(key);
  const count = raw ? parseInt(raw, 10) : 0;
  if (count >= RATE_LIMIT_MAX) return false;
  await kv.put(key, String(count + 1), { expirationTtl: RATE_LIMIT_WINDOW });
  return true;
}

// ─── Route handler ────────────────────────────────────────────────────────────

export const GET: APIRoute = async ({ url, request, locals }) => {
  const ip = request.headers.get('cf-connecting-ip')
    ?? request.headers.get('x-forwarded-for')?.split(',')[0]?.trim()
    ?? 'unknown';

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

  const domainParam = url.searchParams.get('domain') ?? '';
  const domain = sanitizeDomain(domainParam);

  if (!domain) {
    return new Response(JSON.stringify({ error: 'Invalid or disallowed domain' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  try {
    const result = await runDomainMonitoring(domain);
    return new Response(JSON.stringify({ domain, ...result }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Scan failed';
    return new Response(JSON.stringify({ error: message }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' },
    });
  }
};
