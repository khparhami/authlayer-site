export const prerender = false;

import type { APIRoute } from 'astro';

interface KVNamespace {
  get(key: string): Promise<string | null>;
  put(key: string, value: string, opts?: { expirationTtl?: number }): Promise<void>;
  delete(key: string): Promise<void>;
}

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export const GET: APIRoute = async ({ url, locals }) => {
  const kv = (locals as Record<string, unknown>)?.runtime
    ? ((locals as { runtime: { env: Record<string, KVNamespace> } }).runtime.env?.RATE_LIMIT_KV)
    : undefined;

  if (!kv) {
    return new Response(JSON.stringify({ error: 'KV binding not available' }), {
      status: 503,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  const id = url.searchParams.get('id') ?? '';
  if (!UUID_RE.test(id)) {
    return new Response(JSON.stringify({ error: 'Invalid result ID' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  const raw = await kv.get(`result:${id}`);
  // Single-use: delete immediately after retrieval (prevents replay)
  await kv.delete(`result:${id}`);

  if (!raw) {
    return new Response(JSON.stringify({ error: 'Result not found or already retrieved' }), {
      status: 404,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  return new Response(raw, {
    headers: {
      'Content-Type':  'application/json',
      'Cache-Control': 'no-store',
    },
  });
};
