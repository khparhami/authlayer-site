export const prerender = false;

import type { APIRoute } from 'astro';
import {
  getDB, getUserEmail, upsertUser, createOrg, createBrand,
  addLegitimateAsset, setUserOrg,
} from '@/lib/db/client.js';

const DOMAIN_RE = /^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?)+$/i;

function parseDomains(raw: string): string[] {
  return raw
    .split(/[\n,]+/)
    .map(s => s.trim().toLowerCase().replace(/^https?:\/\//, '').split('/')[0])
    .filter(Boolean);
}

function parseNames(raw: string): string[] {
  return raw.split('\n').map(s => s.trim()).filter(Boolean);
}

export const POST: APIRoute = async ({ request, locals }) => {
  const email = getUserEmail(request);
  if (!email) return new Response(null, { status: 401 });

  const db = getDB(locals as Record<string, unknown>);
  if (!db) return new Response('Database unavailable', { status: 503 });

  const form = await request.formData();
  const orgName = (form.get('org_name') as string ?? '').trim();
  const domainsRaw = (form.get('domains') as string ?? '').trim();
  const brandsRaw = (form.get('brands') as string ?? '').trim();

  const redirect = (err: string) =>
    new Response(null, { status: 302, headers: { Location: `/account/setup?error=${err}` } });

  if (!orgName || !domainsRaw) return redirect('missing_fields');

  const domains = parseDomains(domainsRaw);
  if (domains.length === 0) return redirect('missing_fields');
  if (domains.some(d => !DOMAIN_RE.test(d))) return redirect('invalid_domain');

  try {
    const user = await upsertUser(db, email);

    // Don't re-setup if already has an org
    if (user.org_id) {
      return new Response(null, { status: 302, headers: { Location: '/account' } });
    }

    const org = await createOrg(db, orgName);

    // Primary brand from org name; additional brands from form
    await createBrand(db, org.id, orgName, true);
    const extraBrands = parseNames(brandsRaw).filter(n => n.toLowerCase() !== orgName.toLowerCase());
    for (const name of extraBrands) {
      await createBrand(db, org.id, name, false);
    }

    // All provided domains go into legitimate_assets
    for (const domain of domains) {
      await addLegitimateAsset(db, org.id, 'domain', domain);
    }

    await setUserOrg(db, user.id, org.id);

    return new Response(null, { status: 302, headers: { Location: '/account' } });
  } catch {
    return redirect('db_error');
  }
};
