// Typed D1 helpers for P4

export interface D1Database {
  prepare(query: string): D1PreparedStatement;
  exec(query: string): Promise<{ count: number; duration: number }>;
}

interface D1PreparedStatement {
  bind(...values: unknown[]): D1PreparedStatement;
  first<T = Record<string, unknown>>(col?: string): Promise<T | null>;
  all<T = Record<string, unknown>>(): Promise<{ results: T[] }>;
  run(): Promise<{ success: boolean; meta: { changes: number } }>;
}

// ─── Types ────────────────────────────────────────────────────────────────────

export interface User {
  id: string;
  email: string;
  org_id: string | null;
  role: string;
  created_at: number;
}

export interface Organisation {
  id: string;
  name: string;
  created_at: number;
}

export interface Brand {
  id: string;
  org_id: string;
  name: string;
  is_primary: number;
}

export interface LegitimateAsset {
  id: string;
  org_id: string;
  type: string;
  value: string;
  source: string;
  confirmed_at: number | null;
}

export interface MonitoredDomain {
  id: string;
  org_id: string;
  domain: string;
  domain_norm: string;
  risk_level: 'highest' | 'high' | 'medium' | 'low' | 'lowest';
  risk_score: number;
  classification: string;
  attack_type: string | null;
  first_seen: number;
  last_seen: number;
  last_scanned: number | null;
  next_scan_at: number | null;
  discovery_src: string;
  review_status: 'pending' | 'reviewed' | 'dismissed';
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function uid(): string {
  return crypto.randomUUID();
}

function now(): number {
  return Math.floor(Date.now() / 1000);
}

// ─── User ─────────────────────────────────────────────────────────────────────

export async function getUserByEmail(db: D1Database, email: string): Promise<User | null> {
  return db.prepare('SELECT * FROM users WHERE email = ?').bind(email).first<User>();
}

export async function upsertUser(db: D1Database, email: string): Promise<User> {
  const existing = await getUserByEmail(db, email);
  if (existing) return existing;

  const id = uid();
  await db.prepare(
    'INSERT INTO users (id, email, org_id, role, created_at) VALUES (?, ?, NULL, ?, ?)'
  ).bind(id, email, 'admin', now()).run();

  return { id, email, org_id: null, role: 'admin', created_at: now() };
}

export async function setUserOrg(db: D1Database, userId: string, orgId: string): Promise<void> {
  await db.prepare('UPDATE users SET org_id = ? WHERE id = ?').bind(orgId, userId).run();
}

// ─── Organisation ─────────────────────────────────────────────────────────────

export async function getOrgById(db: D1Database, orgId: string): Promise<Organisation | null> {
  return db.prepare('SELECT * FROM organisations WHERE id = ?').bind(orgId).first<Organisation>();
}

export async function createOrg(db: D1Database, name: string): Promise<Organisation> {
  const id = uid();
  const createdAt = now();
  await db.prepare(
    'INSERT INTO organisations (id, name, created_at) VALUES (?, ?, ?)'
  ).bind(id, name, createdAt).run();
  return { id, name, created_at: createdAt };
}

// ─── Brands ───────────────────────────────────────────────────────────────────

export async function getBrandsByOrg(db: D1Database, orgId: string): Promise<Brand[]> {
  const { results } = await db
    .prepare('SELECT * FROM brands WHERE org_id = ? ORDER BY is_primary DESC, name ASC')
    .bind(orgId)
    .all<Brand>();
  return results;
}

export async function createBrand(
  db: D1Database,
  orgId: string,
  name: string,
  isPrimary = false,
): Promise<Brand> {
  const id = uid();
  await db.prepare(
    'INSERT INTO brands (id, org_id, name, is_primary) VALUES (?, ?, ?, ?)'
  ).bind(id, orgId, name, isPrimary ? 1 : 0).run();
  return { id, org_id: orgId, name, is_primary: isPrimary ? 1 : 0 };
}

// ─── Legitimate assets ────────────────────────────────────────────────────────

export async function getAssetsByOrg(db: D1Database, orgId: string): Promise<LegitimateAsset[]> {
  const { results } = await db
    .prepare('SELECT * FROM legitimate_assets WHERE org_id = ? ORDER BY type, value')
    .bind(orgId)
    .all<LegitimateAsset>();
  return results;
}

export async function addLegitimateAsset(
  db: D1Database,
  orgId: string,
  type: string,
  value: string,
  source = 'user_provided',
): Promise<void> {
  const id = uid();
  await db.prepare(
    `INSERT INTO legitimate_assets (id, org_id, type, value, source, confirmed_at)
     VALUES (?, ?, ?, ?, ?, ?)
     ON CONFLICT(org_id, type, value) DO NOTHING`
  ).bind(id, orgId, type, value.toLowerCase().trim(), source, now()).run();
}

// ─── Monitored domains ────────────────────────────────────────────────────────

export async function getDomainsByOrg(
  db: D1Database,
  orgId: string,
  opts?: { limit?: number; riskLevel?: string; reviewStatus?: string },
): Promise<MonitoredDomain[]> {
  const conditions = ['org_id = ?'];
  const bindings: unknown[] = [orgId];

  if (opts?.riskLevel) {
    conditions.push('risk_level = ?');
    bindings.push(opts.riskLevel);
  }
  if (opts?.reviewStatus) {
    conditions.push('review_status = ?');
    bindings.push(opts.reviewStatus);
  }

  const limit = opts?.limit ?? 100;
  const sql = `
    SELECT * FROM monitored_domains
    WHERE ${conditions.join(' AND ')}
    ORDER BY risk_score DESC, first_seen DESC
    LIMIT ?
  `;
  bindings.push(limit);

  const { results } = await db.prepare(sql).bind(...bindings).all<MonitoredDomain>();
  return results;
}

export async function countDomainsByRisk(
  db: D1Database,
  orgId: string,
): Promise<Record<string, number>> {
  const { results } = await db
    .prepare(`
      SELECT risk_level, COUNT(*) as count
      FROM monitored_domains
      WHERE org_id = ?
      GROUP BY risk_level
    `)
    .bind(orgId)
    .all<{ risk_level: string; count: number }>();

  const counts: Record<string, number> = { highest: 0, high: 0, medium: 0, low: 0, lowest: 0 };
  for (const row of results) counts[row.risk_level] = row.count;
  return counts;
}

// ─── Runtime env helper ───────────────────────────────────────────────────────

export function getDB(locals: Record<string, unknown>): D1Database | undefined {
  return (locals as { runtime?: { env?: { DB?: D1Database } } }).runtime?.env?.DB;
}

export function getUserEmail(request: Request): string | null {
  return (
    request.headers.get('CF-Access-Authenticated-User-Email') ??
    (import.meta.env.DEV ? (import.meta.env.DEV_USER_EMAIL ?? 'dev@authlayer.dev') : null)
  );
}
