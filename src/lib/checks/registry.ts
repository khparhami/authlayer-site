import type { SecurityTest, ScanContext, ScanResult, Finding, FindingClassification } from './types.js';
import type { Asset, AttackSurface } from '../assessment/types.js';
import { runPipeline } from '../assessment/engine.js';
import { correlateFindings } from '../assessment/correlation.js';
import { DNS_TESTS } from './dns.js';
import { TRANSPORT_TESTS } from './transport.js';
import { COOKIE_TESTS } from './cookies.js';
import { HEADER_TESTS } from './headers.js';
import { EMAIL_TESTS } from './email.js';
import { OAUTH_TESTS } from './oauth.js';
import { EXPOSURE_TESTS } from './exposure.js';
import { API_TESTS } from './api.js';

// ─── Finding classification ──────────────────────────────────────────────────

export function classifyFinding(f: Finding): FindingClassification {
  if (f.status === 'pass')                                return 'passed';
  if (f.status === 'error')                               return 'not_checked';
  if (f.status === 'inconclusive')                        return 'inconclusive';
  if (f.status === 'not_run' || f.status === 'not_applicable') return 'not_checked';
  if (f.status === 'info')                                return 'security_observation';

  const highSev  = f.severity === 'critical' || f.severity === 'high';
  const highConf = f.confidence === 'confirmed' || f.confidence === 'high';
  const lowSev   = f.severity === 'low' || f.severity === 'informational';

  if (f.status === 'fail' && highSev && highConf) return 'confirmed_vulnerability';
  if (f.status === 'fail' && highSev)             return 'potential_vulnerability';
  if (f.status === 'fail' && f.severity === 'medium' && highConf) return 'potential_vulnerability';
  if (f.status === 'fail' && f.severity === 'medium') return 'security_observation';
  if (f.status === 'fail' && lowSev)              return 'hardening_recommendation';

  if (f.status === 'warn' && highSev)             return 'potential_vulnerability';
  if (f.status === 'warn' && f.severity === 'medium') return 'security_observation';
  return 'hardening_recommendation';
}

// ─── Test tiers ──────────────────────────────────────────────────────────────

export const FREE_TESTS: SecurityTest[] = [
  ...DNS_TESTS,
  ...TRANSPORT_TESTS,
  ...EMAIL_TESTS.filter(t => ['EMAIL-001', 'EMAIL-003', 'EMAIL-004'].includes(t.test_id)),
  ...EXPOSURE_TESTS.filter(t => ['INFO-001a', 'INFO-001b', 'AUTH-001b'].includes(t.test_id)),
  ...OAUTH_TESTS.filter(t => ['AUTH-008', 'EXT-004a'].includes(t.test_id)),
  HEADER_TESTS.find(t => t.test_id === 'WEB-004')!,
  HEADER_TESTS.find(t => t.test_id === 'API-008')!,
];

export const PAID_TESTS: SecurityTest[] = [
  ...DNS_TESTS,
  ...TRANSPORT_TESTS,
  ...COOKIE_TESTS,
  ...HEADER_TESTS,
  ...EMAIL_TESTS,
  ...OAUTH_TESTS,
  ...EXPOSURE_TESTS,
  ...API_TESTS,
];

// ─── Scoring ─────────────────────────────────────────────────────────────────

const SEV_WEIGHT: Record<string, number> = {
  critical: 25, high: 15, medium: 10, low: 5, informational: 0,
};

function calculateScore(findings: Finding[]): number {
  let score = 100;
  for (const f of findings) {
    if (f.status === 'fail') score -= SEV_WEIGHT[f.severity] ?? 0;
    if (f.status === 'warn') score -= Math.floor((SEV_WEIGHT[f.severity] ?? 0) / 2);
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

// ─── Attack surface builder ───────────────────────────────────────────────────

function buildAttackSurface(ctx: ScanContext): { surface: AttackSurface; assetsProvided: Asset[] } {
  const assetsProvided: Asset[] = [
    { id: `asset-${ctx.domain}`, type: 'website', hostname: ctx.domain, source: 'user_provided' },
  ];
  if (ctx.authUrl) {
    try {
      const h = new URL(ctx.authUrl).hostname;
      if (h !== ctx.domain) {
        assetsProvided.push({ id: `asset-${h}`, type: 'auth_service', hostname: h, url: ctx.authUrl, source: 'user_provided' });
      }
    } catch { /* invalid URL, skip */ }
  }
  if (ctx.apiUrl) {
    try {
      const h = new URL(ctx.apiUrl).hostname;
      assetsProvided.push({ id: `asset-${h}`, type: 'api', hostname: h, url: ctx.apiUrl, source: 'user_provided' });
    } catch { /* invalid URL, skip */ }
  }
  const surface: AttackSurface = {
    assetsProvided,
    assetsDiscovered: [],
    assetsTested: assetsProvided,
    endpoints: [],
  };
  return { surface, assetsProvided };
}

// ─── Scan runner ─────────────────────────────────────────────────────────────

export async function runScan(
  ctx: ScanContext,
  tests: SecurityTest[],
): Promise<ScanResult> {
  const assessmentId = `asmt-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;

  // Append API tests for free tier when an apiUrl is provided
  const apiTestIds = new Set(API_TESTS.map(t => t.test_id));
  const hasApiTests = tests.some(t => apiTestIds.has(t.test_id));
  const effectiveTests = (ctx.apiUrl && !hasApiTests)
    ? [...tests, ...API_TESTS]
    : tests;

  const { findings: rawFindings, auditLog, durationMs, httpRequestCount } = await runPipeline(
    ctx, effectiveTests, { assessmentId, concurrency: 6, retries: 2, retryDelayMs: 350 }
  );

  const findings: Finding[] = rawFindings.map(raw => ({ ...raw, classification: classifyFinding(raw) }));
  const correlatedFindings = correlateFindings(findings);

  const score = calculateScore(correlatedFindings);
  const grade = calculateGrade(score);

  const { surface, assetsProvided } = buildAttackSurface(ctx);

  const SORDER: Record<string, number>    = { critical: 0, high: 1, medium: 2, low: 3, informational: 4 };
  const CONF_ORDER: Record<string, number> = { confirmed: 0, high: 1, medium: 2, low: 3, informational: 4 };
  const CORDER: Record<string, number> = {
    confirmed_vulnerability: 0, potential_vulnerability: 1,
    security_observation: 2, hardening_recommendation: 3,
    inconclusive: 4, passed: 5, not_checked: 6,
  };

  const sortedFindings = [...correlatedFindings].sort((a, b) =>
    (CORDER[a.classification ?? 'not_checked'] ?? 9) - (CORDER[b.classification ?? 'not_checked'] ?? 9) ||
    (SORDER[a.severity] ?? 9) - (SORDER[b.severity] ?? 9)
  );

  const topFindings = correlatedFindings
    .filter(f =>
      f.classification === 'confirmed_vulnerability' &&
      (f.severity === 'critical' || f.severity === 'high')
    )
    .sort((a, b) =>
      (SORDER[a.severity] ?? 9) - (SORDER[b.severity] ?? 9) ||
      (CONF_ORDER[a.confidence] ?? 9) - (CONF_ORDER[b.confidence] ?? 9)
    )
    .slice(0, 5);

  return {
    domain: ctx.domain,
    report: tests === FREE_TESTS ? 'free' : 'paid',
    assessmentId,
    assetsDiscovered: assetsProvided.length,
    assetsProvided: assetsProvided.length,
    assetsTested: assetsProvided.length,
    endpointsTested: httpRequestCount,
    testsRun: effectiveTests.length,
    httpRequestCount,
    durationMs,
    score,
    grade,
    findings: sortedFindings,
    topFindings,
    attackSurface: surface,
    auditLog,
  };
}
