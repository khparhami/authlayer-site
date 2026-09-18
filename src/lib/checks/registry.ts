import type { SecurityTest, ScanContext, ScanResult, Finding, FindingClassification } from './types.js';
import { DNS_TESTS } from './dns.js';
import { TRANSPORT_TESTS } from './transport.js';
import { COOKIE_TESTS } from './cookies.js';
import { HEADER_TESTS } from './headers.js';
import { EMAIL_TESTS } from './email.js';
import { OAUTH_TESTS } from './oauth.js';
import { EXPOSURE_TESTS } from './exposure.js';

// ─── Finding classification ──────────────────────────────────────────────────

function classifyFinding(f: Finding): FindingClassification {
  if (f.status === 'pass')  return 'passed';
  if (f.status === 'error') return 'not_checked';
  if (f.status === 'info')  return 'security_observation';

  const highSev  = f.severity === 'critical' || f.severity === 'high';
  const highConf = f.confidence === 'confirmed' || f.confidence === 'high';
  const lowSev   = f.severity === 'low' || f.severity === 'informational';

  if (f.status === 'fail' && highSev && highConf) return 'confirmed_vulnerability';
  if (f.status === 'fail' && highSev)             return 'potential_vulnerability';
  if (f.status === 'fail' && f.severity === 'medium' && highConf) return 'potential_vulnerability';
  if (f.status === 'fail' && f.severity === 'medium') return 'security_observation';
  if (f.status === 'fail' && lowSev)              return 'hardening_recommendation';

  // warn cases
  if (f.status === 'warn' && highSev)             return 'potential_vulnerability';
  if (f.status === 'warn' && f.severity === 'medium') return 'security_observation';
  return 'hardening_recommendation';
}

// ─── Test tiers ──────────────────────────────────────────────────────────────

// Free tier: surface-level passive checks
export const FREE_TESTS: SecurityTest[] = [
  ...DNS_TESTS,
  ...TRANSPORT_TESTS,
  ...EMAIL_TESTS.filter(t => ['EMAIL-001', 'EMAIL-003', 'EMAIL-004'].includes(t.test_id)),
  ...EXPOSURE_TESTS.filter(t => ['INFO-001a', 'INFO-001b', 'AUTH-001b'].includes(t.test_id)),
  ...OAUTH_TESTS.filter(t => ['AUTH-008', 'EXT-004a'].includes(t.test_id)),
  HEADER_TESTS.find(t => t.test_id === 'WEB-004')!,
  HEADER_TESTS.find(t => t.test_id === 'API-008')!,
];

// Paid tier: full check suite
export const PAID_TESTS: SecurityTest[] = [
  ...DNS_TESTS,
  ...TRANSPORT_TESTS,
  ...COOKIE_TESTS,
  ...HEADER_TESTS,
  ...EMAIL_TESTS,
  ...OAUTH_TESTS,
  ...EXPOSURE_TESTS,
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

// ─── Scan runner ─────────────────────────────────────────────────────────────

export async function runScan(
  ctx: ScanContext,
  tests: SecurityTest[],
): Promise<ScanResult> {
  const settled = await Promise.allSettled(tests.map(t => t.run(ctx)));

  const findings: Finding[] = settled.map((r, i) => {
    const t = tests[i];
    const raw: Finding = r.status === 'fulfilled'
      ? r.value
      : {
          test_id: t.test_id,
          name: t.name,
          category: t.category,
          status: 'error',
          severity: 'informational',
          confidence: 'informational',
          finding: 'Check threw an unexpected error',
          errorReason: 'An internal error prevented this check from running.',
        };
    return { ...raw, classification: classifyFinding(raw) };
  });

  const score = calculateScore(findings);
  const grade = calculateGrade(score);

  const SORDER: Record<string, number>    = { critical: 0, high: 1, medium: 2, low: 3, informational: 4 };
  const CONF_ORDER: Record<string, number> = { confirmed: 0, high: 1, medium: 2, low: 3, informational: 4 };
  const CORDER: Record<string, number> = {
    confirmed_vulnerability: 0, potential_vulnerability: 1,
    security_observation: 2, hardening_recommendation: 3,
    passed: 4, not_checked: 5,
  };

  const topFindings = findings
    .filter(f => f.classification === 'confirmed_vulnerability' || f.classification === 'potential_vulnerability')
    .sort((a, b) =>
      (CORDER[a.classification ?? 'not_checked'] ?? 9) - (CORDER[b.classification ?? 'not_checked'] ?? 9) ||
      (SORDER[a.severity] ?? 9) - (SORDER[b.severity] ?? 9) ||
      (CONF_ORDER[a.confidence] ?? 9) - (CONF_ORDER[b.confidence] ?? 9)
    )
    .slice(0, 5);

  return {
    domain: ctx.domain,
    report: tests === FREE_TESTS ? 'free' : 'paid',
    assetsDiscovered: 1 + (ctx.additionalAssets?.length ?? 0),
    endpointsTested: Math.max(tests.length, 14),
    testsRun: tests.length,
    score,
    grade,
    findings,
    topFindings,
  };
}
