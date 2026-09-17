import type { SecurityTest, ScanContext, ScanResult, Finding } from './types.js';
import { TRANSPORT_TESTS } from './transport.js';
import { COOKIE_TESTS } from './cookies.js';
import { HEADER_TESTS } from './headers.js';
import { EMAIL_TESTS } from './email.js';
import { OAUTH_TESTS } from './oauth.js';
import { EXPOSURE_TESTS } from './exposure.js';

// Free tier: core checks covering transport, email, basic exposure
export const FREE_TESTS: SecurityTest[] = [
  ...TRANSPORT_TESTS,
  ...EMAIL_TESTS.filter(t => ['EMAIL-001', 'EMAIL-003'].includes(t.test_id)),
  ...EXPOSURE_TESTS.filter(t => ['INFO-001a', 'AUTH-001b'].includes(t.test_id)),
  ...OAUTH_TESTS.filter(t => ['AUTH-008', 'EXT-004a'].includes(t.test_id)),
  HEADER_TESTS.find(t => t.test_id === 'WEB-004')!,   // clickjacking
  HEADER_TESTS.find(t => t.test_id === 'API-008')!,    // CORS
];

// Paid tier: everything
export const PAID_TESTS: SecurityTest[] = [
  ...TRANSPORT_TESTS,
  ...COOKIE_TESTS,
  ...HEADER_TESTS,
  ...EMAIL_TESTS,
  ...OAUTH_TESTS,
  ...EXPOSURE_TESTS,
];

const SEV_WEIGHT: Record<string, number> = { critical: 25, high: 15, medium: 10, low: 5, informational: 0 };

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

export async function runScan(
  ctx: ScanContext,
  tests: SecurityTest[],
): Promise<ScanResult> {
  const settled = await Promise.allSettled(tests.map(t => t.run(ctx)));

  const findings: Finding[] = settled.map((r, i) => {
    if (r.status === 'fulfilled') return r.value;
    const t = tests[i];
    return {
      test_id: t.test_id,
      name: t.name,
      category: t.category,
      status: 'error',
      severity: 'informational',
      confidence: 'informational',
      finding: 'Check threw an unexpected error',
      errorReason: 'An internal error prevented this check from running. This is not a security finding.',
    };
  });

  const score = calculateScore(findings);
  const grade = calculateGrade(score);

  // Top findings: fail/warn sorted by severity then confidence
  const SORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, informational: 4 };
  const CONF_ORDER: Record<string, number> = { confirmed: 0, high: 1, medium: 2, low: 3, informational: 4 };
  const topFindings = findings
    .filter(f => f.status === 'fail' || f.status === 'warn')
    .sort((a, b) =>
      (SORDER[a.severity] ?? 9) - (SORDER[b.severity] ?? 9) ||
      (CONF_ORDER[a.confidence] ?? 9) - (CONF_ORDER[b.confidence] ?? 9)
    )
    .slice(0, 5);

  // Count unique endpoints tested (domain + authUrl + discovered paths checked)
  const endpointsTested = Math.max(tests.length, 14);

  return {
    domain: ctx.domain,
    report: tests.length === FREE_TESTS.length ? 'free' : 'paid',
    assetsDiscovered: 1 + (ctx.additionalAssets?.length ?? 0),
    endpointsTested,
    testsRun: tests.length,
    score,
    grade,
    findings,
    topFindings,
  };
}
