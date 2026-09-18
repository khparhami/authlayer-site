import type { Finding, ScanContext, SecurityTest } from '../checks/types.js';
import type { AuditEntry } from './types.js';

export interface PipelineOptions {
  concurrency?: number;
  retries?: number;
  retryDelayMs?: number;
  assessmentId?: string;
}

export interface PipelineResult {
  findings: Finding[];
  auditLog: AuditEntry[];
  durationMs: number;
  httpRequestCount: number;
}

export async function boundedConcurrency<T>(
  tasks: Array<() => Promise<T>>,
  limit: number,
): Promise<PromiseSettledResult<T>[]> {
  const results: PromiseSettledResult<T>[] = new Array(tasks.length);
  let next = 0;
  async function worker() {
    while (next < tasks.length) {
      const i = next++;
      try {
        results[i] = { status: 'fulfilled', value: await tasks[i]() };
      } catch (reason) {
        results[i] = { status: 'rejected', reason };
      }
    }
  }
  await Promise.all(Array.from({ length: Math.min(limit, tasks.length) }, worker));
  return results;
}

export async function withRetry<T>(fn: () => Promise<T>, attempts: number, delayMs: number): Promise<T> {
  let lastErr: unknown;
  for (let i = 1; i <= attempts; i++) {
    try { return await fn(); } catch (e) {
      lastErr = e;
      if (i < attempts) await new Promise(r => setTimeout(r, delayMs * i));
    }
  }
  throw lastErr;
}

export async function runPipeline(
  ctx: ScanContext,
  tests: SecurityTest[],
  opts: PipelineOptions = {},
): Promise<PipelineResult> {
  const { concurrency = 6, retries = 2, retryDelayMs = 350, assessmentId = `asmt-${Date.now()}` } = opts;
  const start = Date.now();
  const auditLog: AuditEntry[] = [];
  let httpRequestCount = 0;

  const tasks = tests.map(t => async (): Promise<Finding> => {
    const ts = new Date().toISOString();
    let result: Finding;
    try {
      result = await withRetry(() => t.run(ctx), retries, retryDelayMs);
      httpRequestCount++;
    } catch {
      result = {
        test_id: t.test_id,
        name: t.name,
        category: t.category,
        status: 'error',
        severity: 'informational',
        confidence: 'informational',
        finding: 'Check threw an unexpected error',
        errorReason: 'An internal error prevented this check from running.',
      };
    }
    auditLog.push({
      assessmentId,
      testId: t.test_id,
      assetId: ctx.domain,
      timestamp: ts,
      requestOutcome: result.status === 'error' ? 'error'
        : result.status === 'inconclusive' ? 'timeout' : 'success',
      resultStatus: result.status,
      reasonCode: result.reasonCode,
      classification: result.classification,
      severity: result.severity,
      confidence: result.confidence,
    });
    return result;
  });

  const settled = await boundedConcurrency(tasks, concurrency);
  const findings: Finding[] = settled.map((r, i) =>
    r.status === 'fulfilled' ? r.value : {
      test_id: tests[i].test_id,
      name: tests[i].name,
      category: tests[i].category,
      status: 'error' as const,
      severity: 'informational' as const,
      confidence: 'informational' as const,
      finding: 'Check threw an unexpected error',
      errorReason: 'An internal error prevented this check from running.',
    }
  );

  return { findings, auditLog, durationMs: Date.now() - start, httpRequestCount };
}
