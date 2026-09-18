import { describe, it, expect } from 'vitest';
import { classifyFinding } from '../lib/checks/registry.js';
import type { Finding } from '../lib/checks/types.js';

function f(overrides: Partial<Finding>): Finding {
  return {
    test_id: 'TEST-001',
    name: 'Test Finding',
    category: 'dns',
    status: 'pass',
    severity: 'low',
    confidence: 'medium',
    finding: 'test',
    ...overrides,
  };
}

describe('classifyFinding', () => {
  it('passes → passed', () => {
    expect(classifyFinding(f({ status: 'pass' }))).toBe('passed');
  });

  it('error → not_checked', () => {
    expect(classifyFinding(f({ status: 'error' }))).toBe('not_checked');
  });

  it('inconclusive → inconclusive', () => {
    expect(classifyFinding(f({ status: 'inconclusive' }))).toBe('inconclusive');
  });

  it('not_run → not_checked', () => {
    expect(classifyFinding(f({ status: 'not_run' }))).toBe('not_checked');
  });

  it('not_applicable → not_checked', () => {
    expect(classifyFinding(f({ status: 'not_applicable' }))).toBe('not_checked');
  });

  it('info → security_observation', () => {
    expect(classifyFinding(f({ status: 'info', severity: 'informational' }))).toBe('security_observation');
  });

  it('fail + high + confirmed → confirmed_vulnerability', () => {
    expect(classifyFinding(f({ status: 'fail', severity: 'high', confidence: 'confirmed' }))).toBe('confirmed_vulnerability');
  });

  it('fail + critical + high confidence → confirmed_vulnerability', () => {
    expect(classifyFinding(f({ status: 'fail', severity: 'critical', confidence: 'high' }))).toBe('confirmed_vulnerability');
  });

  it('fail + high + medium confidence → potential_vulnerability', () => {
    expect(classifyFinding(f({ status: 'fail', severity: 'high', confidence: 'medium' }))).toBe('potential_vulnerability');
  });

  it('fail + medium + confirmed → potential_vulnerability', () => {
    expect(classifyFinding(f({ status: 'fail', severity: 'medium', confidence: 'confirmed' }))).toBe('potential_vulnerability');
  });

  it('fail + medium + low confidence → security_observation', () => {
    expect(classifyFinding(f({ status: 'fail', severity: 'medium', confidence: 'low' }))).toBe('security_observation');
  });

  it('fail + low → hardening_recommendation', () => {
    expect(classifyFinding(f({ status: 'fail', severity: 'low', confidence: 'confirmed' }))).toBe('hardening_recommendation');
  });

  it('warn + high → potential_vulnerability', () => {
    expect(classifyFinding(f({ status: 'warn', severity: 'high', confidence: 'medium' }))).toBe('potential_vulnerability');
  });

  it('warn + medium → security_observation', () => {
    expect(classifyFinding(f({ status: 'warn', severity: 'medium', confidence: 'medium' }))).toBe('security_observation');
  });

  it('warn + low → hardening_recommendation', () => {
    expect(classifyFinding(f({ status: 'warn', severity: 'low', confidence: 'medium' }))).toBe('hardening_recommendation');
  });

  it('SPF soft-fail: fail + low → hardening_recommendation (not potential)', () => {
    const spf = f({ status: 'fail', severity: 'low', confidence: 'medium', test_id: 'EMAIL-001' });
    expect(classifyFinding(spf)).toBe('hardening_recommendation');
  });

  it('DMARC quarantine: fail + low → hardening_recommendation', () => {
    const dmarc = f({ status: 'fail', severity: 'low', confidence: 'low', test_id: 'EMAIL-003' });
    expect(classifyFinding(dmarc)).toBe('hardening_recommendation');
  });
});
