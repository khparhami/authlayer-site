import type { Finding } from '../checks/types.js';

function correlateSessionCookieFindings(findings: Finding[]): Finding[] {
  const COOKIE_IDS = new Set(['AUTH-003a', 'AUTH-003b', 'AUTH-003c']);
  const active = findings.filter(f =>
    COOKIE_IDS.has(f.test_id) && f.status !== 'pass' && f.status !== 'not_applicable'
  );
  if (active.length <= 1) return findings;
  return findings.map(f => {
    if (!COOKIE_IDS.has(f.test_id) || f.status === 'pass' || f.status === 'not_applicable') return f;
    const others = active.filter(c => c.test_id !== f.test_id).map(c => c.name).join(', ');
    return others ? {
      ...f,
      detail: f.detail ? `${f.detail}\n\nRelated: ${others}` : `Related cookie findings: ${others}`,
    } : f;
  });
}

export function correlateFindings(findings: Finding[]): Finding[] {
  return correlateSessionCookieFindings([...findings]);
}
