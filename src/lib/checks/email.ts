import type { SecurityTest, Finding, ScanContext } from './types.js';

interface DnsAnswer { name: string; type: number; TTL: number; data: string; }
interface DnsResponse { Status: number; Answer?: DnsAnswer[]; }

async function dnsQuery(name: string, type: string): Promise<DnsResponse> {
  const res = await fetch(
    `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${type}`,
    { headers: { Accept: 'application/dns-json' }, signal: AbortSignal.timeout(6000) },
  );
  if (!res.ok) return { Status: 2 };
  return res.json() as Promise<DnsResponse>;
}

const spfExists: SecurityTest = {
  test_id: 'EMAIL-001',
  name: 'SPF Record',
  version: '1.0.0',
  category: 'email',
  severity: 'medium',
  confidence: 'confirmed',
  owasp_mapping: 'A05:2021',
  cwe: 'CWE-349',
  safe_for_production: true,
  requires_active_testing: false,
  async run({ domain }: ScanContext): Promise<Finding> {
    const base = {
      test_id: this.test_id, name: this.name, category: this.category,
      severity: this.severity, confidence: this.confidence,
      owasp_mapping: this.owasp_mapping, cwe: this.cwe,
      detail: 'Sender Policy Framework (SPF) declares which mail servers are authorised to send email for this domain. Without it, anyone can spoof your domain in phishing emails targeting your users.',
      remediation: 'Add a TXT record: `v=spf1 include:_spf.yourmailprovider.com -all`. Use `-all` (hard fail) rather than `~all` (soft fail) for production domains.',
      references: [{ label: 'RFC 7208 — SPF', url: 'https://tools.ietf.org/html/rfc7208' }],
    };
    try {
      const data = await dnsQuery(domain, 'TXT');
      const spf = data.Answer?.find(r => r.data.replace(/"/g, '').startsWith('v=spf1'));
      if (!spf) return { ...base, status: 'fail', finding: 'No SPF record found for this domain' };
      return { ...base, status: 'pass', finding: `SPF record found: ${spf.data.replace(/"/g, '').slice(0, 80)}` };
    } catch {
      return { ...base, status: 'error', finding: 'DNS query failed — could not check SPF record', errorReason: 'DNS-over-HTTPS query timed out or returned an error.' };
    }
  },
};

const spfStrength: SecurityTest = {
  test_id: 'EMAIL-001b',
  name: 'SPF Enforcement Level',
  version: '1.0.0',
  category: 'email',
  severity: 'high',
  confidence: 'confirmed',
  owasp_mapping: 'A05:2021',
  cwe: 'CWE-349',
  safe_for_production: true,
  requires_active_testing: false,
  async run({ domain }: ScanContext): Promise<Finding> {
    const base = {
      test_id: this.test_id, name: this.name, category: this.category,
      severity: this.severity, confidence: this.confidence,
      owasp_mapping: this.owasp_mapping, cwe: this.cwe,
      detail: '~all (soft fail) marks unauthorised senders as suspicious but still delivers the email. +all permits any server to send mail. Only -all (hard fail) instructs receiving servers to reject unauthorised mail.',
      remediation: 'Change the SPF record to end with `-all` after verifying all legitimate sending sources are included (e.g. Google Workspace, SendGrid, Mailchimp). Test with mail-tester.com before switching.',
      references: [{ label: 'RFC 7208 — SPF Qualifiers', url: 'https://tools.ietf.org/html/rfc7208#section-4.6.2' }],
    };
    try {
      const data = await dnsQuery(domain, 'TXT');
      const spf = data.Answer?.find(r => r.data.replace(/"/g, '').startsWith('v=spf1'));
      if (!spf) return { ...base, status: 'fail', finding: 'No SPF record found' };
      const text = spf.data.replace(/"/g, '');
      if (text.includes('-all')) return { ...base, status: 'pass', finding: 'SPF ends with -all (hard fail) — strongest enforcement' };
      if (text.includes('~all')) return { ...base, status: 'warn', finding: 'SPF ends with ~all (soft fail) — consider upgrading to -all', confidence: 'high' };
      if (text.includes('+all')) return { ...base, status: 'fail', finding: 'SPF ends with +all — any server is permitted to send on behalf of this domain' };
      return { ...base, status: 'warn', finding: 'SPF record has no explicit all qualifier', confidence: 'medium' };
    } catch {
      return { ...base, status: 'error', finding: 'Could not evaluate SPF strength', errorReason: 'DNS-over-HTTPS query timed out or returned an error.' };
    }
  },
};

const dmarcExists: SecurityTest = {
  test_id: 'EMAIL-003',
  name: 'DMARC Record',
  version: '1.0.0',
  category: 'email',
  severity: 'medium',
  confidence: 'confirmed',
  owasp_mapping: 'A05:2021',
  cwe: 'CWE-349',
  safe_for_production: true,
  requires_active_testing: false,
  async run({ domain }: ScanContext): Promise<Finding> {
    const base = {
      test_id: this.test_id, name: this.name, category: this.category,
      severity: this.severity, confidence: this.confidence,
      owasp_mapping: this.owasp_mapping, cwe: this.cwe,
      detail: 'DMARC tells receiving mail servers what to do when SPF or DKIM fails. Without it, spoofed emails from your domain reach inboxes unchallenged.',
      remediation: `Add a TXT record at \`_dmarc.yourdomain.com\`: \`v=DMARC1; p=quarantine; rua=mailto:dmarc@yourdomain.com\`. Start with \`p=none\` for monitoring, then move to \`quarantine\` or \`reject\`.`,
      references: [{ label: 'RFC 7489 — DMARC', url: 'https://tools.ietf.org/html/rfc7489' }],
    };
    try {
      const data = await dnsQuery(`_dmarc.${domain}`, 'TXT');
      const dmarc = data.Answer?.find(r => r.data.replace(/"/g, '').startsWith('v=DMARC1'));
      if (!dmarc) return { ...base, status: 'fail', finding: `No DMARC record found at _dmarc.${domain}` };
      return { ...base, status: 'pass', finding: `DMARC record found: ${dmarc.data.replace(/"/g, '').slice(0, 80)}` };
    } catch {
      return { ...base, status: 'error', finding: 'DNS query failed — could not check DMARC record', errorReason: 'DNS-over-HTTPS query timed out or returned an error.' };
    }
  },
};

const dmarcPolicy: SecurityTest = {
  test_id: 'EMAIL-003b',
  name: 'DMARC Policy Level',
  version: '1.0.0',
  category: 'email',
  severity: 'high',
  confidence: 'confirmed',
  owasp_mapping: 'A05:2021',
  cwe: 'CWE-349',
  safe_for_production: true,
  requires_active_testing: false,
  async run({ domain }: ScanContext): Promise<Finding> {
    const base = {
      test_id: this.test_id, name: this.name, category: this.category,
      severity: this.severity, confidence: this.confidence,
      owasp_mapping: this.owasp_mapping, cwe: this.cwe,
      detail: 'p=none only monitors DMARC failures — it does not quarantine or reject spoofed emails. p=quarantine sends failing messages to spam. p=reject is the gold standard: spoofed emails are dropped at the receiving server.',
      remediation: 'Progress from p=none (monitoring) → p=quarantine (partial enforcement) → p=reject (full enforcement). Review rua/ruf aggregate reports before each step.',
      references: [
        { label: 'RFC 7489 — DMARC', url: 'https://tools.ietf.org/html/rfc7489' },
        { label: 'DMARC.org Guide', url: 'https://dmarc.org/overview/' },
      ],
    };
    try {
      const data = await dnsQuery(`_dmarc.${domain}`, 'TXT');
      const record = data.Answer?.find(r => r.data.replace(/"/g, '').startsWith('v=DMARC1'));
      if (!record) return { ...base, status: 'fail', finding: 'No DMARC record — policy check not possible' };
      const text = record.data.replace(/"/g, '');
      const pMatch = text.match(/\bp=([a-z]+)/i);
      const policy = pMatch?.[1]?.toLowerCase() ?? 'none';
      if (policy === 'reject') return { ...base, status: 'pass', finding: 'DMARC policy is p=reject — maximum enforcement' };
      if (policy === 'quarantine') return { ...base, status: 'warn', finding: 'DMARC policy is p=quarantine — consider upgrading to p=reject', confidence: 'high' };
      return { ...base, status: 'fail', finding: 'DMARC policy is p=none — monitoring only, spoofed emails are not blocked' };
    } catch {
      return { ...base, status: 'error', finding: 'Could not evaluate DMARC policy', errorReason: 'DNS-over-HTTPS query timed out or returned an error.' };
    }
  },
};

const dkimRecord: SecurityTest = {
  test_id: 'EMAIL-002',
  name: 'DKIM Record',
  version: '1.0.0',
  category: 'email',
  severity: 'medium',
  confidence: 'medium',
  owasp_mapping: 'A05:2021',
  cwe: 'CWE-349',
  safe_for_production: true,
  requires_active_testing: false,
  async run({ domain }: ScanContext): Promise<Finding> {
    const base = {
      test_id: this.test_id, name: this.name, category: this.category,
      severity: this.severity, confidence: this.confidence,
      owasp_mapping: this.owasp_mapping, cwe: this.cwe,
      detail: 'DKIM adds a cryptographic signature to outgoing email that receiving servers can verify. Combined with DMARC, it prevents email spoofing. Without DKIM, DMARC alignment via DKIM is impossible.',
      remediation: 'Configure DKIM with your email provider and publish the public key as a TXT record at `selector._domainkey.yourdomain.com`. Common selectors: default, google, mail, dkim1.',
      references: [{ label: 'RFC 6376 — DKIM', url: 'https://tools.ietf.org/html/rfc6376' }],
    };
    const selectors = ['default', 'google', 'mail', 'dkim1', 's1', 's2'];
    try {
      const queries = await Promise.allSettled(
        selectors.map(s => dnsQuery(`${s}._domainkey.${domain}`, 'TXT'))
      );
      const found = selectors.filter((_, i) => {
        const r = queries[i];
        return r.status === 'fulfilled' && (r.value.Answer?.length ?? 0) > 0;
      });
      if (found.length > 0) return { ...base, status: 'pass', finding: `DKIM record found for selector(s): ${found.join(', ')}` };
      return { ...base, status: 'warn', finding: `No DKIM record found for common selectors (${selectors.join(', ')}) — custom selector may be in use`, confidence: 'low' };
    } catch {
      return { ...base, status: 'error', finding: 'Could not query DKIM records', errorReason: 'DNS-over-HTTPS query timed out or returned an error.' };
    }
  },
};

const mxRecords: SecurityTest = {
  test_id: 'EMAIL-004',
  name: 'MX Records',
  version: '1.0.0',
  category: 'email',
  severity: 'informational',
  confidence: 'confirmed',
  owasp_mapping: 'A05:2021',
  safe_for_production: true,
  requires_active_testing: false,
  async run({ domain }: ScanContext): Promise<Finding> {
    const base = {
      test_id: this.test_id, name: this.name, category: this.category,
      severity: this.severity, confidence: this.confidence,
      owasp_mapping: this.owasp_mapping,
      detail: 'MX records define your mail infrastructure. Understanding your mail providers helps identify phishing risk surface and verify that SPF/DKIM/DMARC coverage aligns with your actual sending infrastructure.',
      remediation: 'Ensure MX records only point to authorised mail infrastructure. Remove stale MX records for decommissioned mail servers. Verify SPF includes all mail providers listed here.',
      references: [
        { label: 'RFC 5321 — SMTP MX', url: 'https://tools.ietf.org/html/rfc5321#section-5.1' },
      ],
    };
    try {
      const data = await dnsQuery(domain, 'MX');
      const records = data.Answer ?? [];
      if (records.length === 0) {
        return { ...base, status: 'info', finding: `No MX records found for ${domain} — domain may not accept email` };
      }
      const providers = records.map(r => r.data).join(', ');
      return {
        ...base, status: 'pass',
        finding: `${records.length} MX record${records.length > 1 ? 's' : ''} found: ${providers}`,
        evidence: providers,
      };
    } catch {
      return { ...base, status: 'error', finding: 'Could not query MX records', errorReason: 'DNS-over-HTTPS query timed out.' };
    }
  },
};

export const EMAIL_TESTS: SecurityTest[] = [spfExists, spfStrength, dmarcExists, dmarcPolicy, dkimRecord, mxRecords];
