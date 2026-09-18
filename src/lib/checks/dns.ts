import type { SecurityTest, Finding, ScanContext } from './types.js';

interface DnsAnswer { data: string; name: string; TTL: number; }
interface DnsResponse { Status: number; Answer?: DnsAnswer[]; }

async function dnsQuery(name: string, type: string): Promise<DnsResponse> {
  try {
    const res = await fetch(
      `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${type}`,
      { headers: { Accept: 'application/dns-json' }, signal: AbortSignal.timeout(5000) },
    );
    if (!res.ok) return { Status: 2 };
    return res.json() as Promise<DnsResponse>;
  } catch {
    return { Status: 2 };
  }
}

const dnsConfiguration: SecurityTest = {
  test_id: 'EXT-001',
  name: 'DNS Configuration',
  version: '1.0.0',
  category: 'dns',
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
      detail: 'DNS records define your public attack surface. Missing CAA records allow any certificate authority to issue TLS certificates for your domain. Unexpected or stale records can expose orphaned infrastructure.',
      remediation: 'Add CAA records to restrict certificate issuance to known CAs: `example.com. CAA 0 issue "letsencrypt.org"`. Audit all DNS records quarterly. Remove stale or orphaned entries.',
      references: [
        { label: 'RFC 8659 — DNS CAA Records', url: 'https://tools.ietf.org/html/rfc8659' },
        { label: 'OWASP — A05 Security Misconfiguration', url: 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/' },
      ],
    };

    try {
      const [aRes, aaaaRes, mxRes, nsRes, txtRes, caaRes] = await Promise.allSettled([
        dnsQuery(domain, 'A'),
        dnsQuery(domain, 'AAAA'),
        dnsQuery(domain, 'MX'),
        dnsQuery(domain, 'NS'),
        dnsQuery(domain, 'TXT'),
        dnsQuery(domain, 'CAA'),
      ]);

      const answers = (r: PromiseSettledResult<DnsResponse>) =>
        r.status === 'fulfilled' ? (r.value.Answer ?? []) : [];

      const aRecs    = answers(aRes);
      const aaaaRecs = answers(aaaaRes);
      const mxRecs   = answers(mxRes);
      const nsRecs   = answers(nsRes);
      const txtRecs  = answers(txtRes);
      const caaRecs  = answers(caaRes);

      if (aRecs.length === 0 && aaaaRecs.length === 0) {
        return {
          ...base, status: 'warn', severity: 'medium',
          finding: `No A or AAAA records found for ${domain} — domain may be unreachable or DNS misconfigured`,
        };
      }

      const surface: string[] = [];
      if (aRecs.length)    surface.push(`${aRecs.length} A`);
      if (aaaaRecs.length) surface.push(`${aaaaRecs.length} AAAA`);
      if (mxRecs.length)   surface.push(`${mxRecs.length} MX`);
      if (nsRecs.length)   surface.push(`${nsRecs.length} NS`);
      if (txtRecs.length)  surface.push(`${txtRecs.length} TXT`);
      if (caaRecs.length)  surface.push(`${caaRecs.length} CAA`);

      const evidence = [
        aRecs.length    ? `A: ${aRecs.map(r => r.data).join(', ')}` : null,
        aaaaRecs.length ? `AAAA: ${aaaaRecs.map(r => r.data).join(', ')}` : null,
        nsRecs.length   ? `NS: ${nsRecs.map(r => r.data).join(', ')}` : null,
        mxRecs.length   ? `MX: ${mxRecs.map(r => r.data).join(', ')}` : null,
        caaRecs.length  ? `CAA: ${caaRecs.map(r => r.data).join(', ')}` : null,
      ].filter(Boolean).join('\n');

      if (caaRecs.length === 0) {
        return {
          ...base,
          status: 'warn',
          severity: 'low',
          finding: `DNS surface mapped — ${surface.join(', ')} records found. No restrictive CAA policy was detected for this domain. CAA records can be used to specify which certificate authorities are authorised to issue certificates for the domain.`,
          evidence,
          reasonCode: 'NO_CAA_RECORDS',
        };
      }

      const caaIssuers = caaRecs.map(r => r.data).join(', ');
      return {
        ...base,
        status: 'pass',
        finding: `DNS surface mapped — ${surface.join(', ')} records. CAA records present, restricting issuance to: ${caaIssuers}`,
        evidence,
      };
    } catch {
      return {
        ...base, status: 'inconclusive',
        finding: 'Could not query DNS records',
        errorReason: 'DNS-over-HTTPS query failed or timed out.',
        reasonCode: 'DNS_TIMEOUT',
      };
    }
  },
};

export const DNS_TESTS: SecurityTest[] = [dnsConfiguration];
