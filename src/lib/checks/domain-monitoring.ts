// Domain monitoring: lookalike typosquat detection + CT subdomain discovery

export interface LookalikeDomain {
  domain: string;
  riskLevel: 'highest' | 'high' | 'medium' | 'low' | 'lowest';
  riskScore: number;
  resolves: boolean;
  attackType: 'typosquat' | 'homoglyph' | 'phishing_keyword' | 'tld_variant' | 'ct_discovered';
  reasons: string[];
}

export interface DomainMonitoringResult {
  scanned: number;
  resolving: number;
  ctSubdomains: string[];
  lookalikeDomains: LookalikeDomain[];
}

// ─── Variant generation ──────────────────────────────────────────────────────

interface Variant {
  domain: string;
  attackType: LookalikeDomain['attackType'];
  reasons: string[];
  phishingPriority: number; // higher = more suspicious even unresolved
}

const PHISHING_PREFIXES = ['login', 'secure', 'auth', 'account', 'verify', 'update', 'signin', 'support', 'reset', 'confirm'];
const PHISHING_SUFFIXES = ['login', 'secure', 'auth', 'verify', 'signin', 'support', 'portal', 'online'];
const ALT_TLDS = ['net', 'org', 'co', 'io', 'app', 'online', 'site', 'info', 'biz'];
const HOMOGLYPH_MAP: [string, string, string][] = [
  // [original, replacement, description]
  ['rn', 'm',  '"rn" → "m" (visual clone)'],
  ['vv', 'w',  '"vv" → "w" (visual clone)'],
  ['a',  '4',  '"a" → "4"'],
  ['e',  '3',  '"e" → "3"'],
  ['i',  '1',  '"i" → "1"'],
  ['l',  '1',  '"l" → "1"'],
  ['o',  '0',  '"o" → "0"'],
  ['s',  '5',  '"s" → "5"'],
  ['g',  '9',  '"g" → "9"'],
];

function generateVariants(targetDomain: string): Variant[] {
  const parts = targetDomain.split('.');
  if (parts.length < 2) return [];
  const tldFull = parts.slice(1).join('.');
  const sld = parts[0];

  const variants: Variant[] = [];
  const seen = new Set<string>([targetDomain]);

  function add(d: string, attackType: Variant['attackType'], reason: string, priority = 0) {
    if (!seen.has(d) && d.length > 3 && /^[a-z0-9]([a-z0-9\-.]{0,61}[a-z0-9])?$/.test(d)) {
      seen.add(d);
      variants.push({ domain: d, attackType, reasons: [reason], phishingPriority: priority });
    }
  }

  // 1. Phishing keyword prefix / suffix (highest priority — active attack pattern)
  for (const p of PHISHING_PREFIXES) {
    add(`${p}-${sld}.${tldFull}`, 'phishing_keyword', `Phishing prefix "${p}-"`, 30);
    add(`${p}${sld}.${tldFull}`, 'phishing_keyword', `Phishing prefix "${p}"`, 25);
  }
  for (const s of PHISHING_SUFFIXES) {
    add(`${sld}-${s}.${tldFull}`, 'phishing_keyword', `Phishing suffix "-${s}"`, 28);
  }

  // 2. Homoglyphs / look-alike character substitutions
  for (const [orig, replacement, description] of HOMOGLYPH_MAP) {
    if (sld.includes(orig)) {
      add(`${sld.replace(orig, replacement)}.${tldFull}`, 'homoglyph', description, 20);
      // Also try replacing all occurrences
      add(`${sld.replaceAll(orig, replacement)}.${tldFull}`, 'homoglyph', `All ${description}`, 18);
    }
  }

  // 3. Character deletion (one char missing)
  for (let i = 0; i < sld.length; i++) {
    add(`${sld.slice(0, i)}${sld.slice(i + 1)}.${tldFull}`, 'typosquat', `Missing "${sld[i]}" at position ${i + 1}`, 15);
  }

  // 4. Adjacent character transposition
  for (let i = 0; i < sld.length - 1; i++) {
    const c = sld.split('');
    [c[i], c[i + 1]] = [c[i + 1], c[i]];
    add(`${c.join('')}.${tldFull}`, 'typosquat', `Swapped "${sld[i]}${sld[i+1]}" → "${sld[i+1]}${sld[i]}"`, 12);
  }

  // 5. Character doubling
  for (let i = 0; i < sld.length; i++) {
    add(`${sld.slice(0, i)}${sld[i]}${sld[i]}${sld.slice(i + 1)}.${tldFull}`, 'typosquat', `Doubled "${sld[i]}" at position ${i + 1}`, 10);
  }

  // 6. TLD variations
  const primaryTld = parts.slice(-1)[0];
  for (const altTld of ALT_TLDS) {
    if (altTld !== primaryTld) {
      add(`${sld}.${altTld}`, 'tld_variant', `Alternative TLD .${altTld}`, 8);
    }
  }

  // Sort: phishing keywords first, then by priority desc, limit to 60
  return variants
    .sort((a, b) => b.phishingPriority - a.phishingPriority)
    .slice(0, 60);
}

// ─── DNS resolution via Cloudflare DoH ──────────────────────────────────────

async function resolveDomain(domain: string): Promise<boolean> {
  try {
    const res = await fetch(
      `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=A`,
      {
        headers: { Accept: 'application/dns-json' },
        signal: AbortSignal.timeout(4000),
      }
    );
    if (!res.ok) return false;
    const data = (await res.json()) as { Status: number; Answer?: unknown[] };
    return data.Status === 0 && Array.isArray(data.Answer) && data.Answer.length > 0;
  } catch {
    return false;
  }
}

// ─── Certificate Transparency via crt.sh ────────────────────────────────────

async function queryCtLogs(domain: string): Promise<string[]> {
  try {
    const res = await fetch(
      `https://crt.sh/?q=%.${encodeURIComponent(domain)}&output=json`,
      { signal: AbortSignal.timeout(10000) }
    );
    if (!res.ok) return [];
    const certs = (await res.json()) as Array<{ name_value: string; logged_at?: string }>;
    const names = new Map<string, string>(); // name → logged_at
    for (const cert of certs) {
      if (!cert.name_value) continue;
      for (const entry of cert.name_value.split('\n')) {
        const clean = entry.trim().replace(/^\*\./, '').toLowerCase();
        if (clean && clean !== domain && clean.endsWith(`.${domain}`)) {
          // Keep most recent cert date per subdomain
          const existing = names.get(clean);
          if (!existing || (cert.logged_at && cert.logged_at > existing)) {
            names.set(clean, cert.logged_at ?? '');
          }
        }
      }
    }
    // Return sorted by cert date descending (most recently seen first)
    return [...names.entries()]
      .sort((a, b) => b[1].localeCompare(a[1]))
      .map(([n]) => n)
      .slice(0, 80);
  } catch {
    return [];
  }
}

// ─── Bounded concurrency DNS checker ────────────────────────────────────────

async function boundedDnsCheck(variants: Variant[], concurrency: number): Promise<boolean[]> {
  const results: boolean[] = new Array(variants.length).fill(false);
  let cursor = 0;

  async function worker() {
    while (cursor < variants.length) {
      const i = cursor++;
      results[i] = await resolveDomain(variants[i].domain);
    }
  }

  const pool = Array.from({ length: Math.min(concurrency, variants.length) }, worker);
  await Promise.all(pool);
  return results;
}

// ─── Risk scoring ────────────────────────────────────────────────────────────

function scoreVariant(v: Variant, resolves: boolean): { level: LookalikeDomain['riskLevel']; score: number } {
  let score = 0;
  if (resolves) score += 50;
  score += v.phishingPriority;

  const level: LookalikeDomain['riskLevel'] =
    score >= 75 ? 'highest' :
    score >= 60 ? 'high' :
    score >= 35 ? 'medium' :
    score >= 15 ? 'low' : 'lowest';

  return { level, score };
}

// ─── Main export ─────────────────────────────────────────────────────────────

export async function runDomainMonitoring(
  domain: string,
  _knownAssets?: string[],
): Promise<DomainMonitoringResult> {
  const variants = generateVariants(domain);

  // Run DNS checks and CT log query in parallel, with a 15s overall cap
  const [resolutions, ctSubdomains] = await Promise.all([
    boundedDnsCheck(variants, 8),
    queryCtLogs(domain).catch(() => [] as string[]),
  ]);

  const lookalikeDomains: LookalikeDomain[] = variants
    .map((v, i) => {
      const resolves = resolutions[i];
      const { level, score } = scoreVariant(v, resolves);
      return {
        domain: v.domain,
        riskLevel: level,
        riskScore: score,
        resolves,
        attackType: v.attackType,
        reasons: v.reasons,
      };
    })
    // Show: anything that resolves, or phishing-keyword variants (unresolved = potential threat)
    .filter(d => d.resolves || d.attackType === 'phishing_keyword')
    .sort((a, b) => b.riskScore - a.riskScore)
    .slice(0, 40);

  return {
    scanned: variants.length,
    resolving: resolutions.filter(Boolean).length,
    ctSubdomains,
    lookalikeDomains,
  };
}
