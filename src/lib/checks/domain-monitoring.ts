// Domain monitoring: lookalike typosquat detection + brand+random token detection + CT discovery

// ─── Public interfaces ─────────────────────────────────────────────────────────

export type AttackType =
  | 'typosquat'
  | 'homoglyph'
  | 'phishing_keyword'
  | 'tld_variant'
  | 'ct_discovered'
  | 'brand_random_token';

export interface DomainAge {
  registeredAt?: string;  // 'YYYY-MM-DD'
  ageDays?: number;
  bucket: '<24h' | '<7d' | '<30d' | '<90d' | '>90d' | 'unknown';
}

export interface Evidence {
  type: string;
  description: string;
  value?: string;
}

export interface LookalikeDomain {
  domain: string;
  riskLevel: 'highest' | 'high' | 'medium' | 'low' | 'lowest';
  riskScore: number;
  resolves: boolean;
  attackType: AttackType;
  confidence?: 'high' | 'medium' | 'low';
  domainAge?: DomainAge;
  evidence?: Evidence[];
  reasons: string[];
}

export interface DomainMonitoringResult {
  scanned: number;
  resolving: number;
  ctSubdomains: string[];
  lookalikeDomains: LookalikeDomain[];
  brandTokens: string[];
}

// ─── Internal types ─────────────────────────────────────────────────────────────

interface Variant {
  domain: string;
  attackType: AttackType;
  reasons: string[];
  phishingPriority: number;
}

interface TokenAnalysis {
  token: string;
  isRandomLike: boolean;
  confidence: number;  // 0–1
  entropy: number;
  reasons: string[];
}

interface BrandMatchResult {
  brand: string;
  position: 'prefix' | 'suffix' | 'embedded';
  remaining: string;
}

// ─── Constants ──────────────────────────────────────────────────────────────────

const PHISHING_PREFIXES = ['login', 'secure', 'auth', 'account', 'verify', 'update', 'signin', 'support', 'reset', 'confirm'];
const PHISHING_SUFFIXES = ['login', 'secure', 'auth', 'verify', 'signin', 'support', 'portal', 'online'];
const ALT_TLDS = ['net', 'org', 'co', 'io', 'app', 'online', 'site', 'info', 'biz'];

const HOMOGLYPH_MAP: [string, string, string][] = [
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

const RISKY_TLDS = new Set([
  'top', 'xyz', 'click', 'pw', 'tk', 'ml', 'ga', 'cf', 'gq',
  'work', 'loan', 'online', 'site', 'rest', 'surf', 'beauty',
  'cheap', 'party', 'racing', 'review', 'win', 'download', 'stream',
  'men', 'gdn', 'date', 'faith', 'bid', 'trade',
  'cc', 'cn', 'shop', 'vip', 'link', 'live', 'icu', 'fun',
]);

const PHISHING_KEYWORDS = new Set([
  'login', 'secure', 'auth', 'account', 'verify', 'update', 'signin',
  'support', 'reset', 'confirm', 'portal', 'my', 'web', 'app',
  'bank', 'pay', 'payment', 'transfer', 'service', 'help', 'customer',
  'official', 'real', 'genuine', 'legit', 'safe',
]);

const COMMON_WORDS = new Set([
  'login', 'secure', 'auth', 'bank', 'pay', 'mail', 'shop', 'store',
  'app', 'web', 'online', 'support', 'help', 'service', 'account',
  'money', 'cash', 'card', 'link', 'page', 'site', 'home', 'info',
  'about', 'contact', 'news', 'blog', 'data', 'code', 'work', 'live',
  'play', 'game', 'tech', 'cloud', 'hub', 'lab', 'labs',
]);

const RDAP_SERVERS: Record<string, string> = {
  com:    'https://rdap.verisign.com/com/v1/domain/',
  net:    'https://rdap.verisign.com/net/v1/domain/',
  cc:     'https://rdap.verisign.com/cc/v1/domain/',
  tv:     'https://rdap.verisign.com/tv/v1/domain/',
  org:    'https://rdap.publicinterestregistry.org/rdap/domain/',
  io:     'https://rdap.nic.io/domain/',
  app:    'https://rdap.nic.google/domain/',
  dev:    'https://rdap.nic.google/domain/',
  xyz:    'https://rdap.nic.xyz/domain/',
  top:    'https://rdap.nic.top/domain/',
  online: 'https://rdap.centralnic.com/domain/',
  site:   'https://rdap.centralnic.com/domain/',
  shop:   'https://rdap.centralnic.com/domain/',
  biz:    'https://rdap.centralnic.com/domain/',
  info:   'https://rdap.afilias.info/rdap/domain/',
  co:     'https://rdap.nic.co/domain/',
};

// ─── Brand extraction ────────────────────────────────────────────────────────────

export function extractBrandTokens(targetDomain: string): string[] {
  const sld = targetDomain.split('.')[0].toLowerCase().replace(/[^a-z0-9-]/g, '');
  const tokens = new Set<string>([sld]);

  if (sld.includes('-')) {
    tokens.add(sld.replace(/-/g, ''));
    for (const part of sld.split('-')) {
      if (part.length >= 3) tokens.add(part);
    }
  }

  return [...tokens].filter(t => t.length >= 3);
}

// ─── Token analysis ───────────────────────────────────────────────────────────────

const VOWELS = new Set(['a', 'e', 'i', 'o', 'u']);

export function analyzeToken(token: string): TokenAnalysis {
  const lower = token.toLowerCase().replace(/[^a-z0-9]/g, '');
  if (lower.length === 0) {
    return { token, isRandomLike: false, confidence: 0, entropy: 0, reasons: [] };
  }

  // Shannon entropy
  const freq = new Map<string, number>();
  for (const c of lower) freq.set(c, (freq.get(c) ?? 0) + 1);
  let entropy = 0;
  for (const count of freq.values()) {
    const p = count / lower.length;
    entropy -= p * Math.log2(p);
  }

  const vowelCount = [...lower].filter(c => VOWELS.has(c)).length;
  const vowelRatio = vowelCount / lower.length;
  const hasConsonantCluster = /[^aeiou0-9]{3,}/.test(lower);
  const numericRatio = (lower.match(/\d/g) ?? []).length / lower.length;
  const uniqueRatio = freq.size / lower.length;
  const isCommonWord = COMMON_WORDS.has(lower) || PHISHING_KEYWORDS.has(lower);

  const reasons: string[] = [];
  let score = 0;

  if (isCommonWord) score -= 5;

  if (lower.length >= 5 && entropy >= 2.5) {
    score += 2;
    reasons.push(`High entropy (${entropy.toFixed(2)} bits)`);
  } else if (lower.length >= 4 && entropy >= 2.0) {
    score += 1;
  }

  if (hasConsonantCluster) {
    score += 2;
    reasons.push('Unusual consonant cluster');
  }

  if (vowelRatio === 0 && lower.length >= 3) {
    // No vowels at all — very strong randomness signal (e.g. "9fg", "qshdp", "zop5s")
    score += 3;
    reasons.push('No vowels in token');
  } else if (vowelRatio < 0.2 && lower.length >= 4) {
    score += 2;
    reasons.push(`Very low vowel ratio (${(vowelRatio * 100).toFixed(0)}%)`);
  } else if (vowelRatio <= 0.25 && lower.length >= 4 && lower.length <= 8) {
    // Short tokens with low (but not zero) vowel ratio — e.g. "zop5s", "mazny"
    score += 1;
    reasons.push('Low vowel ratio for short token');
  }

  if (numericRatio >= 0.4 && numericRatio < 1.0) {
    score += 1;
    reasons.push('High numeric density');
  }

  if (uniqueRatio >= 0.85 && lower.length >= 5) {
    score += 1;
    reasons.push('High character uniqueness');
  }

  return {
    token: lower,
    isRandomLike: score >= 2,
    confidence: Math.max(0, Math.min(1, score / 5)),
    entropy,
    reasons,
  };
}

// ─── Brand detection in candidate domain ─────────────────────────────────────────

export function detectBrandInDomain(
  candidateDomain: string,
  brandTokens: string[],
): BrandMatchResult | null {
  const sld = candidateDomain.split('.')[0].toLowerCase();
  const normalizedSld = normalizeHomoglyphs(sld);
  const isHomoglyphSld = normalizedSld !== sld;

  for (const brand of brandTokens) {
    if (brand.length < 3) continue;

    // Check both the raw sld and the homoglyph-normalized version
    for (const [target, isHomoglyph] of [[sld, false], [normalizedSld, isHomoglyphSld]] as [string, boolean][]) {
      if (!isHomoglyph && target === brand) return null; // exact match = target domain itself

      if (target.startsWith(brand)) {
        const remaining = (isHomoglyph ? sld : target).slice(brand.length).replace(/^[-_]/, '');
        if (remaining.length === 0 && !isHomoglyph) return null; // plain TLD variant
        return { brand, position: 'prefix', remaining };
      }

      if (target.endsWith(brand)) {
        const raw = isHomoglyph ? sld : target;
        const remaining = raw.slice(0, raw.length - brand.length).replace(/[-_]$/, '');
        if (remaining.length === 0 && !isHomoglyph) return null;
        return { brand, position: 'suffix', remaining };
      }

      // Embedded: only for brands 4+ chars to limit noise
      if (brand.length >= 4) {
        const idx = target.indexOf(brand);
        if (idx > 0 && idx + brand.length < target.length) {
          return { brand, position: 'embedded', remaining: sld };
        }
      }
    }
  }
  return null;
}

// ─── Homoglyph brand normalization ──────────────────────────────────────────────

const HOMOGLYPH_TO_ALPHA: Record<string, string> = {
  '0': 'o', '1': 'i', '3': 'e', '4': 'a', '5': 's', '7': 't', '9': 'g',
};

function normalizeHomoglyphs(s: string): string {
  return s.replace(/[013457 9]/g, c => HOMOGLYPH_TO_ALPHA[c] ?? c);
}

// Generate the common digit-substituted variant of a brand token (e.g. "ofx" → "0fx")
export function homoglyphVariants(brand: string): string[] {
  const variants = new Set<string>();
  // Only substitute the first different char to keep variants focused
  for (let i = 0; i < brand.length; i++) {
    for (const [alpha, digit] of Object.entries(HOMOGLYPH_TO_ALPHA).map(([d, a]) => [a, d] as const)) {
      if (brand[i] === alpha) {
        variants.add(brand.slice(0, i) + digit + brand.slice(i + 1));
      }
    }
  }
  return [...variants].filter(v => v !== brand);
}

// ─── CT brand domain discovery ───────────────────────────────────────────────────

async function fetchCtBrandDomains(brandTokens: string[], targetDomain: string): Promise<string[]> {
  const primaryBrand = brandTokens[0];
  if (!primaryBrand || primaryBrand.length < 3) return [];

  // Include homoglyph variants of the primary brand (e.g. "ofx" → "0fx")
  const searchTerms = [primaryBrand, ...homoglyphVariants(primaryBrand)];

  const results = new Set<string>();

  await Promise.allSettled(searchTerms.map(async (term) => {
    try {
      const res = await fetch(
        `https://crt.sh/?q=%25${encodeURIComponent(term)}%25&output=json`,
        { signal: AbortSignal.timeout(12000) },
      );
      if (!res.ok) return;

      const certs = (await res.json() as Array<{ name_value: string }>).slice(0, 300);

      for (const cert of certs) {
        if (!cert.name_value) continue;
        for (const entry of cert.name_value.split('\n')) {
          const clean = entry.trim().replace(/^\*\./, '').toLowerCase();
          if (!clean) continue;
          if (!/^[a-z0-9][a-z0-9\-.]{0,60}[a-z0-9]\.[a-z]{2,}$/.test(clean)) continue;
          if (clean === targetDomain || clean.endsWith(`.${targetDomain}`)) continue;
          results.add(clean);
        }
      }
    } catch {
      // non-fatal
    }
  }));

  return [...results];
}

// ─── RDAP domain age lookup ──────────────────────────────────────────────────────

function extractApexDomain(hostname: string): string {
  const parts = hostname.split('.');
  // Simple 2-label apex extraction (covers >95% of gTLDs)
  // Does not handle compound TLDs like .co.uk — acceptable tradeoff for a free tool
  return parts.length > 2 ? parts.slice(-2).join('.') : hostname;
}

async function fetchRdap(hostname: string): Promise<DomainAge> {
  const domain = extractApexDomain(hostname);
  const tld = domain.split('.').pop()?.toLowerCase() ?? '';
  const server = RDAP_SERVERS[tld];
  if (!server) return { bucket: 'unknown' };

  try {
    const res = await fetch(`${server}${encodeURIComponent(domain)}`, {
      headers: { Accept: 'application/rdap+json' },
      signal: AbortSignal.timeout(4000),
    });
    if (!res.ok) return { bucket: 'unknown' };

    const data = await res.json() as {
      events?: Array<{ eventAction: string; eventDate: string }>;
    };

    const regEvent = data.events?.find(e => e.eventAction === 'registration');
    if (!regEvent?.eventDate) return { bucket: 'unknown' };

    const registeredAt = new Date(regEvent.eventDate);
    if (isNaN(registeredAt.getTime())) return { bucket: 'unknown' };

    const ageDays = Math.floor((Date.now() - registeredAt.getTime()) / 86_400_000);

    return {
      registeredAt: registeredAt.toISOString().split('T')[0],
      ageDays,
      bucket:
        ageDays < 1  ? '<24h' :
        ageDays < 7  ? '<7d'  :
        ageDays < 30 ? '<30d' :
        ageDays < 90 ? '<90d' : '>90d',
    };
  } catch {
    return { bucket: 'unknown' };
  }
}

// ─── Variant generation ──────────────────────────────────────────────────────────

function generateVariants(targetDomain: string): Variant[] {
  const parts = targetDomain.split('.');
  if (parts.length < 2) return [];

  const tldFull = parts.slice(1).join('.');
  const sld = parts[0].toLowerCase();
  const variants: Variant[] = [];
  const seen = new Set<string>();

  function add(domain: string, attackType: AttackType, reason: string, priority: number) {
    if (!seen.has(domain) && domain.length >= 3 && /^[a-z0-9]([a-z0-9\-.]{0,61}[a-z0-9])?$/.test(domain)) {
      seen.add(domain);
      variants.push({ domain, attackType, reasons: [reason], phishingPriority: priority });
    }
  }

  // 1. Phishing prefixes / suffixes
  for (const p of PHISHING_PREFIXES) {
    add(`${p}-${sld}.${tldFull}`, 'phishing_keyword', `Prefix "${p}" — brand impersonation keyword`, 30);
    add(`${p}${sld}.${tldFull}`,  'phishing_keyword', `Prefix "${p}" — brand impersonation keyword`, 25);
  }
  for (const s of PHISHING_SUFFIXES) {
    add(`${sld}-${s}.${tldFull}`, 'phishing_keyword', `Suffix "${s}" — brand impersonation keyword`, 28);
    add(`${sld}${s}.${tldFull}`,  'phishing_keyword', `Suffix "${s}" — brand impersonation keyword`, 22);
  }

  // 2. Homoglyphs
  for (const [orig, replacement, description] of HOMOGLYPH_MAP) {
    if (sld.includes(orig)) {
      add(`${sld.replace(orig, replacement)}.${tldFull}`, 'homoglyph', description, 20);
      add(`${sld.replaceAll(orig, replacement)}.${tldFull}`, 'homoglyph', `All ${description}`, 18);
    }
  }

  // 3. Character deletion
  for (let i = 0; i < sld.length; i++) {
    add(`${sld.slice(0, i)}${sld.slice(i + 1)}.${tldFull}`, 'typosquat', `Missing "${sld[i]}" at position ${i + 1}`, 15);
  }

  // 4. Adjacent transposition
  for (let i = 0; i < sld.length - 1; i++) {
    const c = sld.split('');
    [c[i], c[i + 1]] = [c[i + 1], c[i]];
    add(`${c.join('')}.${tldFull}`, 'typosquat', `Swapped "${sld[i]}${sld[i + 1]}" → "${sld[i + 1]}${sld[i]}"`, 12);
  }

  // 5. Character doubling
  for (let i = 0; i < sld.length; i++) {
    add(`${sld.slice(0, i)}${sld[i]}${sld[i]}${sld.slice(i + 1)}.${tldFull}`, 'typosquat', `Doubled "${sld[i]}" at position ${i + 1}`, 10);
  }

  // 6. TLD variations
  const primaryTld = parts.slice(-1)[0];
  for (const altTld of ALT_TLDS) {
    if (altTld !== primaryTld) {
      add(`${sld}.${altTld}`, 'tld_variant', `TLD variant (.${altTld})`, 8);
    }
  }

  return variants
    .sort((a, b) => b.phishingPriority - a.phishingPriority)
    .slice(0, 60);
}

// ─── DNS resolution ──────────────────────────────────────────────────────────────

async function resolveDomain(domain: string): Promise<boolean> {
  try {
    const res = await fetch(
      `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=A`,
      { headers: { Accept: 'application/dns-json' }, signal: AbortSignal.timeout(4000) },
    );
    if (!res.ok) return false;
    const data = await res.json() as { Answer?: unknown[] };
    return Array.isArray(data.Answer) && data.Answer.length > 0;
  } catch {
    return false;
  }
}

// ─── CT subdomain lookup ──────────────────────────────────────────────────────────

async function fetchCtSubdomains(targetDomain: string): Promise<string[]> {
  try {
    const res = await fetch(
      `https://crt.sh/?q=%.${encodeURIComponent(targetDomain)}&output=json`,
      { signal: AbortSignal.timeout(10000) },
    );
    if (!res.ok) return [];
    const certs = (await res.json()) as Array<{ name_value: string; logged_at?: string }>;
    const names = new Map<string, string>();
    for (const cert of certs) {
      if (!cert.name_value) continue;
      for (const entry of cert.name_value.split('\n')) {
        const clean = entry.trim().replace(/^\*\./, '').toLowerCase();
        if (clean && clean !== targetDomain && clean.endsWith(`.${targetDomain}`)) {
          const existing = names.get(clean);
          if (!existing || (cert.logged_at && cert.logged_at > existing)) {
            names.set(clean, cert.logged_at ?? '');
          }
        }
      }
    }
    return [...names.entries()]
      .sort((a, b) => b[1].localeCompare(a[1]))
      .map(([n]) => n)
      .slice(0, 80);
  } catch {
    return [];
  }
}

// ─── Bounded concurrency DNS checker ─────────────────────────────────────────────

async function boundedDnsCheck(domains: string[], concurrency: number): Promise<boolean[]> {
  const results: boolean[] = new Array(domains.length).fill(false);
  let cursor = 0;

  async function worker() {
    while (cursor < domains.length) {
      const i = cursor++;
      results[i] = await resolveDomain(domains[i]);
    }
  }

  const pool = Array.from({ length: Math.min(concurrency, domains.length) }, worker);
  await Promise.all(pool);
  return results;
}

// ─── Risk scoring: traditional variants ──────────────────────────────────────────

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

// ─── Risk scoring: brand + random token ──────────────────────────────────────────

function scoreBrandRandomToken(
  domain: string,
  brandMatch: BrandMatchResult,
  tokenAnalysis: TokenAnalysis,
  domainAge: DomainAge,
  resolves: boolean,
): {
  level: LookalikeDomain['riskLevel'];
  score: number;
  confidence: 'high' | 'medium' | 'low';
  reasons: string[];
  evidence: Evidence[];
} {
  let score = 0;
  const reasons: string[] = [];
  const evidence: Evidence[] = [];

  // Exact brand match (always present)
  score += 35;
  reasons.push(`Exact brand match: ${brandMatch.brand.toUpperCase()}`);
  evidence.push({
    type: 'brand_match',
    description: `Brand token "${brandMatch.brand.toUpperCase()}" found at ${brandMatch.position} of domain`,
    value: brandMatch.brand,
  });

  // Token randomness or phishing keyword
  if (tokenAnalysis.isRandomLike) {
    const tokenScore = Math.round(tokenAnalysis.confidence * 25);
    score += tokenScore;
    const conf = tokenAnalysis.confidence >= 0.7 ? 'high' : 'medium';
    reasons.push(`Random-looking token "${tokenAnalysis.token}" (${conf} confidence)`);
    evidence.push({
      type: 'random_token',
      description: `Token "${tokenAnalysis.token}" appears algorithmically generated`,
      value: tokenAnalysis.token,
    });
  } else if (PHISHING_KEYWORDS.has(tokenAnalysis.token)) {
    score += 15;
    reasons.push(`Phishing keyword "${tokenAnalysis.token}" combined with brand`);
    evidence.push({
      type: 'phishing_keyword',
      description: `Token "${tokenAnalysis.token}" is a known phishing keyword`,
      value: tokenAnalysis.token,
    });
  }

  // Domain age signals
  switch (domainAge.bucket) {
    case '<24h': score += 30; reasons.push('Domain registered < 24 hours ago'); break;
    case '<7d':  score += 20; reasons.push('Domain registered < 7 days ago'); break;
    case '<30d': score += 10; reasons.push('Domain registered < 30 days ago'); break;
  }
  evidence.push({
    type: 'domain_age',
    description: domainAge.bucket === 'unknown'
      ? 'Domain registration date unavailable'
      : `Domain age: ${domainAge.bucket}${domainAge.registeredAt ? ` (registered ${domainAge.registeredAt})` : ''}`,
    value: domainAge.bucket,
  });

  // DNS resolution
  if (resolves) {
    score += 15;
    reasons.push('Domain currently resolves in DNS');
  }

  // TLD risk
  const tld = domain.split('.').pop()?.toLowerCase() ?? '';
  if (RISKY_TLDS.has(tld)) {
    score += 10;
    reasons.push(`.${tld} TLD commonly used in phishing campaigns`);
    evidence.push({
      type: 'tld_risk',
      description: `.${tld} TLD — elevated risk profile`,
      value: tld,
    });
  }

  const level: LookalikeDomain['riskLevel'] =
    score >= 90 ? 'highest' :
    score >= 70 ? 'high' :
    score >= 45 ? 'medium' :
    score >= 20 ? 'low' : 'lowest';

  const confidence: 'high' | 'medium' | 'low' =
    score >= 70 ? 'high' :
    score >= 40 ? 'medium' : 'low';

  return { level, score, confidence, reasons, evidence };
}

// ─── Main export ─────────────────────────────────────────────────────────────────

export async function runDomainMonitoring(targetDomain: string): Promise<DomainMonitoringResult> {
  const brandTokens = extractBrandTokens(targetDomain);
  const variants = generateVariants(targetDomain);

  // Phase 1: Run CT subdomain search, CT brand search, and DNS checks in parallel
  const [resolutions, ctSubdomains, ctBrandRaw] = await Promise.all([
    boundedDnsCheck(variants.map(v => v.domain), 8),
    fetchCtSubdomains(targetDomain),
    fetchCtBrandDomains(brandTokens, targetDomain),
  ]);

  // Phase 2: Score traditional lookalikes
  const traditionalLookalikes: LookalikeDomain[] = variants
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
    .filter(d => d.resolves || d.attackType === 'phishing_keyword')
    .sort((a, b) => b.riskScore - a.riskScore)
    .slice(0, 40);

  // Phase 3: Brand detection on CT candidates
  const brandCandidates = ctBrandRaw
    .map(domain => ({ domain, match: detectBrandInDomain(domain, brandTokens) }))
    .filter((c): c is { domain: string; match: BrandMatchResult } => c.match !== null)
    .slice(0, 50);

  // Phase 4: DNS check brand candidates
  const brandResolutions = await boundedDnsCheck(
    brandCandidates.map(c => c.domain),
    5,
  );

  // Phase 5: RDAP for top candidates (resolving first, then unresolved, max 20)
  const rdapTargets = brandCandidates
    .map((c, i) => ({ ...c, resolves: brandResolutions[i] }))
    .sort((a, b) => (b.resolves ? 1 : 0) - (a.resolves ? 1 : 0))
    .slice(0, 20);

  const rdapResults = await Promise.all(rdapTargets.map(c => fetchRdap(c.domain)));

  const rdapMap = new Map<string, DomainAge>();
  for (let i = 0; i < rdapTargets.length; i++) {
    rdapMap.set(rdapTargets[i].domain, rdapResults[i]);
  }

  // Phase 6: Score brand candidates
  const brandLookalikes: LookalikeDomain[] = [];
  for (let i = 0; i < brandCandidates.length; i++) {
    const { domain, match } = brandCandidates[i];
    const resolves = brandResolutions[i];
    const tokenAnalysis = analyzeToken(match.remaining);
    const domainAge = rdapMap.get(domain) ?? { bucket: 'unknown' as const };

    const { level, score, confidence, reasons, evidence } = scoreBrandRandomToken(
      domain, match, tokenAnalysis, domainAge, resolves,
    );

    if (score >= 40) {
      brandLookalikes.push({
        domain,
        riskLevel: level,
        riskScore: score,
        resolves,
        attackType: 'brand_random_token',
        confidence,
        domainAge,
        evidence,
        reasons,
      });
    }
  }

  // Deduplicate and merge
  const traditionalSet = new Set(traditionalLookalikes.map(d => d.domain));
  const uniqueBrandLookalikes = brandLookalikes
    .filter(d => !traditionalSet.has(d.domain))
    .sort((a, b) => b.riskScore - a.riskScore)
    .slice(0, 30);

  const allLookalikes = [...traditionalLookalikes, ...uniqueBrandLookalikes]
    .sort((a, b) => b.riskScore - a.riskScore)
    .slice(0, 60);

  return {
    scanned: variants.length + brandCandidates.length,
    resolving: [...resolutions, ...brandResolutions].filter(Boolean).length,
    ctSubdomains,
    lookalikeDomains: allLookalikes,
    brandTokens,
  };
}
