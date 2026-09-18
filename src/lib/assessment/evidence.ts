import type { EvidenceItem, EvidenceQuality } from './types.js';

const REDACT_PATTERNS: [RegExp, string][] = [
  [/Bearer\s+[A-Za-z0-9\-._~+/]+=*/gi,               'Bearer [REDACTED]'],
  [/token[=:]["']?[A-Za-z0-9\-._~+/]{16,}/gi,         'token=[REDACTED]'],
  [/api[_-]?key[=:]["']?[A-Za-z0-9\-._~+/]{8,}/gi,    'api_key=[REDACTED]'],
  [/password[=:]["']?[^\s"'&]{3,}/gi,                  'password=[REDACTED]'],
  [/secret[=:]["']?[A-Za-z0-9\-._~+/]{8,}/gi,         'secret=[REDACTED]'],
  [/access_token[=:]["']?[A-Za-z0-9\-._~+/]{8,}/gi,   'access_token=[REDACTED]'],
  [/refresh_token[=:]["']?[A-Za-z0-9\-._~+/]{8,}/gi,  'refresh_token=[REDACTED]'],
  [/eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]*/g, '[JWT_REDACTED]'],
  [/AKIA[A-Z0-9]{16}/g,                                '[AWS_KEY_REDACTED]'],
  [/\b[0-9a-f]{40,}\b/gi,                              '[HEX_REDACTED]'],
];

const SENSITIVE_HEADER_NAMES = new Set([
  'authorization', 'cookie', 'set-cookie', 'x-api-key',
  'x-auth-token', 'x-access-token', 'proxy-authorization',
]);

const DISPLAY_HEADERS = new Set([
  'content-type', 'access-control-allow-origin', 'access-control-allow-credentials',
  'access-control-allow-methods', 'access-control-allow-headers',
  'server', 'x-powered-by', 'strict-transport-security',
  'x-frame-options', 'content-security-policy', 'x-content-type-options',
  'www-authenticate', 'x-ratelimit-limit', 'x-ratelimit-remaining',
  'x-rate-limit-limit', 'retry-after', 'x-request-id',
  'x-api-version', 'api-version', 'vary', 'cache-control',
]);

export function redactSensitive(text: string): string {
  let result = text;
  for (const [pattern, replacement] of REDACT_PATTERNS) {
    result = result.replace(pattern, replacement);
  }
  return result;
}

export function sanitizeHeaderValue(name: string, value: string): string {
  const lower = name.toLowerCase();
  if (!SENSITIVE_HEADER_NAMES.has(lower)) return redactSensitive(value);
  if (lower === 'authorization' || lower === 'proxy-authorization') {
    const type = value.split(' ')[0] ?? 'Bearer';
    return `${type} [REDACTED]`;
  }
  if (lower === 'set-cookie') {
    return value.replace(/^([^=;]+)=[^;]*(;|$)/, '$1=[REDACTED]$2');
  }
  return '[REDACTED]';
}

export function buildHttpEvidence(opts: {
  url: string;
  method: string;
  response: Response;
  bodyExcerpt?: string | null;
  quality: EvidenceQuality;
  observations: string[];
}): EvidenceItem {
  const safeUrl = redactSensitive(opts.url);
  const responseHeaders: Record<string, string> = {};
  opts.response.headers.forEach((v, k) => {
    if (DISPLAY_HEADERS.has(k.toLowerCase())) {
      responseHeaders[k] = sanitizeHeaderValue(k, v);
    }
  });
  const safeBody = opts.bodyExcerpt
    ? redactSensitive(opts.bodyExcerpt.slice(0, 400))
    : undefined;

  const item: EvidenceItem = {
    type: 'http_response',
    request: { method: opts.method, url: safeUrl },
    response: {
      status: opts.response.status,
      statusText: opts.response.statusText ?? '',
      headers: responseHeaders,
      bodyExcerpt: safeBody,
    },
    observations: opts.observations,
    quality: opts.quality,
  };
  item.raw = formatEvidenceItem(item);
  return item;
}

export function formatEvidenceItem(item: EvidenceItem): string {
  const lines: string[] = [];
  if (item.request) {
    lines.push(`${item.request.method} ${item.request.url}`);
  }
  if (item.response) {
    lines.push(`HTTP ${item.response.status}${item.response.statusText ? ' ' + item.response.statusText : ''}`);
    if (item.response.headers) {
      for (const [k, v] of Object.entries(item.response.headers)) {
        lines.push(`${k}: ${v}`);
      }
    }
    if (item.response.bodyExcerpt) {
      lines.push('');
      lines.push(`Body (excerpt): ${item.response.bodyExcerpt}`);
    }
  }
  if (item.observations.length > 0) {
    lines.push('');
    for (const obs of item.observations) lines.push(`• ${obs}`);
  }
  return lines.join('\n');
}
