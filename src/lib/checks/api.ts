import type { SecurityTest, Finding, ScanContext } from './types.js';
import { isBlockedHost } from '../ssrf.js';
import { buildHttpEvidence, redactSensitive } from '../assessment/evidence.js';

// ─── Shared helpers ────────────────────────────────────────────────────────────

async function fetchSafe(url: string, init: RequestInit = {}, ms = 8000): Promise<Response> {
  const hostname = new URL(url).hostname;
  if (isBlockedHost(hostname)) throw new Error(`Blocked host: ${hostname}`);
  return fetch(url, { ...init, signal: AbortSignal.timeout(ms) });
}

function getApiBase(ctx: ScanContext): string | null {
  if (!ctx.apiUrl) return null;
  try {
    const u = new URL(ctx.apiUrl);
    return `${u.protocol}//${u.host}`;
  } catch { return null; }
}

const OPENAPI_PATHS = [
  '/openapi.json', '/openapi.yaml', '/openapi',
  '/swagger.json', '/swagger.yaml', '/swagger',
  '/api-docs', '/api-docs.json', '/api/docs',
  '/v1/openapi.json', '/v2/openapi.json', '/v3/openapi.json',
  '/swagger/v1/swagger.json', '/api/swagger.json', '/api/openapi.json',
  '/_api', '/api/schema',
];

const GRAPHQL_PATHS = ['/graphql', '/api/graphql', '/query', '/gql', '/v1/graphql'];

async function tryOpenAPI(base: string): Promise<{ url: string; spec: Record<string, unknown> } | null> {
  for (const p of OPENAPI_PATHS) {
    try {
      const url = base + p;
      const res = await fetchSafe(url, { headers: { Accept: 'application/json, application/yaml, */*' } }, 5000);
      if (!res.ok) continue;
      const ct = res.headers.get('content-type') ?? '';
      if (!ct.includes('json') && !ct.includes('yaml') && !ct.includes('text')) continue;
      const text = await res.text();
      if (!/(openapi|swagger|paths|info)/i.test(text.slice(0, 500))) continue;
      try {
        const spec = JSON.parse(text) as Record<string, unknown>;
        return { url, spec };
      } catch {
        return { url, spec: { _yaml: true, _text: text.slice(0, 2000) } };
      }
    } catch { /* try next */ }
  }
  return null;
}

function parseOpenAPISpec(spec: Record<string, unknown>) {
  const info = spec['info'] as Record<string, unknown> | undefined;
  const title = typeof info?.title === 'string' ? info.title : undefined;
  const version = typeof info?.version === 'string' ? info.version
    : (typeof spec['openapi'] === 'string' ? spec['openapi'] : typeof spec['swagger'] === 'string' ? spec['swagger'] : undefined);

  const paths = spec['paths'] as Record<string, Record<string, unknown>> | undefined;
  const endpoints: Array<{ path: string; methods: string[]; authenticated: boolean }> = [];
  if (paths) {
    for (const [path, methods] of Object.entries(paths)) {
      const methodList = Object.keys(methods).filter(m =>
        ['get', 'post', 'put', 'delete', 'patch', 'head', 'options'].includes(m.toLowerCase())
      );
      if (methodList.length === 0) continue;
      const authenticated = methodList.some(m => {
        const op = methods[m] as Record<string, unknown> | undefined;
        return Array.isArray(op?.security) && (op.security as unknown[]).length > 0;
      });
      endpoints.push({ path, methods: methodList.map(m => m.toUpperCase()), authenticated });
    }
  }

  const authSchemes: string[] = [];
  const components = spec['components'] as Record<string, unknown> | undefined;
  const securitySchemes = (components?.securitySchemes ?? spec['securityDefinitions']) as Record<string, Record<string, unknown>> | undefined;
  if (securitySchemes) {
    for (const [name, scheme] of Object.entries(securitySchemes)) {
      const type = scheme['type'] as string | undefined;
      const flow = scheme['flows'] ? 'OAuth2' : undefined;
      authSchemes.push(flow ?? type ?? name);
    }
  }

  return { title, version, endpoints: endpoints.slice(0, 50), authSchemes };
}

// ─── API Tests ─────────────────────────────────────────────────────────────────

const apiEndpointDiscovery: SecurityTest = {
  test_id: 'API-001',
  name: 'API Endpoint Discovery',
  version: '1.0.0',
  category: 'api',
  severity: 'informational',
  confidence: 'medium',
  safe_for_production: true,
  requires_active_testing: false,
  async run(ctx: ScanContext): Promise<Finding> {
    const base = {
      test_id: this.test_id, name: this.name, category: this.category,
      severity: this.severity, confidence: this.confidence,
      detail: 'Determines whether the provided API URL is accessible, identifies the API technology, and gathers basic endpoint characteristics.',
      remediation: 'Ensure all API endpoints require appropriate authentication. Minimise information disclosed in response headers.',
      owasp_mapping: 'API9:2023',
      references: [
        { label: 'OWASP API Security Top 10', url: 'https://owasp.org/API-Security/editions/2023/en/0x00-header/' },
      ],
    };
    if (!ctx.apiUrl) {
      return { ...base, status: 'not_applicable', finding: 'No API URL was provided', reasonCode: 'NO_API_URL' };
    }
    try {
      const res = await fetchSafe(ctx.apiUrl, { headers: { Accept: 'application/json, */*' } }, 8000);
      const ct   = res.headers.get('content-type') ?? '';
      const srv  = res.headers.get('server') ?? '';
      const xpow = res.headers.get('x-powered-by') ?? '';
      const isJson = ct.includes('application/json') || ct.includes('application/vnd.');
      const isXml  = ct.includes('application/xml') || ct.includes('text/xml');
      const tech: string[] = [];
      if (srv) tech.push(`Server: ${redactSensitive(srv)}`);
      if (xpow) tech.push(`X-Powered-By: ${redactSensitive(xpow)}`);
      const apiType = isJson ? 'JSON API' : isXml ? 'XML/SOAP API' : `endpoint (${ct.split(';')[0].trim() || 'unknown type'})`;
      const evItem = buildHttpEvidence({
        url: ctx.apiUrl, method: 'GET', response: res,
        quality: 'direct',
        observations: [
          `HTTP ${res.status} — ${ct || 'no content-type'}`,
          ...tech,
        ],
      });
      return {
        ...base, status: 'info',
        finding: `API endpoint accessible — ${apiType}, HTTP ${res.status}${tech.length ? ' · ' + tech.join(', ') : ''}`,
        evidence: evItem.raw,
        confidence: 'high',
      };
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : String(e);
      if (msg.includes('Blocked')) return { ...base, status: 'not_applicable', finding: 'API URL blocked by safety policy', reasonCode: 'BLOCKED' };
      return { ...base, status: 'inconclusive', finding: 'Could not reach API endpoint', errorReason: 'Request timed out or the endpoint is unreachable.', reasonCode: 'REQUEST_TIMEOUT' };
    }
  },
};

const openAPIDiscovery: SecurityTest = {
  test_id: 'API-002',
  name: 'OpenAPI Documentation',
  version: '1.0.0',
  category: 'api',
  severity: 'medium',
  confidence: 'high',
  safe_for_production: true,
  requires_active_testing: false,
  async run(ctx: ScanContext): Promise<Finding> {
    const base = {
      test_id: this.test_id, name: this.name, category: this.category,
      severity: this.severity, confidence: this.confidence,
      detail: 'Publicly accessible API documentation (OpenAPI/Swagger) provides attackers with a complete map of endpoints, parameters, authentication mechanisms, and data schemas. This can significantly accelerate attack reconnaissance.',
      business_impact: 'Exposed API documentation reduces the effort required for targeted API attacks including BOLA, BFLA, and parameter manipulation.',
      remediation: 'Restrict access to API documentation to internal networks, authenticated users, or specific IP ranges. Do not serve Swagger UI or OpenAPI specs in production without access controls.',
      owasp_mapping: 'API9:2023',
      cwe: 'CWE-200',
      references: [
        { label: 'OWASP API9:2023 — Improper Inventory Management', url: 'https://owasp.org/API-Security/editions/2023/en/0xa9-improper-assets-management/' },
        { label: 'OpenAPI Specification', url: 'https://spec.openapis.org/oas/latest.html' },
      ],
    };
    const apiBase = getApiBase(ctx) ?? `https://${ctx.domain}`;
    try {
      const found = await tryOpenAPI(apiBase);
      if (!found) {
        return { ...base, status: 'inconclusive', finding: 'No OpenAPI/Swagger documentation found at common paths — documentation may exist at a custom location or require authentication', confidence: 'low', reasonCode: 'NOT_FOUND_AT_COMMON_PATHS' };
      }
      if (found.spec['_yaml']) {
        return {
          ...base, status: 'fail',
          finding: `OpenAPI documentation publicly accessible at ${found.url} (YAML format)`,
          evidence: `URL: ${found.url}\nFormat: YAML`,
        };
      }
      const parsed = parseOpenAPISpec(found.spec);
      const endpointCount = parsed.endpoints.length;
      const authSchemes = parsed.authSchemes.join(', ') || 'none detected';
      const evLines = [
        `URL: ${found.url}`,
        parsed.title ? `API: ${parsed.title}` : '',
        parsed.version ? `Version: ${parsed.version}` : '',
        `Endpoints enumerated: ${endpointCount}`,
        `Auth schemes: ${authSchemes}`,
      ].filter(Boolean).join('\n');
      return {
        ...base, status: 'fail',
        finding: `OpenAPI documentation publicly accessible at ${found.url} — ${endpointCount} endpoint${endpointCount !== 1 ? 's' : ''} enumerated`,
        evidence: evLines,
        detail: base.detail + (parsed.endpoints.length > 0
          ? `\n\nDiscovered endpoints (first 10): ${parsed.endpoints.slice(0, 10).map(e => `${e.methods.join('/')} ${e.path}`).join(', ')}`
          : ''),
      };
    } catch {
      return { ...base, status: 'inconclusive', finding: 'Could not complete OpenAPI discovery', errorReason: 'Network error during documentation scan.', reasonCode: 'REQUEST_TIMEOUT' };
    }
  },
};

const graphqlDetection: SecurityTest = {
  test_id: 'API-003',
  name: 'GraphQL API Detection',
  version: '1.0.0',
  category: 'api',
  severity: 'informational',
  confidence: 'medium',
  safe_for_production: true,
  requires_active_testing: false,
  async run(ctx: ScanContext): Promise<Finding> {
    const base = {
      test_id: this.test_id, name: this.name, category: this.category,
      severity: this.severity, confidence: this.confidence,
      detail: 'GraphQL APIs have unique security considerations including introspection exposure, batching attacks, and recursive query depth. Identifying the presence of GraphQL enables targeted security assessment.',
      remediation: 'Disable introspection in production. Implement query depth limiting, query complexity limits, and rate limiting on the GraphQL endpoint.',
      owasp_mapping: 'API9:2023',
      references: [
        { label: 'OWASP GraphQL Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html' },
      ],
    };
    const apiBase = getApiBase(ctx) ?? `https://${ctx.domain}`;
    const SAFE_QUERY = JSON.stringify({ query: '{ __typename }' });
    try {
      const results = await Promise.allSettled(
        GRAPHQL_PATHS.map(p =>
          fetchSafe(apiBase + p, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
            body: SAFE_QUERY,
          }, 5000)
        )
      );
      for (let i = 0; i < results.length; i++) {
        const r = results[i];
        if (r.status !== 'fulfilled') continue;
        const res = r.value;
        if (!res.ok && res.status !== 400) continue;
        const ct = res.headers.get('content-type') ?? '';
        if (!ct.includes('application/json')) continue;
        const text = await res.text().catch(() => '');
        if (!text.includes('data') && !text.includes('errors') && !text.includes('__typename')) continue;
        const path = GRAPHQL_PATHS[i];
        const introspectionEnabled = text.includes('__typename');
        return {
          ...base, status: 'info',
          finding: `GraphQL endpoint detected at ${path}${introspectionEnabled ? ' — __typename query succeeds' : ''}`,
          evidence: `URL: ${apiBase + path}\nHTTP: ${res.status}\n${ct ? 'Content-Type: ' + ct : ''}`,
          confidence: 'high',
        };
      }
      return { ...base, status: 'inconclusive', finding: 'GraphQL endpoint not identified at common paths', confidence: 'low', reasonCode: 'NOT_FOUND_AT_COMMON_PATHS' };
    } catch {
      return { ...base, status: 'inconclusive', finding: 'Could not probe for GraphQL endpoints', errorReason: 'Request timed out.', reasonCode: 'REQUEST_TIMEOUT' };
    }
  },
};

const apiAuthRequirement: SecurityTest = {
  test_id: 'API-004',
  name: 'API Authentication Requirement',
  version: '1.0.0',
  category: 'api',
  severity: 'high',
  confidence: 'medium',
  safe_for_production: true,
  requires_active_testing: false,
  async run(ctx: ScanContext): Promise<Finding> {
    const base = {
      test_id: this.test_id, name: this.name, category: this.category,
      severity: this.severity, confidence: this.confidence,
      detail: 'Determines whether the API endpoint requires authentication for access. An API that responds with data to unauthenticated requests may be exposing resources that require authorisation.',
      business_impact: 'Unauthenticated access to an API intended to be protected constitutes broken authentication (OWASP API2) and may expose sensitive business data.',
      remediation: 'Ensure all non-public API endpoints enforce authentication. Use 401 Unauthorized for missing credentials and 403 Forbidden for insufficient permissions.',
      owasp_mapping: 'API2:2023',
      cwe: 'CWE-306',
      references: [
        { label: 'OWASP API2:2023 — Broken Authentication', url: 'https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/' },
      ],
    };
    if (!ctx.apiUrl) {
      return { ...base, status: 'not_applicable', finding: 'No API URL was provided', reasonCode: 'NO_API_URL' };
    }
    try {
      const res = await fetchSafe(ctx.apiUrl, { headers: { Accept: 'application/json' } }, 8000);
      const ct = res.headers.get('content-type') ?? '';
      const wwwAuth = res.headers.get('www-authenticate');
      if (res.status === 401) {
        const scheme = wwwAuth ? wwwAuth.split(' ')[0] : 'unknown';
        return {
          ...base, status: 'pass',
          finding: `API returns 401 for unauthenticated requests — authentication scheme: ${scheme}`,
          evidence: `${ctx.apiUrl}\nHTTP 401 Unauthorized\n${wwwAuth ? 'WWW-Authenticate: ' + wwwAuth : ''}`,
        };
      }
      if (res.status === 403) {
        return {
          ...base, status: 'pass', confidence: 'medium',
          finding: 'API returns 403 for unauthenticated requests',
          evidence: `${ctx.apiUrl}\nHTTP 403 Forbidden`,
        };
      }
      if (res.status >= 200 && res.status < 300) {
        const isJson = ct.includes('application/json');
        const bodyExcerpt = isJson ? await res.text().then(t => redactSensitive(t.slice(0, 200))).catch(() => '') : null;
        const evItem = buildHttpEvidence({
          url: ctx.apiUrl, method: 'GET', response: res,
          bodyExcerpt,
          quality: 'direct',
          observations: [
            'No authentication header sent in request',
            `Endpoint returned HTTP ${res.status} with ${ct || 'no content-type'}`,
          ],
        });
        return {
          ...base, status: 'warn',
          finding: `API endpoint accessible without authentication — returned HTTP ${res.status}. Verify this endpoint is intentionally public.`,
          evidence: evItem.raw,
          reasonCode: 'UNAUTHENTICATED_ACCESS',
        };
      }
      return {
        ...base, status: 'inconclusive', confidence: 'low',
        finding: `API returned HTTP ${res.status} — authentication requirement could not be determined`,
        reasonCode: 'UNEXPECTED_STATUS',
      };
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : '';
      if (msg.includes('Blocked')) return { ...base, status: 'not_applicable', finding: 'API URL blocked by safety policy', reasonCode: 'BLOCKED' };
      return { ...base, status: 'inconclusive', finding: 'Could not determine API authentication requirement', errorReason: 'Request timed out or endpoint unreachable.', reasonCode: 'REQUEST_TIMEOUT' };
    }
  },
};

const apiCorsPolicy: SecurityTest = {
  test_id: 'API-005',
  name: 'API CORS Policy',
  version: '1.0.0',
  category: 'api',
  severity: 'high',
  confidence: 'confirmed',
  safe_for_production: true,
  requires_active_testing: false,
  async run(ctx: ScanContext): Promise<Finding> {
    const base = {
      test_id: this.test_id, name: this.name, category: this.category,
      severity: this.severity, confidence: this.confidence,
      detail: 'An overly permissive CORS policy on an API allows any web origin to make cross-origin requests, potentially enabling credential theft and cross-site request forgery when combined with insecure session handling.',
      remediation: 'Set Access-Control-Allow-Origin to specific trusted origins. Never use * with Access-Control-Allow-Credentials: true. Validate the Origin header against an allowlist.',
      owasp_mapping: 'API7:2023',
      references: [
        { label: 'MDN: CORS', url: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS' },
        { label: 'OWASP CORS Security', url: 'https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html#cross-origin-resource-sharing' },
      ],
    };
    const apiBase = getApiBase(ctx);
    if (!apiBase) {
      return { ...base, status: 'not_applicable', finding: 'No API URL was provided', reasonCode: 'NO_API_URL' };
    }
    try {
      const res = await fetchSafe(ctx.apiUrl!, {
        headers: { Origin: 'https://attacker.example', 'Access-Control-Request-Method': 'GET' },
      }, 6000);
      const acao = res.headers.get('access-control-allow-origin');
      const acac = res.headers.get('access-control-allow-credentials');
      const evidence = [
        `GET ${ctx.apiUrl}`,
        `Origin: https://attacker.example`,
        `Access-Control-Allow-Origin: ${acao ?? '(not set)'}`,
        acac ? `Access-Control-Allow-Credentials: ${acac}` : '',
      ].filter(Boolean).join('\n');

      if (!acao) return { ...base, status: 'pass', finding: 'No CORS headers returned — API does not appear to set permissive CORS', confidence: 'medium', evidence };
      if (acao === '*' && acac === 'true') return { ...base, status: 'fail', finding: 'API CORS wildcard (*) with credentials:true — any origin can make authenticated requests to this API', evidence };
      if (acao === '*') return { ...base, status: 'warn', finding: 'API CORS Access-Control-Allow-Origin: * — any origin may read responses. Verify this is intentional for a public API.', evidence, confidence: 'high' };
      if (acao === 'https://attacker.example') return { ...base, status: 'fail', finding: 'API reflects arbitrary Origin header in CORS response — any origin is permitted', evidence };
      return { ...base, status: 'pass', finding: `API CORS restricts to: ${acao}`, evidence };
    } catch {
      return { ...base, status: 'inconclusive', finding: 'Could not evaluate API CORS policy', errorReason: 'Request failed.', reasonCode: 'REQUEST_TIMEOUT' };
    }
  },
};

const apiRateLimiting: SecurityTest = {
  test_id: 'API-006',
  name: 'Rate Limiting',
  version: '1.0.0',
  category: 'api',
  severity: 'medium',
  confidence: 'low',
  safe_for_production: true,
  requires_active_testing: false,
  async run(ctx: ScanContext): Promise<Finding> {
    const base = {
      test_id: this.test_id, name: this.name, category: this.category,
      severity: this.severity, confidence: this.confidence,
      detail: 'Rate limiting on API endpoints prevents brute-force attacks, credential stuffing, and denial-of-service. Its presence can be detected from response headers.',
      remediation: 'Implement rate limiting at the API gateway or application level. Return X-RateLimit-Limit and Retry-After headers to help legitimate clients manage request rates.',
      owasp_mapping: 'API4:2023',
      references: [
        { label: 'OWASP API4:2023 — Unrestricted Resource Consumption', url: 'https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/' },
      ],
    };
    const targetUrl = ctx.apiUrl ?? `https://${ctx.domain}`;
    try {
      const res = await fetchSafe(targetUrl, {}, 6000);
      const rateLimitHeaders = [
        'x-ratelimit-limit', 'x-ratelimit-remaining', 'x-ratelimit-reset',
        'x-rate-limit-limit', 'ratelimit-limit', 'retry-after',
      ];
      const found: string[] = [];
      for (const h of rateLimitHeaders) {
        const v = res.headers.get(h);
        if (v) found.push(`${h}: ${v}`);
      }
      if (found.length > 0) {
        return { ...base, status: 'pass', finding: `Rate limiting headers detected: ${found.join(', ')}`, evidence: found.join('\n'), confidence: 'medium' };
      }
      return { ...base, status: 'inconclusive', finding: 'No rate limiting headers detected in response. Rate limiting may still be implemented without header disclosure.', confidence: 'low', reasonCode: 'NO_RATE_LIMIT_HEADERS' };
    } catch {
      return { ...base, status: 'inconclusive', finding: 'Could not check for rate limiting headers', errorReason: 'Request timed out.', reasonCode: 'REQUEST_TIMEOUT' };
    }
  },
};

const apiVersionDisclosure: SecurityTest = {
  test_id: 'API-007',
  name: 'Server and Version Disclosure',
  version: '1.0.0',
  category: 'api',
  severity: 'low',
  confidence: 'confirmed',
  safe_for_production: true,
  requires_active_testing: false,
  async run(ctx: ScanContext): Promise<Finding> {
    const base = {
      test_id: this.test_id, name: this.name, category: this.category,
      severity: this.severity, confidence: this.confidence,
      detail: 'Detailed server version information in response headers aids attackers in targeting known CVEs for specific software versions. This is a low-severity observation rather than a direct vulnerability.',
      remediation: 'Configure the web server or reverse proxy to suppress or genericise Server and X-Powered-By headers. In nginx: server_tokens off; In Apache: ServerTokens Prod.',
      owasp_mapping: 'API9:2023',
      cwe: 'CWE-200',
      references: [
        { label: 'OWASP API9:2023 — Improper Inventory Management', url: 'https://owasp.org/API-Security/editions/2023/en/0xa9-improper-assets-management/' },
      ],
    };
    const targetUrl = ctx.apiUrl ?? `https://${ctx.domain}`;
    try {
      const res = await fetchSafe(targetUrl, {}, 6000);
      const server = res.headers.get('server') ?? '';
      const xpow = res.headers.get('x-powered-by') ?? '';
      const VERSION_RE = /[\d.]{3,}|apache|nginx|iis|express|rails|django|laravel|php|node\.js|python|java|tomcat|gunicorn|uvicorn|fastapi/i;
      const disclosures: string[] = [];
      if (server && VERSION_RE.test(server)) disclosures.push(`Server: ${server}`);
      if (xpow && VERSION_RE.test(xpow)) disclosures.push(`X-Powered-By: ${xpow}`);
      if (disclosures.length > 0) {
        return { ...base, status: 'warn', finding: `Server/version information disclosed: ${disclosures.join('; ')}`, evidence: disclosures.join('\n') };
      }
      return { ...base, status: 'pass', finding: 'No detailed server/version information detected in response headers', confidence: 'medium' };
    } catch {
      return { ...base, status: 'inconclusive', finding: 'Could not check server version disclosure', errorReason: 'Request timed out.', reasonCode: 'REQUEST_TIMEOUT' };
    }
  },
};

const apiHttpMethods: SecurityTest = {
  test_id: 'API-009',
  name: 'HTTP Method Policy',
  version: '1.0.0',
  category: 'api',
  severity: 'low',
  confidence: 'medium',
  safe_for_production: true,
  requires_active_testing: false,
  async run(ctx: ScanContext): Promise<Finding> {
    const base = {
      test_id: this.test_id, name: this.name, category: this.category,
      severity: this.severity, confidence: this.confidence,
      detail: 'Identifies HTTP methods accepted by the API endpoint. Unnecessarily enabled methods (TRACE, CONNECT) may indicate overly permissive configuration.',
      remediation: 'Only enable HTTP methods required by the API. Disable TRACE and CONNECT at the server/proxy level. Verify that mutating methods (PUT, DELETE, PATCH) require appropriate authorisation.',
      owasp_mapping: 'API8:2023',
      references: [
        { label: 'OWASP API8:2023 — Security Misconfiguration', url: 'https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/' },
      ],
    };
    const targetUrl = ctx.apiUrl ?? `https://${ctx.domain}`;
    try {
      const res = await fetchSafe(targetUrl, { method: 'OPTIONS' }, 6000);
      const allow = res.headers.get('allow') ?? res.headers.get('access-control-allow-methods') ?? '';
      if (!allow) {
        return { ...base, status: 'inconclusive', finding: 'OPTIONS request did not return an Allow header — method policy could not be determined', confidence: 'low', reasonCode: 'NO_ALLOW_HEADER' };
      }
      const methods = allow.split(/,\s*/).map(m => m.trim().toUpperCase()).filter(Boolean);
      const risky = methods.filter(m => ['TRACE', 'CONNECT', 'TRACK'].includes(m));
      if (risky.length > 0) {
        return { ...base, status: 'warn', finding: `Potentially dangerous HTTP method(s) enabled: ${risky.join(', ')}`, evidence: `Allow: ${allow}` };
      }
      return { ...base, status: 'info', finding: `HTTP methods supported: ${methods.join(', ')}`, evidence: `Allow: ${allow}` };
    } catch {
      return { ...base, status: 'inconclusive', finding: 'Could not determine HTTP method policy', errorReason: 'Request timed out.', reasonCode: 'REQUEST_TIMEOUT' };
    }
  },
};

const apiTokenInUrl: SecurityTest = {
  test_id: 'API-010',
  name: 'Token Leakage in URL',
  version: '1.0.0',
  category: 'api',
  severity: 'high',
  confidence: 'confirmed',
  safe_for_production: true,
  requires_active_testing: false,
  async run(ctx: ScanContext): Promise<Finding> {
    const base = {
      test_id: this.test_id, name: this.name, category: this.category,
      severity: this.severity, confidence: this.confidence,
      detail: 'API keys, access tokens, and session tokens in URLs are logged by servers, proxies, and browser history. This is a common source of credential leakage.',
      remediation: 'Never pass authentication tokens as URL query parameters. Use the Authorization header or secure cookies instead.',
      owasp_mapping: 'API2:2023',
      cwe: 'CWE-598',
      references: [
        { label: 'OWASP: Sensitive Information in URL', url: 'https://owasp.org/www-community/vulnerabilities/Information_exposure_through_query_strings_in_url' },
      ],
    };
    if (!ctx.apiUrl) return { ...base, status: 'not_applicable', finding: 'No API URL provided', reasonCode: 'NO_API_URL' };
    try {
      const u = new URL(ctx.apiUrl);
      const SENSITIVE_PARAMS = ['token', 'access_token', 'api_key', 'apikey', 'key', 'secret', 'password', 'auth', 'jwt', 'bearer'];
      const found = SENSITIVE_PARAMS.filter(p => u.searchParams.has(p));
      if (found.length > 0) {
        return {
          ...base, status: 'fail',
          finding: `Potential authentication token(s) found in API URL query string: ${found.join(', ')}`,
          evidence: `URL parameters: ${found.map(p => `${p}=[REDACTED]`).join(', ')}`,
          reasonCode: 'TOKEN_IN_URL',
        };
      }
      return { ...base, status: 'pass', finding: 'No authentication token parameters detected in API URL' };
    } catch {
      return { ...base, status: 'inconclusive', finding: 'Could not parse API URL', reasonCode: 'PARSE_ERROR' };
    }
  },
};

export const API_TESTS: SecurityTest[] = [
  apiEndpointDiscovery,
  openAPIDiscovery,
  graphqlDetection,
  apiAuthRequirement,
  apiCorsPolicy,
  apiRateLimiting,
  apiVersionDisclosure,
  apiHttpMethods,
  apiTokenInUrl,
];
