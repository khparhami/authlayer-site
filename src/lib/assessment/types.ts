export type AssetType =
  | 'website' | 'api' | 'auth_service' | 'subdomain'
  | 'dns_domain' | 'email_infra' | 'hostname';

export type AssetSource = 'user_provided' | 'discovered' | 'derived';

export type AssessmentMode = 'passive' | 'safe_active' | 'authenticated';

export type EvidenceQuality = 'direct' | 'strong' | 'indirect' | 'insufficient';

export type RetestStatus = 'fixed' | 'still_present' | 'changed' | 'inconclusive';

export interface Asset {
  id: string;
  type: AssetType;
  hostname: string;
  url?: string;
  source: AssetSource;
  discoveredFrom?: string;
  metadata?: Record<string, unknown>;
}

export interface EvidenceRequest {
  method: string;
  url: string;
  headers?: Record<string, string>;
}

export interface EvidenceResponse {
  status: number;
  statusText?: string;
  headers?: Record<string, string>;
  bodyExcerpt?: string;
}

export interface EvidenceItem {
  type: 'http_response' | 'dns_record' | 'header_observation' | 'cookie_observation' | 'tls_observation' | 'generic';
  request?: EvidenceRequest;
  response?: EvidenceResponse;
  observations: string[];
  quality: EvidenceQuality;
  raw?: string;
}

export interface EndpointInfo {
  assetId: string;
  url: string;
  method?: string;
  authenticated?: boolean;
  rateLimited?: boolean;
  technology?: string;
}

export interface AttackSurface {
  assetsProvided: Asset[];
  assetsDiscovered: Asset[];
  assetsTested: Asset[];
  endpoints: EndpointInfo[];
}

export interface AttackPathNode {
  assetId: string;
  label: string;
  type: 'entry_point' | 'service' | 'data_store' | 'auth_boundary';
}

export interface AttackPath {
  id: string;
  label: string;
  nodes: AttackPathNode[];
  relatedFindingIds: string[];
  risk: 'critical' | 'high' | 'medium' | 'low';
  description?: string;
}

export interface RetestResult {
  originalFindingId: string;
  retestTimestamp: string;
  status: RetestStatus;
  evidenceItems?: EvidenceItem[];
  notes?: string;
}

export interface AssessmentSummary {
  assessmentId: string;
  timestamp: string;
  domain: string;
  confirmed: number;
  potential: number;
  observations: number;
  passed: number;
  inconclusive: number;
  notRun: number;
  score: number;
  grade: string;
}

export interface AuditEntry {
  assessmentId: string;
  testId: string;
  assetId: string;
  timestamp: string;
  requestOutcome: 'success' | 'timeout' | 'error' | 'blocked';
  resultStatus: string;
  reasonCode?: string;
  evidenceRef?: string;
  classification?: string;
  severity?: string;
  confidence?: string;
}

export interface OpenAPIEndpoint {
  path: string;
  methods: string[];
  authenticated: boolean;
  parameters?: string[];
  tags?: string[];
}

export interface OpenAPIDiscoveryResult {
  found: boolean;
  url?: string;
  version?: string;
  title?: string;
  endpoints?: OpenAPIEndpoint[];
  authSchemes?: string[];
  inconclusiveReason?: string;
}

export interface APIDiscoveryResult {
  type: 'rest' | 'graphql' | 'soap' | 'jsonrpc' | 'unknown';
  baseUrl: string;
  authMechanisms: string[];
  openapi?: OpenAPIDiscoveryResult;
  technology?: string;
  version?: string;
  rateLimit?: boolean;
  corsPolicy?: string;
  httpRequestCount?: number;
}

export interface TestRequires {
  authentication: boolean;
  javascript: boolean;
  assetTypes: AssetType[];
  apiUrl?: boolean;
}

export interface ClassificationRule {
  condition: string;
  classification: string;
  severity?: string;
  confidence?: string;
}

export interface TestMetadata {
  requires: TestRequires;
  allowedModes: AssessmentMode[];
  expectedEvidence: string[];
  classificationRules: ClassificationRule[];
  inconclusiveConditions: string[];
  owaspApiCategories?: string[];
}
