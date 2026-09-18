export type FindingStatus = 'pass' | 'fail' | 'warn' | 'info' | 'error' | 'inconclusive' | 'not_run' | 'not_applicable';
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'informational';
export type Confidence = 'confirmed' | 'high' | 'medium' | 'low' | 'informational';
export type Category =
  | 'dns'
  | 'transport'
  | 'cookies'
  | 'headers'
  | 'email'
  | 'oauth'
  | 'exposure'
  | 'api'
  | 'authentication';

export type FindingClassification =
  | 'confirmed_vulnerability'
  | 'potential_vulnerability'
  | 'security_observation'
  | 'hardening_recommendation'
  | 'passed'
  | 'not_checked'
  | 'inconclusive';

export interface Reference {
  label: string;
  url: string;
}

export interface Finding {
  test_id: string;
  name: string;
  category: Category;
  status: FindingStatus;
  severity: Severity;
  confidence: Confidence;
  classification?: FindingClassification;
  finding: string;
  detail?: string;
  business_impact?: string;
  evidence?: string;
  remediation?: string;
  owasp_mapping?: string;
  cwe?: string;
  references?: Reference[];
  errorReason?: string;
  reasonCode?: string;
}

export interface ScanContext {
  domain: string;
  authUrl: string | null;
  apiUrl?: string | null;
  additionalAssets?: string[];
  scope?: string[];
}

export interface ScanResult {
  domain: string;
  report: 'free' | 'paid';
  assetsDiscovered: number;
  endpointsTested: number;
  testsRun: number;
  score: number;
  grade: string;
  findings: Finding[];
  topFindings: Finding[];
}

export interface SecurityTest {
  test_id: string;
  name: string;
  version: string;
  category: Category;
  severity: Severity;
  confidence: Confidence;
  owasp_mapping?: string;
  cwe?: string;
  safe_for_production: boolean;
  requires_active_testing: boolean;
  run(ctx: ScanContext): Promise<Finding>;
}
