export type OAuthProtocol = 'oidc' | 'oauth2';

export interface OIDCDiscovery {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  jwks_uri?: string;
  revocation_endpoint?: string;
  userinfo_endpoint?: string;
  scopes_supported?: string[];
  response_types_supported?: string[];
  grant_types_supported?: string[];
  code_challenge_methods_supported?: string[];
  id_token_signing_alg_values_supported?: string[];
}

// Stored in KV under oauth:{state}, TTL 600s
// SECURITY: codeVerifier is secret — never log it
export interface OAuthFlowState {
  state: string;
  nonce: string;
  codeVerifier: string;
  domain: string;
  apiUrl?: string;
  authUrl?: string;
  issuer: string;
  tokenEndpoint: string;
  jwksUri?: string;
  revocationEndpoint?: string;
  clientId: string;
  redirectUri: string;
  requestedScopes: string;
  expiresAt: number; // epoch ms
}

export interface TokenMetadata {
  tokenType: 'JWT' | 'opaque';
  issuer?: string;
  subject?: string;
  audience?: string | string[];
  algorithm?: string;
  keyId?: string;
  issuedAt?: number;
  expiresAt?: number;
  expiresInSeconds?: number;
  scopes?: string[];
  notBefore?: number;
}

// SECURITY: this object must NEVER be serialized, logged, or stored anywhere
export interface AuthenticatedContext {
  /** SECURITY: never log, never serialize, never pass to AI */
  accessToken: string;
  tokenType: string;
  tokenMetadata: TokenMetadata;
  domain: string;
  apiUrl?: string;
  authUrl?: string;
  issuer: string;
  clientId: string;
  requestedScopes: string;
}

// Safe subset — OK to serialize and include in results
export interface AuthConnectionInfo {
  issuer: string;
  scopes: string[];
  algorithm?: string;
  expiresInSeconds?: number;
  tokenType: 'JWT' | 'opaque';
}
