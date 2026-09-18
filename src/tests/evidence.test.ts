import { describe, it, expect } from 'vitest';
import { redactSensitive, sanitizeHeaderValue, formatEvidenceItem } from '../lib/assessment/evidence.js';
import type { EvidenceItem } from '../lib/assessment/types.js';

describe('redactSensitive', () => {
  it('redacts Bearer tokens', () => {
    const input = 'Authorization: Bearer eyJhbGciOiJSUzI1NiJ9.payload.sig';
    const result = redactSensitive(input);
    expect(result).not.toContain('eyJhbGci');
    expect(result).toContain('[REDACTED]');
  });

  it('redacts standalone JWTs (no Bearer prefix)', () => {
    const input = 'rawjwt: eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.SIGNATURE123';
    const result = redactSensitive(input);
    expect(result).toContain('[JWT_REDACTED]');
    expect(result).not.toContain('eyJhbGci');
  });

  it('redacts AWS access keys', () => {
    const input = 'key=AKIAIOSFODNN7EXAMPLE';
    expect(redactSensitive(input)).toContain('[AWS_KEY_REDACTED]');
    expect(redactSensitive(input)).not.toContain('AKIAIOSFODNN7EXAMPLE');
  });

  it('redacts long hex strings (potential tokens/hashes)', () => {
    const input = 'session=a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2';
    const result = redactSensitive(input);
    expect(result).toContain('[HEX_REDACTED]');
  });

  it('does not alter clean strings', () => {
    const input = 'Content-Type: application/json';
    expect(redactSensitive(input)).toBe(input);
  });

  it('redacts password in query string', () => {
    const input = 'url?password=mysecretpassword';
    expect(redactSensitive(input)).toContain('password=[REDACTED]');
    expect(redactSensitive(input)).not.toContain('mysecretpassword');
  });
});

describe('sanitizeHeaderValue', () => {
  it('redacts Authorization header completely (preserves scheme)', () => {
    const result = sanitizeHeaderValue('Authorization', 'Bearer abc123secrettoken');
    expect(result).toBe('Bearer [REDACTED]');
    expect(result).not.toContain('abc123');
  });

  it('preserves non-sensitive headers', () => {
    const result = sanitizeHeaderValue('Content-Type', 'application/json');
    expect(result).toBe('application/json');
  });

  it('redacts cookie value but preserves name and attributes', () => {
    const result = sanitizeHeaderValue('set-cookie', 'session=abc123; HttpOnly; Secure; SameSite=Strict');
    expect(result).toContain('session=[REDACTED]');
    expect(result).toContain('HttpOnly');
    expect(result).toContain('Secure');
    expect(result).not.toContain('abc123');
  });

  it('fully redacts x-api-key header', () => {
    const result = sanitizeHeaderValue('x-api-key', 'super-secret-key-12345');
    expect(result).toBe('[REDACTED]');
  });

  it('is case-insensitive for header names', () => {
    const result1 = sanitizeHeaderValue('AUTHORIZATION', 'Basic dXNlcjpwYXNz');
    const result2 = sanitizeHeaderValue('authorization', 'Basic dXNlcjpwYXNz');
    expect(result1).toBe('Basic [REDACTED]');
    expect(result2).toBe('Basic [REDACTED]');
  });
});

describe('formatEvidenceItem', () => {
  it('formats HTTP response evidence', () => {
    const item: EvidenceItem = {
      type: 'http_response',
      request: { method: 'GET', url: 'https://api.example.com/v1/users' },
      response: {
        status: 200,
        statusText: 'OK',
        headers: { 'content-type': 'application/json' },
      },
      observations: ['No authentication required', 'Returns user list'],
      quality: 'direct',
    };
    const result = formatEvidenceItem(item);
    expect(result).toContain('GET https://api.example.com/v1/users');
    expect(result).toContain('HTTP 200 OK');
    expect(result).toContain('content-type: application/json');
    expect(result).toContain('• No authentication required');
    expect(result).toContain('• Returns user list');
  });

  it('formats DNS record evidence', () => {
    const item: EvidenceItem = {
      type: 'dns_record',
      observations: ['SPF record: v=spf1 ~all'],
      quality: 'direct',
    };
    const result = formatEvidenceItem(item);
    expect(result).toContain('• SPF record: v=spf1 ~all');
  });
});
