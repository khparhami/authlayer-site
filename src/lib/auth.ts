const SESSION_COOKIE = '__session';
const STATE_COOKIE = '__oauth_state';
const SESSION_HOURS = 8;
const ALLOWED_EMAIL = 'khparhami@gmail.com';

interface SessionPayload {
  email: string;
  exp: number;
}

async function getKey(secret: string): Promise<CryptoKey> {
  const enc = new TextEncoder();
  return crypto.subtle.importKey(
    'raw',
    enc.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign', 'verify']
  );
}

export async function signSession(email: string, secret: string): Promise<string> {
  const payload: SessionPayload = {
    email,
    exp: Date.now() + SESSION_HOURS * 60 * 60 * 1000,
  };
  const data = btoa(JSON.stringify(payload));
  const key = await getKey(secret);
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(data));
  const sigB64 = btoa(String.fromCharCode(...new Uint8Array(sig)));
  return `${data}.${sigB64}`;
}

export async function verifySession(
  cookieValue: string,
  secret: string
): Promise<SessionPayload | null> {
  try {
    const [data, sigB64] = cookieValue.split('.');
    if (!data || !sigB64) return null;

    const key = await getKey(secret);
    const sigBytes = Uint8Array.from(atob(sigB64), (c) => c.charCodeAt(0));
    const valid = await crypto.subtle.verify('HMAC', key, sigBytes, new TextEncoder().encode(data));
    if (!valid) return null;

    const payload: SessionPayload = JSON.parse(atob(data));
    if (Date.now() > payload.exp) return null;
    return payload;
  } catch {
    return null;
  }
}

export function sessionCookie(value: string): string {
  return `${SESSION_COOKIE}=${value}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${SESSION_HOURS * 3600}`;
}

export function clearSessionCookie(): string {
  return `${SESSION_COOKIE}=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0`;
}

export function stateCookie(state: string): string {
  return `${STATE_COOKIE}=${state}; HttpOnly; Secure; SameSite=Lax; Path=/api/auth; Max-Age=600`;
}

export function getSessionCookieValue(cookieHeader: string | null): string | null {
  if (!cookieHeader) return null;
  for (const part of cookieHeader.split(';')) {
    const [name, ...rest] = part.trim().split('=');
    if (name === SESSION_COOKIE) return rest.join('=');
  }
  return null;
}

export function getStateCookieValue(cookieHeader: string | null): string | null {
  if (!cookieHeader) return null;
  for (const part of cookieHeader.split(';')) {
    const [name, ...rest] = part.trim().split('=');
    if (name === STATE_COOKIE) return rest.join('=');
  }
  return null;
}

export { ALLOWED_EMAIL };
