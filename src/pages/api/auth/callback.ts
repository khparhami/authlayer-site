export const prerender = false;

import type { APIRoute } from 'astro';
import {
  ALLOWED_EMAIL,
  signSession,
  sessionCookie,
  getStateCookieValue,
} from '../../../lib/auth';

export const GET: APIRoute = async ({ url, locals, request }) => {
  const env = locals.runtime?.env ?? import.meta.env;
  const clientId = env.GOOGLE_CLIENT_ID;
  const clientSecret = env.GOOGLE_CLIENT_SECRET;
  const sessionSecret = env.SESSION_SECRET;

  const code = url.searchParams.get('code');
  const state = url.searchParams.get('state');
  const storedState = getStateCookieValue(request.headers.get('cookie'));

  if (!code || !state || state !== storedState) {
    return Response.redirect(new URL('/login?error=oauth', url.origin), 302);
  }

  try {
    const redirectUri = new URL('/api/auth/callback', url.origin).toString();

    const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        code,
        client_id: clientId,
        client_secret: clientSecret,
        redirect_uri: redirectUri,
        grant_type: 'authorization_code',
      }),
    });

    if (!tokenRes.ok) {
      return Response.redirect(new URL('/login?error=oauth', url.origin), 302);
    }

    const { access_token } = await tokenRes.json<{ access_token: string }>();

    const userRes = await fetch('https://www.googleapis.com/oauth2/v2/userinfo', {
      headers: { Authorization: `Bearer ${access_token}` },
    });

    const { email } = await userRes.json<{ email: string }>();

    if (email !== ALLOWED_EMAIL) {
      return Response.redirect(new URL('/login?error=unauthorized', url.origin), 302);
    }

    const token = await signSession(email, sessionSecret);

    return new Response(null, {
      status: 302,
      headers: {
        Location: '/admin',
        'Set-Cookie': sessionCookie(token),
      },
    });
  } catch {
    return Response.redirect(new URL('/login?error=oauth', url.origin), 302);
  }
};
