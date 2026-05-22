export const prerender = false;

import type { APIRoute } from 'astro';
import { stateCookie } from '../../../lib/auth';

export const GET: APIRoute = async ({ url, locals }) => {
  const clientId = locals.runtime?.env?.GOOGLE_CLIENT_ID ?? import.meta.env.GOOGLE_CLIENT_ID;

  const state = crypto.randomUUID();
  const redirectUri = new URL('/api/auth/callback', url.origin).toString();

  const params = new URLSearchParams({
    client_id: clientId,
    redirect_uri: redirectUri,
    response_type: 'code',
    scope: 'openid email',
    state,
    prompt: 'select_account',
  });

  return new Response(null, {
    status: 302,
    headers: {
      Location: `https://accounts.google.com/o/oauth2/v2/auth?${params}`,
      'Set-Cookie': stateCookie(state),
    },
  });
};
