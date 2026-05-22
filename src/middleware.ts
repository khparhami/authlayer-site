import { defineMiddleware } from 'astro:middleware';
import { verifySession, getSessionCookieValue } from './lib/auth';

export const onRequest = defineMiddleware(async (context, next) => {
  const { pathname } = context.url;

  if (!pathname.startsWith('/admin')) {
    return next();
  }

  const secret = context.locals.runtime?.env?.SESSION_SECRET ?? import.meta.env.SESSION_SECRET;
  const cookieHeader = context.request.headers.get('cookie');
  const cookieValue = getSessionCookieValue(cookieHeader);

  if (cookieValue && secret) {
    const session = await verifySession(cookieValue, secret);
    if (session) {
      context.locals.userEmail = session.email;
      return next();
    }
  }

  return context.redirect('/login');
});
