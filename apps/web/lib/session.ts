import { cookies } from 'next/headers';
import { redirect } from 'next/navigation';
import { env, SESSION_COOKIE } from './env';
import type { User } from './types';

/** Resolve the current user via the API's /auth/me, or null if unauthenticated. */
export async function getUser(): Promise<User | null> {
  const token = (await cookies()).get(SESSION_COOKIE)?.value;
  if (!token) return null;
  const res = await fetch(`${env.apiBaseUrl}/api/v1/auth/me`, {
    headers: { cookie: `${SESSION_COOKIE}=${token}` },
    cache: 'no-store',
  });
  if (!res.ok) return null;
  return (await res.json()) as User;
}

/** Server-component guard: redirect to /login when unauthenticated. */
export async function requireUser(): Promise<User> {
  const user = await getUser();
  if (!user) redirect('/login');
  return user;
}

// The two helpers below mutate cookies and must be called from a Server Action
// or Route Handler (Next forbids cookie writes during render).
export async function setSessionCookie(token: string) {
  (await cookies()).set(SESSION_COOKIE, token, {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    path: '/',
    maxAge: 60 * 60 * 24 * 7,
  });
}

export async function clearSessionCookie() {
  (await cookies()).delete(SESSION_COOKIE);
}
