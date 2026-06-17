'use server';

import { cookies } from 'next/headers';
import { redirect } from 'next/navigation';
import { env, SESSION_COOKIE } from '@/lib/env';

export async function logoutAction() {
  const cookieStore = await cookies();
  const token = cookieStore.get(SESSION_COOKIE)?.value;
  if (token) {
    try {
      await fetch(`${env.apiBaseUrl}/api/v1/auth/logout`, {
        method: 'POST',
        headers: { cookie: `${SESSION_COOKIE}=${token}` },
      });
    } catch {
      /* best effort */
    }
  }
  cookieStore.delete(SESSION_COOKIE);
  redirect('/login');
}
