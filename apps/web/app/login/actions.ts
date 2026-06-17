'use server';

import { redirect } from 'next/navigation';
import { env } from '@/lib/env';
import { setSessionCookie } from '@/lib/session';

export async function loginAction(formData: FormData) {
  const email = String(formData.get('email') ?? '').trim();
  const password = String(formData.get('password') ?? '');

  const res = await fetch(`${env.apiBaseUrl}/api/v1/auth/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email, password }),
    cache: 'no-store',
  });

  if (!res.ok) redirect('/login?error=invalid');

  const data = (await res.json()) as { token: string };
  await setSessionCookie(data.token);
  redirect('/projects');
}
