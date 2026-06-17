'use server';

import { redirect } from 'next/navigation';
import { env } from '@/lib/env';
import { setSessionCookie } from '@/lib/session';

export async function signupAction(formData: FormData) {
  const email = String(formData.get('email') ?? '').trim();
  const password = String(formData.get('password') ?? '');
  const displayName = String(formData.get('displayName') ?? '').trim();

  const res = await fetch(`${env.apiBaseUrl}/api/v1/auth/signup`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email, password, displayName }),
    cache: 'no-store',
  });

  if (!res.ok) {
    const body = (await res.json().catch(() => ({}))) as { error?: string };
    redirect(`/signup?error=${encodeURIComponent(body.error ?? 'invalid')}`);
  }

  const data = (await res.json()) as { token: string };
  await setSessionCookie(data.token);
  redirect('/projects');
}
