import { cookies } from 'next/headers';
import { NextResponse } from 'next/server';
import { env, SESSION_COOKIE } from '@/lib/env';

export const runtime = 'nodejs';

// Stream a findings export (json | sarif | markdown | html) from the API,
// preserving the content-type and attachment headers so the browser downloads.
export async function GET(req: Request, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const format = new URL(req.url).searchParams.get('format') ?? 'json';
  const token = (await cookies()).get(SESSION_COOKIE)?.value;

  const res = await fetch(
    `${env.apiBaseUrl}/api/v1/projects/${id}/export?format=${encodeURIComponent(format)}`,
    {
      headers: token ? { cookie: `${SESSION_COOKIE}=${token}` } : {},
      cache: 'no-store',
    },
  );

  if (!res.ok) {
    return NextResponse.json({ error: 'export_failed' }, { status: res.status });
  }

  const headers = new Headers();
  for (const name of ['content-type', 'content-disposition', 'content-length']) {
    const value = res.headers.get(name);
    if (value) headers.set(name, value);
  }
  return new NextResponse(res.body, { status: 200, headers });
}
