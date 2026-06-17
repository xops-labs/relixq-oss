import { NextResponse } from 'next/server';
import { apiSend } from '@/lib/api';

export const runtime = 'nodejs';

export async function POST(_req: Request, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const r = await apiSend<{ id: string }>(`/api/v1/projects/${id}/scans`, {});
  if (!r.ok || !r.data) {
    return NextResponse.json({ error: 'failed' }, { status: r.status || 500 });
  }
  return NextResponse.json({ scanId: r.data.id });
}
