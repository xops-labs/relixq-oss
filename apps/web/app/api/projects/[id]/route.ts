import { NextResponse } from 'next/server';
import { apiSend } from '@/lib/api';

export const runtime = 'nodejs';

export async function DELETE(_req: Request, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const r = await apiSend<unknown>(`/api/v1/projects/${id}`, undefined, 'DELETE');
  if (!r.ok) {
    const error =
      r.status === 409 ? 'scan_in_progress' : r.status === 404 ? 'not_found' : 'failed';
    return NextResponse.json({ error }, { status: r.status || 500 });
  }
  return new NextResponse(null, { status: 204 });
}
