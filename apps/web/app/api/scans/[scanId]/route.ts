import { NextResponse } from 'next/server';
import { apiGet } from '@/lib/api';

export const runtime = 'nodejs';

export async function GET(_req: Request, { params }: { params: Promise<{ scanId: string }> }) {
  const { scanId } = await params;
  const scan = await apiGet(`/api/v1/scans/${scanId}`);
  if (!scan) return NextResponse.json({ status: 'unknown' }, { status: 404 });
  return NextResponse.json(scan);
}
