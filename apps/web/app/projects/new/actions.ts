'use server';

import { redirect } from 'next/navigation';
import { apiSend, apiUpload } from '@/lib/api';

export async function createProjectAction(formData: FormData) {
  const name = String(formData.get('name') ?? '').trim();
  const description = String(formData.get('description') ?? '').trim();
  const kind = String(formData.get('kind') ?? 'sample');
  const gitUrl = String(formData.get('gitUrl') ?? '').trim();
  const gitToken = String(formData.get('gitToken') ?? '').trim();
  const localPath = String(formData.get('localPath') ?? '').trim();
  const zipFile = formData.get('zipFile');

  if (!name) redirect('/projects/new?error=name');
  if (kind === 'git' && !gitUrl.startsWith('http')) redirect('/projects/new?error=git');

  let source: { kind: string; value: string; token?: string };
  if (kind === 'git') {
    source = { kind: 'git', value: gitUrl, ...(gitToken ? { token: gitToken } : {}) };
  } else if (kind === 'local') {
    source = { kind: 'local', value: localPath };
  } else if (kind === 'upload') {
    if (!(zipFile instanceof File) || zipFile.size === 0) redirect('/projects/new?error=zip_required');
    const fd = new FormData();
    fd.append('file', zipFile as File);
    const up = await apiUpload<{ uploadId: string }>('/api/v1/uploads', fd);
    if (!up.ok || !up.data) {
      const code = (up.error as { error?: string })?.error ?? 'upload_failed';
      redirect(`/projects/new?error=${encodeURIComponent(code)}`);
    }
    source = { kind: 'upload', value: up.data.uploadId };
  } else {
    source = { kind: 'sample', value: 'sample-vulnerable' };
  }

  const r = await apiSend<{ id: string }>('/api/v1/projects', { name, description, source });
  if (!r.ok || !r.data) {
    const code = (r.error as { error?: string })?.error ?? 'failed';
    redirect(`/projects/new?error=${encodeURIComponent(code)}`);
  }
  redirect(`/projects/${r.data.id}`);
}
