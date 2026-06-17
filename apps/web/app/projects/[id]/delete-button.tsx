'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { Button } from '@/components/ui';

export function DeleteProjectButton({ projectId }: { projectId: string }) {
  const router = useRouter();
  const [confirming, setConfirming] = useState(false);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string | null>(null);

  async function remove() {
    setBusy(true);
    setMessage(null);
    try {
      const res = await fetch(`/api/projects/${projectId}`, { method: 'DELETE' });
      if (res.status === 204) {
        router.push('/projects');
        router.refresh();
        return;
      }
      const body = (await res.json().catch(() => null)) as { error?: string } | null;
      setMessage(
        body?.error === 'scan_in_progress'
          ? 'A scan is running — wait for it to finish, then delete.'
          : 'Could not delete the project.',
      );
      setConfirming(false);
    } catch {
      setMessage('Could not delete the project.');
      setConfirming(false);
    } finally {
      setBusy(false);
    }
  }

  if (!confirming) {
    return (
      <div className="flex items-center gap-3">
        <Button
          onClick={() => setConfirming(true)}
          className="border border-destructive/40 bg-transparent text-destructive hover:bg-destructive/10"
        >
          Delete project
        </Button>
        {message && <span className="text-sm text-muted-foreground">{message}</span>}
      </div>
    );
  }

  return (
    <div className="flex items-center gap-2">
      <span className="text-sm text-muted-foreground">Delete permanently, including all scans?</span>
      <Button
        onClick={remove}
        disabled={busy}
        className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
      >
        {busy ? 'Deleting…' : 'Confirm delete'}
      </Button>
      <Button onClick={() => setConfirming(false)} disabled={busy} className="bg-transparent border text-foreground hover:bg-muted">
        Cancel
      </Button>
    </div>
  );
}
