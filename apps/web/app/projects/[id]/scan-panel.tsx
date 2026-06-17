'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { InfoTip } from '@relix-q/web-components';
import { Button } from '@/components/ui';

export function ScanPanel({ projectId, initiallyRunning }: { projectId: string; initiallyRunning: boolean }) {
  const router = useRouter();
  const [busy, setBusy] = useState(initiallyRunning);
  const [message, setMessage] = useState<string | null>(initiallyRunning ? 'Scan running…' : null);

  async function run() {
    setBusy(true);
    setMessage('Scanning…');
    try {
      const start = await fetch(`/api/projects/${projectId}/scan`, { method: 'POST' });
      if (!start.ok) {
        setMessage('Could not start scan.');
        setBusy(false);
        return;
      }
      const { scanId } = (await start.json()) as { scanId: string };

      for (let i = 0; i < 150; i++) {
        await new Promise((r) => setTimeout(r, 2000));
        const status = (await fetch(`/api/scans/${scanId}`, { cache: 'no-store' }).then((r) => r.json())) as {
          status: string;
          error?: string;
        };
        if (status.status === 'succeeded') {
          setMessage(null);
          break;
        }
        if (status.status === 'failed') {
          setMessage(`Scan failed: ${status.error ?? 'unknown error'}`);
          break;
        }
      }
    } catch {
      setMessage('Scan error.');
    } finally {
      setBusy(false);
      router.refresh();
    }
  }

  return (
    <div className="flex items-center gap-3">
      <Button onClick={run} disabled={busy}>
        {busy ? 'Scanning…' : 'Run scan'}
      </Button>
      <InfoTip
        label="About scans"
        side="bottom"
        moreHref="/help#scanning"
        text="Runs the static scanner over the project source with the community rule pack, then recomputes the findings list, risk score, and crypto-agility grade."
      />
      {message && <span className="text-sm text-muted-foreground">{message}</span>}
    </div>
  );
}
