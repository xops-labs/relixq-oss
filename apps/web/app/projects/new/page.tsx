import Link from 'next/link';
import { InfoTip } from '@relix-q/web-components';
import { Button, Field, Input, Label } from '@/components/ui';
import { createProjectAction } from './actions';

const MESSAGES: Record<string, string> = {
  name: 'Project name is required.',
  git: 'Enter a valid http(s) git URL.',
  git_url_required: 'Enter a git URL.',
  invalid_local_path: 'Local path must stay inside the mounted scan folder (no "..").',
  zip_required: 'Upload a .zip archive of your code.',
  upload_too_large: 'That .zip is too large (server limit is 1 GB). Zip your source only — exclude node_modules/, .git/, and build output.',
  upload_failed: 'The upload failed. Try again, or use a smaller .zip.',
  upload_not_found: 'The uploaded archive could not be found. Try uploading again.',
  slug_taken: 'A project with that name already exists.',
  failed: 'Could not create the project. Try again.',
};

export default function NewProjectPage({ searchParams }: { searchParams: { error?: string } }) {
  const message = searchParams.error ? (MESSAGES[searchParams.error] ?? MESSAGES.failed) : null;
  return (
    <div className="mx-auto max-w-lg space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">New project</h1>
        <p className="text-sm text-muted-foreground">
          Scan the bundled sample, a git repository, a mounted local folder, or a .zip you upload.
        </p>
      </div>

      {message && (
        <p className="rounded-md border border-destructive/40 bg-destructive/10 px-3 py-2 text-sm text-destructive">
          {message}
        </p>
      )}

      <form action={createProjectAction} encType="multipart/form-data" className="space-y-4">
        <Field label="Name">
          <Input name="name" type="text" placeholder="My service" required />
        </Field>
        <Field label="Description">
          <Input name="description" type="text" placeholder="Optional" />
        </Field>
        <div className="space-y-1">
          <span className="mb-1 flex items-center gap-1.5">
            <Label className="mb-0">Source</Label>
            <InfoTip
              label="About sources"
              side="bottom"
              moreHref="/help#scanning"
              text="What to scan: the bundled intentionally-vulnerable sample, a public or private git repository, a folder mounted under scan-targets/, or a .zip of source you upload."
            />
          </span>
          <select
            name="kind"
            defaultValue="sample"
            className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm focus-ring"
          >
            <option value="sample">Bundled sample (intentionally vulnerable)</option>
            <option value="git">Git repository</option>
            <option value="local">Local path (mounted folder)</option>
            <option value="upload">Upload code (.zip)</option>
          </select>
        </div>
        <Field
          label="Git URL (git source)"
          hint="http(s) URL of the repository to clone and scan. Only used when the source is 'Git repository'."
        >
          <Input name="gitUrl" type="url" placeholder="https://github.com/owner/repo" />
        </Field>
        <Field
          label="Access token (private git repos — optional)"
          hint="Personal access token used to clone private repositories. Stored server-side for re-scans and never shown again."
        >
          <Input name="gitToken" type="password" placeholder="Personal access token; stored for re-scans" autoComplete="off" />
        </Field>
        <Field
          label="Local path (local source)"
          hint="Subfolder under the read-only scan-targets/ mount to scan. Leave blank to scan the whole mount. Paths may not escape the mount ('..' is rejected)."
        >
          <Input name="localPath" type="text" placeholder="subfolder under scan-targets/ (blank = scan all)" />
        </Field>
        <Field label="Upload a .zip of your code (upload source)">
          <Input name="zipFile" type="file" accept=".zip,application/zip" className="py-1.5 file:mr-3 file:rounded file:border-0 file:bg-secondary file:px-3 file:py-1 file:text-sm" />
          <p className="text-xs text-muted-foreground">
            Zip your source only — exclude <code>node_modules/</code>, <code>.git/</code>, and build output. Max 1 GB.
          </p>
        </Field>
        <div className="flex items-center gap-3">
          <Button type="submit">Create project</Button>
          <Link href="/projects" className="text-sm text-muted-foreground hover:text-foreground focus-ring rounded-sm">
            Cancel
          </Link>
        </div>
      </form>
    </div>
  );
}
