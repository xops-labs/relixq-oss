import Link from 'next/link';
import { Button, Field, Input } from '@/components/ui';
import { signupAction } from './actions';

const MESSAGES: Record<string, string> = {
  invalid_email: 'That email address does not look valid.',
  weak_password: 'Password is too weak — use at least 8 characters and avoid common patterns.',
  email_taken: 'An account with that email already exists.',
  invalid: 'Could not create the account. Check your details and try again.',
};

export default function SignupPage({ searchParams }: { searchParams: { error?: string } }) {
  const message = searchParams.error ? (MESSAGES[searchParams.error] ?? MESSAGES.invalid) : null;
  return (
    <div className="mx-auto max-w-sm space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Create your account</h1>
        <p className="text-sm text-muted-foreground">Self-hosted Relix-Q. One shared workspace.</p>
      </div>

      {message && (
        <p className="rounded-md border border-destructive/40 bg-destructive/10 px-3 py-2 text-sm text-destructive">
          {message}
        </p>
      )}

      <form action={signupAction} className="space-y-4">
        <Field label="Name">
          <Input name="displayName" type="text" autoComplete="name" placeholder="Ada Lovelace" />
        </Field>
        <Field label="Email">
          <Input name="email" type="email" autoComplete="email" required />
        </Field>
        <Field label="Password">
          <Input name="password" type="password" autoComplete="new-password" required minLength={8} />
        </Field>
        <Button type="submit" className="w-full">
          Create account
        </Button>
      </form>

      <p className="text-center text-sm text-muted-foreground">
        Already have an account?{' '}
        <Link href="/login" className="text-foreground underline-offset-2 hover:underline focus-ring rounded-sm">
          Sign in
        </Link>
      </p>
    </div>
  );
}
