import './globals.css';
import type { Metadata } from 'next';
import Link from 'next/link';
import { env } from '@/lib/env';
import { getUser } from '@/lib/session';
import { logoutAction } from './actions';

export const metadata: Metadata = {
  title: 'Relix-Q OSS',
  description: 'Post-quantum crypto risk scanner — open-source self-host.',
};

export default async function RootLayout({ children }: { children: React.ReactNode }) {
  const user = await getUser();
  return (
    <html lang="en" className="scroll-smooth">
      <body className="min-h-screen">
        <header className="sticky top-0 z-40 border-b bg-background/95 backdrop-blur">
          <div className="container flex h-14 items-center justify-between">
            <Link href="/" className="flex items-center gap-2 rounded-sm font-semibold tracking-tight focus-ring">
              <span className="flex h-7 w-7 items-center justify-center rounded-lg bg-slate-950 font-mono text-xs text-cyan-300">
                RQ
              </span>
              <span>{env.appName}</span>
            </Link>
            <nav className="flex items-center gap-3 text-sm sm:gap-4">
              <Link href="/about" className="text-muted-foreground hover:text-foreground focus-ring rounded-sm">
                About
              </Link>
              <Link href="/help" className="hidden text-muted-foreground hover:text-foreground focus-ring rounded-sm sm:inline">
                Help
              </Link>
              {user ? (
                <>
                  <Link href="/projects" className="text-muted-foreground hover:text-foreground focus-ring rounded-sm">
                    Projects
                  </Link>
                  <span className="hidden text-muted-foreground lg:inline">{user.email}</span>
                  <form action={logoutAction}>
                    <button className="text-muted-foreground hover:text-foreground focus-ring rounded-sm">
                      Sign out
                    </button>
                  </form>
                </>
              ) : (
                <>
                  <Link href="/login" className="text-muted-foreground hover:text-foreground focus-ring rounded-sm">
                    Sign in
                  </Link>
                  <Link
                    href="/signup"
                    className="rounded-lg bg-slate-950 px-3 py-2 text-xs font-semibold text-white hover:bg-slate-800 focus-ring sm:text-sm"
                  >
                    Create account
                  </Link>
                </>
              )}
            </nav>
          </div>
        </header>
        <main className="container py-8">{children}</main>
      </body>
    </html>
  );
}
