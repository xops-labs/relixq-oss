import type { Metadata } from 'next';
import Link from 'next/link';
import { SeverityBadge, cn, type Severity } from '@relix-q/web-components';
import { FamilyGrid } from './family-grid';
import { FaqAccordion, type FaqItem } from './faq-accordion';

export const metadata: Metadata = {
  title: 'Help — Relix-Q OSS',
  description:
    'How Relix-Q scores findings: risk score, severity, crypto agility, the NIST standards behind each recommendation, and answers to common questions.',
};

const NAV = [
  { id: 'risk-score', label: 'Risk score' },
  { id: 'severity', label: 'Severity' },
  { id: 'crypto-agility', label: 'Crypto agility' },
  { id: 'nist-standards', label: 'Algorithm families' },
  { id: 'scanning', label: 'Scanning' },
  { id: 'faq', label: 'FAQ' },
];

const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

const AGILITY_METRICS: { title: string; body: string; icon: React.ReactNode }[] = [
  {
    title: 'Library consolidation',
    body: 'Each extra crypto library is a separate migration project.',
    icon: <LayersIcon />,
  },
  {
    title: 'Call-site concentration',
    body: 'Crypto in 3 files migrates faster than in 40.',
    icon: <TargetIcon />,
  },
  {
    title: 'Algorithm diversity',
    body: 'Each distinct primitive needs its own replacement plan.',
    icon: <BranchIcon />,
  },
  {
    title: 'Hardcoded-key prevalence',
    body: 'Embedded keys can’t be swapped via imports or config.',
    icon: <KeyIcon />,
  },
];

const AGILITY_GRADES: { range: string; grade: string; pill: string; meaning: string }[] = [
  {
    range: '75–100',
    grade: 'Agile',
    pill: 'bg-emerald-500/15 text-emerald-700 ring-emerald-600/30 dark:text-emerald-400',
    meaning: 'Mechanical migration: a library or config swap suffices.',
  },
  {
    range: '50–74',
    grade: 'Manageable',
    pill: 'bg-sky-500/15 text-sky-700 ring-sky-600/30 dark:text-sky-400',
    meaning: 'Focused refactoring, single-sprint scope.',
  },
  {
    range: '25–49',
    grade: 'Difficult',
    pill: 'bg-amber-500/15 text-amber-700 ring-amber-600/30 dark:text-amber-400',
    meaning: 'Architectural changes; design review required.',
  },
  {
    range: '0–24',
    grade: 'Brittle',
    pill: 'bg-red-500/15 text-red-700 ring-red-600/30 dark:text-red-400',
    meaning: 'Structural rewrite; crypto is fundamentally entangled.',
  },
];

const SOURCES: { title: string; body: React.ReactNode; icon: React.ReactNode }[] = [
  {
    title: 'Bundled sample',
    body: 'Intentionally vulnerable, good for a first run.',
    icon: <FlaskIcon />,
  },
  {
    title: 'Git repository',
    body: 'http(s) URL, optional token for private repos, stored server-side.',
    icon: <GitIcon />,
  },
  {
    title: 'Local path',
    body: (
      <>
        A subfolder of the read-only <code className="rounded bg-muted px-1 py-0.5 font-mono text-xs">scan-targets/</code>{' '}
        mount.
      </>
    ),
    icon: <FolderIcon />,
  },
  {
    title: 'Uploaded .zip',
    body: (
      <>
        Max 1 GB — exclude <code className="rounded bg-muted px-1 py-0.5 font-mono text-xs">node_modules/</code>,{' '}
        <code className="rounded bg-muted px-1 py-0.5 font-mono text-xs">.git/</code>, and build output for faster,
        quieter scans.
      </>
    ),
    icon: <ArchiveIcon />,
  },
];

const FAQ: FaqItem[] = [
  {
    id: 'vendored',
    question: 'Why are files in node_modules or .next flagged?',
    answer: (
      <>
        The scanner inventories <em>every</em> crypto usage in the upload, including vendored dependencies and build
        output — bundled copies of weak crypto still ship with your application, so they belong in a complete
        inventory. When you want to focus on code you own, tick <strong>Hide vendored / build paths</strong> in the
        findings filter bar, or exclude those folders from the .zip before uploading.
      </>
    ),
  },
  {
    id: 'unknown-columns',
    question: 'Why do Service, Env, Exposure, and Owner show “unknown” or “—”?',
    answer: (
      <>
        Those columns are filled by context enrichment — service catalog, CODEOWNERS, environment tags, runtime
        telemetry. The OSS build scores findings on the evidence in the code itself; that enrichment pipeline is
        out of scope here, so the columns stay unknown and the corresponding score factors use
        neutral values.
      </>
    ),
  },
  {
    id: 'privacy',
    question: 'Does my code leave my machine?',
    answer: (
      <>
        No. The whole stack — Postgres, the API, the scanner, and this web UI — runs in your own Docker environment.
        There is no SaaS backend and no telemetry. Uploaded archives and clones are stored and scanned locally.
      </>
    ),
  },
  {
    id: 'dts-critical',
    question: 'Why is a .d.ts type declaration marked critical?',
    answer: (
      <>
        Severity comes from the rule that matched (for example “Node crypto.createECDH”), which can match in type
        declarations and bundled polyfills as well as in live call sites. A declaration file is evidence the API is
        part of your dependency surface, but it is weaker evidence than a call in your own source — use the path
        filter or the vendored-paths toggle to triage, and prioritize findings in code you deploy.
      </>
    ),
  },
  {
    id: 'risk-vs-agility',
    question: 'What is the difference between risk score and crypto agility?',
    answer: (
      <>
        They answer different questions. <strong>Risk score</strong> (higher = worse) measures how dangerous the
        most severe finding is today. <strong>Crypto agility</strong> (higher = better) predicts how hard the
        migration will be, from the structure of your crypto usage. High risk with high agility means “dangerous but
        cheap to fix — do it now”; high risk with low agility means “start planning early.”
      </>
    ),
  },
  {
    id: 'report',
    question: 'A crypto usage was not detected — or something safe was flagged. What should I do?',
    answer: (
      <>
        Open an issue on{' '}
        <a
          href="https://github.com/xops-labs/relixq-oss/issues"
          className="focus-ring rounded-sm underline underline-offset-2"
          target="_blank"
          rel="noreferrer"
        >
          GitHub
        </a>{' '}
        with the snippet. Every rule ships with inline self-tests and the pack is gated by a labeled validation
        corpus, so reports of missed crypto or false positives turn into permanent regression tests.
      </>
    ),
  },
];

// ---------------------------------------------------------------------------
// Icons (decorative, aria-hidden)
// ---------------------------------------------------------------------------

function QuestionIcon() {
  return (
    <svg viewBox="0 0 20 20" fill="none" aria-hidden className="h-6 w-6 text-muted-foreground">
      <circle cx="10" cy="10" r="8" stroke="currentColor" strokeWidth="1.4" />
      <path d="M7.8 7.7a2.2 2.2 0 1 1 3.2 2c-.7.4-1 .8-1 1.6v.2" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" />
      <circle cx="10" cy="14.2" r="0.9" fill="currentColor" stroke="none" />
    </svg>
  );
}

function LayersIcon() {
  return (
    <svg viewBox="0 0 16 16" fill="none" aria-hidden className="h-4 w-4">
      <path d="m8 2 6 3-6 3-6-3 6-3Z" stroke="currentColor" strokeWidth="1.2" strokeLinejoin="round" />
      <path d="m2 8 6 3 6-3M2 11l6 3 6-3" stroke="currentColor" strokeWidth="1.2" strokeLinejoin="round" />
    </svg>
  );
}

function TargetIcon() {
  return (
    <svg viewBox="0 0 16 16" fill="none" aria-hidden className="h-4 w-4">
      <circle cx="8" cy="8" r="6" stroke="currentColor" strokeWidth="1.2" />
      <circle cx="8" cy="8" r="3" stroke="currentColor" strokeWidth="1.2" />
      <circle cx="8" cy="8" r="0.8" fill="currentColor" stroke="none" />
    </svg>
  );
}

function BranchIcon() {
  return (
    <svg viewBox="0 0 16 16" fill="none" aria-hidden className="h-4 w-4">
      <circle cx="4" cy="3.5" r="1.5" stroke="currentColor" strokeWidth="1.2" />
      <circle cx="4" cy="12.5" r="1.5" stroke="currentColor" strokeWidth="1.2" />
      <circle cx="12" cy="6" r="1.5" stroke="currentColor" strokeWidth="1.2" />
      <path d="M4 5v6M12 7.5c0 2.5-3 2-5.5 3" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" />
    </svg>
  );
}

function KeyIcon() {
  return (
    <svg viewBox="0 0 16 16" fill="none" aria-hidden className="h-4 w-4">
      <circle cx="5.5" cy="5.5" r="3" stroke="currentColor" strokeWidth="1.2" />
      <path d="m7.7 7.7 5.3 5.3M11 11l1.8-1.8M9 13l1.5-1.5" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" />
    </svg>
  );
}

function FlaskIcon() {
  return (
    <svg viewBox="0 0 16 16" fill="none" aria-hidden className="h-4 w-4">
      <path d="M6 2h4M7 2v4.5L3.2 12a1.5 1.5 0 0 0 1.3 2.3h7a1.5 1.5 0 0 0 1.3-2.3L9 6.5V2" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" strokeLinejoin="round" />
      <path d="M5 10h6" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" />
    </svg>
  );
}

function GitIcon() {
  return (
    <svg viewBox="0 0 16 16" fill="none" aria-hidden className="h-4 w-4">
      <circle cx="4" cy="4" r="1.6" stroke="currentColor" strokeWidth="1.2" />
      <circle cx="4" cy="12" r="1.6" stroke="currentColor" strokeWidth="1.2" />
      <circle cx="12" cy="4" r="1.6" stroke="currentColor" strokeWidth="1.2" />
      <path d="M4 5.6v4.8M12 5.6c0 3-4 2.5-6.5 4" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" />
    </svg>
  );
}

function FolderIcon() {
  return (
    <svg viewBox="0 0 16 16" fill="none" aria-hidden className="h-4 w-4">
      <path d="M2 4a1 1 0 0 1 1-1h3.5l1.5 2H13a1 1 0 0 1 1 1v6a1 1 0 0 1-1 1H3a1 1 0 0 1-1-1V4Z" stroke="currentColor" strokeWidth="1.2" strokeLinejoin="round" />
    </svg>
  );
}

function ArchiveIcon() {
  return (
    <svg viewBox="0 0 16 16" fill="none" aria-hidden className="h-4 w-4">
      <rect x="2" y="2.5" width="12" height="3.5" rx="0.5" stroke="currentColor" strokeWidth="1.2" />
      <path d="M3 6v7a.5.5 0 0 0 .5.5h9a.5.5 0 0 0 .5-.5V6M6.5 8.5h3" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" />
    </svg>
  );
}

// ---------------------------------------------------------------------------

function GroupLabel({ children }: { children: React.ReactNode }) {
  return <p className="text-xs font-medium uppercase tracking-[0.15em] text-muted-foreground">{children}</p>;
}

function Section({ id, title, children }: { id: string; title: string; children: React.ReactNode }) {
  return (
    <section id={id} className="scroll-mt-20 space-y-3">
      <h2 className="text-xl font-medium tracking-tight">
        <a href={`#${id}`} className="focus-ring rounded-sm hover:underline">
          {title}
        </a>
      </h2>
      {children}
    </section>
  );
}

export default function HelpPage() {
  return (
    <article className="mx-auto max-w-3xl space-y-10">
      <div className="flex items-start gap-3">
        <span className="mt-1">
          <QuestionIcon />
        </span>
        <div>
          <h1 className="text-2xl font-medium tracking-tight">Help</h1>
          <p className="mt-1 text-sm text-muted-foreground">
            What the numbers mean, which NIST standards back each recommendation, and answers to common questions.
          </p>
        </div>
      </div>

      <nav aria-label="On this page" className="flex flex-wrap gap-1 rounded-lg border bg-muted/40 p-1">
        {NAV.map((item) => (
          <a
            key={item.id}
            href={`#${item.id}`}
            className="focus-ring rounded-md px-3 py-1.5 text-sm text-muted-foreground transition-colors hover:bg-background hover:text-foreground"
          >
            {item.label}
          </a>
        ))}
      </nav>

      <div className="space-y-8">
        <GroupLabel>Scoring</GroupLabel>

        <Section id="risk-score" title="Risk score">
          <div className="grid gap-4 sm:grid-cols-2">
            <div className="rounded-lg border p-4">
              <p className="font-mono text-2xl">0–100</p>
              <p className="text-sm text-muted-foreground">higher = worse</p>
              <p className="mt-2 text-xs text-muted-foreground">Deterministic, from scoring formula v1.</p>
            </div>
            <div className="rounded-lg border p-4">
              <p className="text-sm font-medium">Weighted sum of</p>
              <p className="mt-1 text-sm text-muted-foreground">
                algorithm risk · usage criticality · exposure · data sensitivity · environment
              </p>
            </div>
          </div>
          <p className="text-sm">
            Every finding gets a deterministic <strong>0–100 risk score</strong> (higher = worse) from scoring formula
            v1: a weighted sum of algorithm risk (e.g.{' '}
            <code className="rounded bg-muted px-1.5 py-0.5 font-mono text-xs">MD5 = 9</code>,{' '}
            <code className="rounded bg-muted px-1.5 py-0.5 font-mono text-xs">RSA = 8</code>), usage criticality (key
            exchange &gt; hashing &gt; test helper), exposure, data sensitivity, and environment. The score shown on
            the project gauge is the <strong>most severe finding</strong> in the latest scan — one critical usage keeps
            the gauge high no matter how many low findings surround it. In the OSS build the context factors (exposure,
            environment, …) use neutral values; an external enrichment pipeline can supply real ones.
          </p>
        </Section>

        <Section id="severity" title="Severity">
          <div className="flex flex-wrap gap-2">
            {SEVERITIES.map((s) => (
              <SeverityBadge key={s} value={s} />
            ))}
          </div>
          <p className="text-sm">
            Severity is assigned by the detection rule that matched and reflects the algorithm and usage pattern in
            isolation — quantum-broken public-key usage is critical, weakened or deprecated primitives rank lower. It
            is independent of the risk score: severity says what kind of problem this is, the risk score folds in how
            and where it is used.
          </p>
        </Section>

        <Section id="crypto-agility" title="Crypto agility">
          <p className="text-sm">
            The crypto-agility score (<strong>0–100, higher = better</strong>) predicts how mechanically replaceable
            your cryptography is — the cost of the migration, independent of how dangerous the findings are. It is the
            sum of four equally weighted sub-metrics, each 0–25:
          </p>
          <div className="grid gap-3 sm:grid-cols-2">
            {AGILITY_METRICS.map((m) => (
              <div key={m.title} className="rounded-lg border p-4">
                <h3 className="flex items-center gap-2 text-sm font-medium">
                  <span aria-hidden className="text-muted-foreground">
                    {m.icon}
                  </span>
                  {m.title}
                </h3>
                <p className="mt-1.5 text-sm text-muted-foreground">{m.body}</p>
              </div>
            ))}
          </div>
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b text-left text-xs uppercase tracking-wide text-muted-foreground">
                <th className="py-2 pr-4 font-medium">Score</th>
                <th className="py-2 pr-4 font-medium">Grade</th>
                <th className="py-2 font-medium">Migration disposition</th>
              </tr>
            </thead>
            <tbody>
              {AGILITY_GRADES.map((g) => (
                <tr key={g.grade} className="border-b last:border-0">
                  <td className="py-2.5 pr-4 font-mono text-xs">{g.range}</td>
                  <td className="py-2.5 pr-4">
                    <span className={cn('rounded-md px-2 py-0.5 text-xs font-medium ring-1 ring-inset', g.pill)}>
                      {g.grade}
                    </span>
                  </td>
                  <td className="py-2.5 text-muted-foreground">{g.meaning}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Section>

        <GroupLabel>Reference</GroupLabel>

        <Section id="nist-standards" title="Algorithm families & NIST standards">
          <p className="text-sm">
            Findings are grouped into families that share a threat model and a migration target. The same references
            apply to every finding in a family, which is why expanded findings of the same algorithm cite the same
            standards.
          </p>
          <FamilyGrid />
        </Section>

        <GroupLabel>How it works</GroupLabel>

        <Section id="scanning" title="Scanning">
          <p className="text-sm">
            A scan runs the static analyzer over the project source with the community rule pack (725+ rules, 47
            packs, 31 languages), then recomputes the findings list, risk score, and crypto-agility grade. Four source
            kinds are supported:
          </p>
          <div className="grid gap-3 sm:grid-cols-2">
            {SOURCES.map((s) => (
              <div key={s.title} className="rounded-lg border p-4">
                <h3 className="flex items-center gap-2 text-sm font-medium">
                  <span aria-hidden className="text-muted-foreground">
                    {s.icon}
                  </span>
                  {s.title}
                </h3>
                <p className="mt-1.5 text-sm text-muted-foreground">{s.body}</p>
              </div>
            ))}
          </div>
          <p className="text-sm">
            Everything runs locally; see the{' '}
            <Link href="/about" className="focus-ring rounded-sm underline underline-offset-2">
              About page
            </Link>{' '}
            for the full capability list.
          </p>
        </Section>

        <GroupLabel>Common questions</GroupLabel>

        <Section id="faq" title="FAQ">
          <FaqAccordion items={FAQ} />
        </Section>
      </div>
    </article>
  );
}
