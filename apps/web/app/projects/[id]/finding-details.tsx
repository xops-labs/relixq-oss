// Expanded explanation panel for a finding row: why the rule fired (with the
// rule's own message when provided), the flagged code in a dark editor-style
// block, a recommendation callout, and a compact standards line. The full
// NIST table lives on /help.

import Link from 'next/link';
import type { Finding } from '@/lib/types';
import { familyFor } from '@/lib/crypto-help';

// ---------------------------------------------------------------------------
// Prose enrichment: wrap code-looking tokens in chips. Conservative on
// purpose — dotted identifiers (crypto.createECDH), all-caps hyphenated
// names (ML-KEM, AES-256), and caps-with-digits names (X25519MLKEM768).
// Plain hyphenated English ("quantum-vulnerable") stays untouched.
// ---------------------------------------------------------------------------

// Dotted segments need >= 2 chars so abbreviations like "e.g." stay prose.
const PROSE_TOKEN =
  /[A-Za-z_$][\w$]+(?:\.[A-Za-z_$][\w$]+)+(?:\(\))?|\b[A-Z]{2,}[0-9]*(?:-[A-Z0-9]+)+\b|\b[A-Z][A-Z0-9]*\d[A-Z0-9]*\b/g;

function RichText({ text }: { text: string }) {
  const parts: React.ReactNode[] = [];
  let last = 0;
  for (const m of text.matchAll(PROSE_TOKEN)) {
    const i = m.index ?? 0;
    if (i > last) parts.push(text.slice(last, i));
    parts.push(
      <code key={i} className="rounded bg-muted px-1.5 py-0.5 font-mono text-[0.85em]">
        {m[0]}
      </code>,
    );
    last = i + m[0].length;
  }
  if (last < text.length) parts.push(text.slice(last));
  return <>{parts}</>;
}

// ---------------------------------------------------------------------------
// Minimal syntax highlighting for the snippet block. Regex tokenizer:
// comments, strings, keywords, declared names, calls, numbers.
// ---------------------------------------------------------------------------

const CODE_TOKEN =
  /(\/\/[^\n]*|\/\*[\s\S]*?\*\/|(?<!\S)#[^\n]*)|('(?:[^'\\\n]|\\.)*'|"(?:[^"\\\n]|\\.)*"|`(?:[^`\\]|\\.)*`)|\b(const|let|var|function|return|new|class|import|export|from|require|if|else|for|while|def|fn|func|use|public|private|protected|static|void|namespace|using|package|type|interface|async|await)\b|([A-Za-z_$][\w$]*)(?=\s*\()|\b(\d[\w]*)\b|([A-Za-z_$][\w$]*)/g;

const DECL_KEYWORDS = new Set(['const', 'let', 'var', 'function', 'def', 'fn', 'func', 'class', 'type', 'interface']);

function HighlightedCode({ code }: { code: string }) {
  const parts: React.ReactNode[] = [];
  let last = 0;
  let declNext = false;
  for (const m of code.matchAll(CODE_TOKEN)) {
    const i = m.index ?? 0;
    if (i > last) parts.push(code.slice(last, i));
    const [comment, str, keyword, call, num, ident] = [m[1], m[2], m[3], m[4], m[5], m[6]];
    let cls = '';
    if (comment) cls = 'italic text-slate-500';
    else if (str) cls = 'text-amber-300';
    else if (keyword) {
      cls = 'text-violet-400';
      declNext = DECL_KEYWORDS.has(keyword);
    } else if (call) {
      cls = 'text-yellow-300';
      declNext = false;
    } else if (num) cls = 'text-cyan-300';
    else if (ident) {
      if (declNext) cls = 'text-sky-300';
      declNext = false;
    }
    parts.push(
      cls ? (
        <span key={i} className={cls}>
          {m[0]}
        </span>
      ) : (
        m[0]
      ),
    );
    last = i + m[0].length;
  }
  if (last < code.length) parts.push(code.slice(last));
  return <>{parts}</>;
}

/** Display cleanup: drop doc-comment asterisks and common indentation. */
function snippetLines(snippet: string): string[] {
  let lines = snippet.replace(/\r\n?/g, '\n').split('\n');
  while (lines.length > 0 && lines[lines.length - 1].trim() === '') lines.pop();
  while (lines.length > 0 && lines[0].trim() === '') lines.shift();
  const nonEmpty = lines.filter((l) => l.trim() !== '');
  if (nonEmpty.length > 0 && nonEmpty.every((l) => /^\s*\*/.test(l))) {
    lines = lines.map((l) => l.replace(/^\s*\*\s?/, ''));
  }
  const indents = lines.filter((l) => l.trim() !== '').map((l) => (l.match(/^\s*/) as RegExpMatchArray)[0].length);
  const dedent = indents.length > 0 ? Math.min(...indents) : 0;
  return lines.map((l) => l.slice(dedent));
}

// ---------------------------------------------------------------------------

function FlagIcon() {
  return (
    <svg viewBox="0 0 16 16" fill="none" aria-hidden className="h-3.5 w-3.5 text-red-600">
      <path d="M3.5 14.5v-12" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
      <path d="M3.5 2.5h8.6l-2.2 3 2.2 3H3.5" fill="currentColor" stroke="currentColor" strokeWidth="1" strokeLinejoin="round" />
    </svg>
  );
}

function BulbIcon() {
  return (
    <svg viewBox="0 0 16 16" fill="none" aria-hidden className="h-3.5 w-3.5">
      <path d="M8 1.5a4.5 4.5 0 0 1 2.5 8.24c-.5.36-.8.9-.8 1.46v.3H6.3v-.3c0-.56-.3-1.1-.8-1.46A4.5 4.5 0 0 1 8 1.5Z" stroke="currentColor" strokeWidth="1.3" />
      <path d="M6.5 13.5h3M7 15h2" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round" />
    </svg>
  );
}

function CodeIcon() {
  return (
    <svg viewBox="0 0 16 16" fill="none" aria-hidden className="h-3.5 w-3.5">
      <path d="m5 5-3 3 3 3M11 5l3 3-3 3" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

function ExternalIcon() {
  return (
    <svg viewBox="0 0 16 16" fill="none" aria-hidden className="inline h-3 w-3">
      <path d="M6.5 3.5H3.5a1 1 0 0 0-1 1v8a1 1 0 0 0 1 1h8a1 1 0 0 0 1-1V9.5M9.5 2.5h4v4M13 3 7.5 8.5" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

function MetaChip({ children }: { children: React.ReactNode }) {
  return (
    <span className="rounded-md bg-muted px-2 py-1 font-mono text-xs text-muted-foreground">{children}</span>
  );
}

// ---------------------------------------------------------------------------

export function FindingDetails({ finding }: { finding: Finding }) {
  const family = familyFor(finding.algorithm);
  const fileName = finding.filePath.split('/').pop() ?? finding.filePath;
  const lines = finding.snippet ? snippetLines(finding.snippet) : [];
  const lineNoWidth = String(finding.lineNumber + Math.max(0, lines.length - 1)).length;

  return (
    <div className="space-y-4 px-6 py-5 text-sm sm:px-10">
      <section>
        <h4 className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
          <FlagIcon />
          Why this was flagged
        </h4>
        <p className="mt-2 leading-relaxed">
          <RichText text={finding.message?.trim() || family.why} />
        </p>
        <div className="mt-3 flex flex-wrap gap-2">
          <MetaChip>rule {finding.ruleId}</MetaChip>
          {finding.category && <MetaChip>{finding.category}</MetaChip>}
          <MetaChip>{finding.language}</MetaChip>
        </div>
      </section>

      {lines.length > 0 && (
        <div className="overflow-hidden rounded-lg bg-slate-950">
          <div className="flex items-center justify-between gap-3 border-b border-slate-800 px-4 py-2">
            <span className="flex items-center gap-2 font-mono text-xs text-slate-400">
              <CodeIcon />
              flagged code
            </span>
            <span className="truncate font-mono text-xs text-slate-500">
              {fileName}:{finding.lineNumber}
            </span>
          </div>
          <div className="max-h-48 overflow-y-auto px-4 py-3 font-mono text-xs leading-relaxed text-slate-100">
            {lines.map((line, i) => (
              <div key={i} className="flex gap-4">
                <span
                  aria-hidden
                  className="shrink-0 select-none text-right text-slate-600"
                  style={{ minWidth: `${lineNoWidth}ch` }}
                >
                  {finding.lineNumber + i}
                </span>
                {/* break-all: a minified line must never widen the table */}
                <code className="whitespace-pre-wrap break-all">
                  <HighlightedCode code={line} />
                </code>
              </div>
            ))}
          </div>
        </div>
      )}

      <section className="rounded-lg border border-emerald-600/30 bg-emerald-500/10 px-4 py-3">
        <h4 className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wide text-emerald-700 dark:text-emerald-400">
          <BulbIcon />
          Recommendation
        </h4>
        <p className="mt-2 leading-relaxed">
          <RichText text={finding.recommendation?.trim() || family.fix} />
        </p>
      </section>

      <div className="flex flex-wrap items-center justify-between gap-2 border-t pt-3 text-xs text-muted-foreground">
        <span>
          Standards:{' '}
          {family.refs.map((ref, i) => (
            <span key={ref.url}>
              {i > 0 && <span className="mx-1.5">·</span>}
              <a
                href={ref.url}
                target="_blank"
                rel="noreferrer"
                className="focus-ring rounded-sm text-foreground underline decoration-border underline-offset-2 hover:decoration-foreground"
              >
                {ref.short}
              </a>
            </span>
          ))}
        </span>
        <Link
          href="/help#nist-standards"
          className="focus-ring flex items-center gap-1 rounded-sm font-medium text-primary underline underline-offset-2 hover:opacity-80"
        >
          Learn more <ExternalIcon />
        </Link>
      </div>
    </div>
  );
}
