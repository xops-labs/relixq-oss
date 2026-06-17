// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.
import { cn } from '../lib/cn';

interface CodeViewerBase {
  /** 1-based line number of the first rendered line. */
  startLine: number;
  /** 1-based absolute line number to emphasize (the finding location). */
  highlightLine?: number;
  className?: string;
}

interface CodeViewerFromText extends CodeViewerBase {
  /** Raw source slice; rendered with a plain monospace fallback. */
  code: string;
  html?: never;
}

interface CodeViewerFromHtml extends CodeViewerBase {
  /**
   * Pre-highlighted HTML (e.g. produced by the host app's Shiki on the
   * server). Each line node should carry `data-line="<absolute>"`; the
   * matching line gets the `.relixq-line-hl` class. Trusted input only.
   */
  html: string;
  code?: never;
}

export type CodeViewerProps = CodeViewerFromText | CodeViewerFromHtml;

const HL =
  '[&_.relixq-line-hl]:bg-severity-critical/10 [&_.relixq-line-hl]:!border-l-2 [&_.relixq-line-hl]:!border-severity-critical [&_.relixq-line-hl]:pl-2';

/**
 * Syntax-highlighted finding context. Deliberately highlighter-agnostic: pass
 * `html` when the host has already run Shiki (keeps this package free of a
 * heavy highlighter dependency), or pass `code` for a plain monospace render
 * with line numbers and an emphasized line.
 */
export function CodeViewer(props: CodeViewerProps) {
  if ('html' in props && props.html !== undefined) {
    return (
      <div
        className={cn(
          'overflow-hidden rounded-md border border-border [&_pre]:m-0 [&_pre]:overflow-x-auto [&_pre]:p-4 [&_pre]:text-xs',
          HL,
          props.className,
        )}
        // Trusted, server-generated highlight markup.
        dangerouslySetInnerHTML={{ __html: props.html }}
      />
    );
  }

  const { code, startLine, highlightLine, className } = props;
  const lines = code.replace(/\n$/, '').split('\n');
  return (
    <div className={cn('overflow-hidden rounded-md border border-border', className)}>
      <pre className="m-0 overflow-x-auto p-4 text-xs">
        <code>
          {lines.map((line, i) => {
            const absolute = startLine + i;
            const isHl = absolute === highlightLine;
            return (
              <span
                key={absolute}
                data-line={absolute}
                className={cn(
                  'block',
                  isHl &&
                    'relixq-line-hl border-l-2 border-severity-critical bg-severity-critical/10 pl-2',
                )}
              >
                <span aria-hidden className="mr-4 inline-block w-8 select-none text-right text-muted-foreground">
                  {absolute}
                </span>
                {line || ' '}
              </span>
            );
          })}
        </code>
      </pre>
    </div>
  );
}
