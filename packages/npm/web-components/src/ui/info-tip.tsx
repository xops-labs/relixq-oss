// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.
import * as React from 'react';
import { cn } from '../lib/cn';

export interface InfoTipProps {
  /** Tooltip body. Keep it to a sentence or two. */
  text: React.ReactNode;
  /** Accessible name for the icon button. */
  label?: string;
  /** Which side of the icon the tooltip opens on. */
  side?: 'top' | 'bottom';
  /** Optional "Learn more →" target rendered at the end of the tooltip. */
  moreHref?: string;
  className?: string;
}

/**
 * Information icon with a hover / keyboard-focus tooltip. CSS-only (no client
 * JS), so it renders fine inside React Server Components — same approach as
 * ScoreGauge. Don't place it inside an `overflow: auto` container (e.g. the
 * Table scroll wrapper): the absolutely-positioned panel would be clipped.
 * Use a native `title` attribute there instead.
 *
 * The gap between icon and panel is padding on the panel wrapper (not margin),
 * so the pointer can travel into the panel — required for `moreHref` links to
 * be clickable.
 */
export function InfoTip({ text, label = 'More information', side = 'top', moreHref, className }: InfoTipProps) {
  const id = React.useId();
  return (
    <span className={cn('group relative inline-flex', className)}>
      <button
        type="button"
        aria-label={label}
        aria-describedby={id}
        className="focus-ring inline-flex h-4 w-4 items-center justify-center rounded-full text-muted-foreground transition-colors hover:text-foreground"
      >
        <svg viewBox="0 0 16 16" fill="none" className="h-3.5 w-3.5" aria-hidden>
          <circle cx="8" cy="8" r="6.5" stroke="currentColor" />
          <path d="M8 7.4v3.4" stroke="currentColor" strokeLinecap="round" />
          <circle cx="8" cy="5.1" r="0.9" fill="currentColor" stroke="none" />
        </svg>
      </button>
      <span
        id={id}
        role="tooltip"
        className={cn(
          'invisible absolute left-1/2 z-50 -translate-x-1/2 opacity-0 transition-opacity',
          'group-focus-within:visible group-focus-within:opacity-100 group-hover:visible group-hover:opacity-100',
          side === 'top' ? 'bottom-full pb-2' : 'top-full pt-2',
        )}
      >
        <span
          className={cn(
            // font/case resets so the panel reads the same inside uppercase or mono contexts
            'block w-64 rounded-md bg-foreground px-3 py-2 text-left text-xs font-normal normal-case leading-relaxed tracking-normal text-background shadow-md',
          )}
        >
          {text}
          {moreHref && (
            <>
              {' '}
              <a
                href={moreHref}
                className="focus-ring whitespace-nowrap rounded-sm underline underline-offset-2 hover:opacity-80"
              >
                Learn more →
              </a>
            </>
          )}
        </span>
      </span>
    </span>
  );
}
