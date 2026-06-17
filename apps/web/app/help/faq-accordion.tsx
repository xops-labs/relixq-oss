'use client';

// Accessible FAQ accordion. Answer bodies arrive as server-rendered nodes via
// props, so the copy itself stays in the server page.

import { useState } from 'react';
import { cn } from '@relix-q/web-components';

export interface FaqItem {
  id: string;
  question: string;
  answer: React.ReactNode;
}

export function FaqAccordion({ items }: { items: FaqItem[] }) {
  const [open, setOpen] = useState<ReadonlySet<string>>(new Set());

  function toggle(id: string) {
    setOpen((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  return (
    <div className="divide-y rounded-lg border">
      {items.map((item) => {
        const isOpen = open.has(item.id);
        return (
          <div key={item.id}>
            <h3>
              <button
                type="button"
                id={`faq-${item.id}-toggle`}
                aria-expanded={isOpen}
                aria-controls={`faq-${item.id}-panel`}
                onClick={() => toggle(item.id)}
                className="focus-ring flex w-full items-center justify-between gap-3 rounded-md px-4 py-3 text-left text-sm font-medium"
              >
                {item.question}
                <svg
                  viewBox="0 0 16 16"
                  fill="none"
                  aria-hidden
                  className={cn('h-4 w-4 shrink-0 text-muted-foreground transition-transform', isOpen && 'rotate-180')}
                >
                  <path d="m4 6 4 4 4-4" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
                </svg>
              </button>
            </h3>
            {isOpen && (
              <div
                id={`faq-${item.id}-panel`}
                role="region"
                aria-labelledby={`faq-${item.id}-toggle`}
                className="px-4 pb-4 text-sm text-muted-foreground"
              >
                {item.answer}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}
