import * as React from 'react';
import { cn, InfoTip } from '@relix-q/web-components';

export function Button({ className, ...props }: React.ButtonHTMLAttributes<HTMLButtonElement>) {
  return (
    <button
      className={cn(
        'inline-flex items-center justify-center rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground transition hover:opacity-90 focus-ring disabled:pointer-events-none disabled:opacity-50',
        className,
      )}
      {...props}
    />
  );
}

export function Input({ className, ...props }: React.InputHTMLAttributes<HTMLInputElement>) {
  return (
    <input
      className={cn(
        'w-full rounded-md border border-input bg-background px-3 py-2 text-sm shadow-sm focus-ring',
        className,
      )}
      {...props}
    />
  );
}

export function Label({ className, ...props }: React.LabelHTMLAttributes<HTMLLabelElement>) {
  return <label className={cn('mb-1 block text-sm font-medium', className)} {...props} />;
}

export function Field({
  label,
  hint,
  children,
}: {
  label: string;
  /** Optional info-icon tooltip rendered next to the label. */
  hint?: React.ReactNode;
  children: React.ReactNode;
}) {
  return (
    <div className="space-y-1">
      {hint ? (
        <span className="mb-1 flex items-center gap-1.5">
          <Label className="mb-0">{label}</Label>
          <InfoTip text={hint} label={`About ${label}`} side="bottom" />
        </span>
      ) : (
        <Label>{label}</Label>
      )}
      {children}
    </div>
  );
}
