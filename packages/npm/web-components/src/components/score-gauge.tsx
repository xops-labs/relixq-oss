// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.
import { cn } from '../lib/cn';

export interface ScoreGaugeProps {
  /** 0..100 score. Higher is healthier (PQC readiness) by default. */
  value: number;
  /**
   * 'readiness' (default) treats high as good (green at the top);
   * 'risk' inverts the color band so high is bad (red at the top).
   */
  mode?: 'readiness' | 'risk';
  /** Diameter in px. */
  size?: number;
  /** Stroke thickness in px. */
  thickness?: number;
  /** Accessible label; falls back to a generated one. */
  ariaLabel?: string;
  /** Caption rendered under the numeric value. */
  label?: string;
  className?: string;
}

/** Map a 0..100 value to a severity color token, respecting the mode. */
function bandColor(value: number, mode: 'readiness' | 'risk'): string {
  const v = mode === 'risk' ? 100 - value : value;
  if (v >= 80) return 'hsl(var(--severity-low))';
  if (v >= 60) return 'hsl(var(--severity-info))';
  if (v >= 40) return 'hsl(var(--severity-medium))';
  if (v >= 20) return 'hsl(var(--severity-high))';
  return 'hsl(var(--severity-critical))';
}

/**
 * Pure-SVG 0..100 gauge. Maps directly onto RelixQ.Scoring readiness output.
 * Self-contained — no charting library — so it is safe to ship in a portable
 * component package and render on the server or client.
 */
export function ScoreGauge({
  value,
  mode = 'readiness',
  size = 140,
  thickness = 12,
  ariaLabel,
  label,
  className,
}: ScoreGaugeProps) {
  const clamped = Math.max(0, Math.min(100, value));
  const radius = (size - thickness) / 2;
  const circumference = 2 * Math.PI * radius;
  // Leave a 90° gap at the bottom; sweep the remaining 270°.
  const sweep = 0.75;
  const arcLength = circumference * sweep;
  const filled = arcLength * (clamped / 100);
  const color = bandColor(clamped, mode);
  const center = size / 2;

  return (
    <div
      className={cn('inline-flex flex-col items-center', className)}
      role="img"
      aria-label={ariaLabel ?? `${mode === 'risk' ? 'Risk' : 'Readiness'} score ${clamped} of 100`}
    >
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
        <g transform={`rotate(135 ${center} ${center})`}>
          <circle
            cx={center}
            cy={center}
            r={radius}
            fill="none"
            stroke="hsl(var(--muted))"
            strokeWidth={thickness}
            strokeLinecap="round"
            strokeDasharray={`${arcLength} ${circumference}`}
          />
          <circle
            cx={center}
            cy={center}
            r={radius}
            fill="none"
            stroke={color}
            strokeWidth={thickness}
            strokeLinecap="round"
            strokeDasharray={`${filled} ${circumference}`}
          />
        </g>
        <text
          x={center}
          y={center}
          textAnchor="middle"
          dominantBaseline="central"
          className="fill-foreground font-mono font-bold"
          style={{ fontSize: size * 0.26 }}
        >
          {Math.round(clamped)}
        </text>
      </svg>
      {label && <span className="mt-1 text-xs text-muted-foreground">{label}</span>}
    </div>
  );
}
