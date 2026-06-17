// Server-rendered SVG donut for a labelled count breakdown (files per
// language, findings per algorithm, ...). Pure SVG (no client JS), same
// approach as the web-components ScoreGauge.

const PALETTE = [
  '#2563eb', // blue
  '#16a34a', // green
  '#d97706', // amber
  '#dc2626', // red
  '#7c3aed', // violet
  '#0891b2', // cyan
  '#db2777', // pink
  '#65a30d', // lime
];
const OTHER_COLOR = '#94a3b8'; // slate for the grouped remainder

const R = 40;
const STROKE = 18;
const C = 2 * Math.PI * R;
const MAX_SEGMENTS = PALETTE.length;

export function BreakdownPie({
  total,
  data,
  ariaLabel,
}: {
  total: number;
  data: Record<string, number>;
  ariaLabel: string;
}) {
  const sorted = Object.entries(data).sort((a, b) => b[1] - a[1]);
  const shown = sorted.slice(0, MAX_SEGMENTS);
  const rest = sorted.slice(MAX_SEGMENTS);
  const segments = [
    ...shown.map(([label, count], i) => ({ label, count, color: PALETTE[i] })),
    ...(rest.length > 0
      ? [{ label: 'other', count: rest.reduce((n, [, c]) => n + c, 0), color: OTHER_COLOR }]
      : []),
  ];
  const sum = segments.reduce((n, s) => n + s.count, 0) || 1;

  let cumulative = 0;
  const arcs = segments.map((s) => {
    const start = cumulative / sum;
    cumulative += s.count;
    return { ...s, frac: s.count / sum, start };
  });

  return (
    // flex-wrap: in narrow cards (5-up grid) the legend drops below the donut
    // instead of truncating beside it.
    <div className="flex flex-wrap items-center gap-4">
      <svg viewBox="0 0 100 100" className="h-28 w-28 shrink-0" role="img" aria-label={ariaLabel}>
        {arcs.map((a) => (
          <circle
            key={a.label}
            cx="50"
            cy="50"
            r={R}
            fill="none"
            stroke={a.color}
            strokeWidth={STROKE}
            strokeDasharray={`${a.frac * C} ${C - a.frac * C}`}
            strokeDashoffset={-a.start * C}
            transform="rotate(-90 50 50)"
          >
            <title>{`${a.label}: ${a.count}`}</title>
          </circle>
        ))}
        <text x="50" y="50" textAnchor="middle" dominantBaseline="central" className="fill-foreground font-mono" fontSize="22">
          {total}
        </text>
      </svg>
      <ul className="min-w-0 space-y-1 text-sm">
        {arcs.map((a) => (
          <li key={a.label} className="flex items-center gap-2">
            <span aria-hidden className="h-2.5 w-2.5 shrink-0 rounded-full" style={{ backgroundColor: a.color }} />
            <span className="truncate text-muted-foreground">
              {a.label} <span className="font-mono text-foreground">{a.count}</span>
            </span>
          </li>
        ))}
      </ul>
    </div>
  );
}
