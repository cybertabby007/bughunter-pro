import { ScanStats, SEVERITY_COLORS } from "@/lib/types";

interface Props {
  stats: ScanStats;
}

const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;

export default function StatsBar({ stats }: Props) {
  const total = stats.severity.total || 1;

  return (
    <div className="rounded-lg p-4" style={{ background: "var(--surface)", border: "1px solid var(--border)" }}>
      <div className="flex items-center gap-3 mb-3">
        {SEVERITIES.map(sev => (
          <div key={sev} className="flex items-center gap-1.5">
            <div className="w-2.5 h-2.5 rounded-full" style={{ background: SEVERITY_COLORS[sev] }} />
            <span className="text-lg font-bold" style={{ color: SEVERITY_COLORS[sev] }}>
              {stats.severity[sev] || 0}
            </span>
            <span className="text-xs uppercase" style={{ color: "var(--muted)" }}>{sev}</span>
          </div>
        ))}
        <div className="ml-auto text-sm font-bold" style={{ color: "white" }}>
          {stats.severity.total} total
        </div>
      </div>

      {/* Stacked bar */}
      <div className="h-2 rounded-full overflow-hidden flex" style={{ background: "var(--surface-2)" }}>
        {SEVERITIES.map(sev => {
          const count = stats.severity[sev] || 0;
          const pct = (count / total) * 100;
          return pct > 0 ? (
            <div key={sev} style={{ width: `${pct}%`, background: SEVERITY_COLORS[sev] }}
                 title={`${sev}: ${count}`} />
          ) : null;
        })}
      </div>
    </div>
  );
}
