import { Severity, SEVERITY_COLORS, SEVERITY_BG } from "@/lib/types";

interface Props {
  severity: Severity;
  size?: "sm" | "md";
}

export default function SeverityBadge({ severity, size = "md" }: Props) {
  const color = SEVERITY_COLORS[severity] || "#888";
  const bg    = SEVERITY_BG[severity]    || "rgba(136,136,136,0.15)";
  const pad   = size === "sm" ? "px-1.5 py-0.5 text-[10px]" : "px-2.5 py-1 text-xs";

  return (
    <span className={`${pad} rounded font-bold uppercase tracking-wide inline-block`}
          style={{ color, background: bg, border: `1px solid ${color}33` }}>
      {severity}
    </span>
  );
}
