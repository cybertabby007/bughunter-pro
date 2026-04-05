"use client";
import { useState } from "react";
import { ChevronDown, ChevronUp, Copy, Check, ExternalLink } from "lucide-react";
import { Finding, SEVERITY_COLORS } from "@/lib/types";
import SeverityBadge from "./SeverityBadge";

const TYPE_LABELS: Record<string, string> = {
  xss: "XSS", sqli: "SQLi", ssrf: "SSRF", cors: "CORS",
  redirect: "Open Redirect", header: "Headers",
  exposed_file: "Exposed File", secret_in_js: "Secret Leak",
  takeover: "Subdomain Takeover", subdomain: "Subdomain",
  open_port: "Open Port", admin_panel: "Admin Panel",
  api_endpoint: "API Endpoint",
};

interface Props {
  finding: Finding;
  index: number;
}

export default function FindingCard({ finding, index }: Props) {
  const [expanded, setExpanded] = useState(false);
  const [copied, setCopied] = useState(false);
  const color = SEVERITY_COLORS[finding.severity] || "#888";

  const handleCopy = () => {
    const text = JSON.stringify(finding, null, 2);
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="rounded-lg overflow-hidden animate-fade-in"
         style={{ background: "var(--surface)", border: `1px solid var(--border)`, borderLeft: `3px solid ${color}` }}>
      {/* Header row */}
      <div className="flex items-start gap-3 p-4 cursor-pointer hover:bg-white/5 transition-colors"
           onClick={() => setExpanded(!expanded)}>
        <span className="text-xs mt-0.5 font-mono" style={{ color: "var(--muted)" }}>
          #{String(index).padStart(3, "0")}
        </span>
        <div className="flex-1 min-w-0">
          <div className="flex flex-wrap items-center gap-2 mb-1">
            <SeverityBadge severity={finding.severity} />
            <span className="text-xs px-1.5 py-0.5 rounded"
                  style={{ background: "var(--surface-2)", color: "var(--muted)", border: "1px solid var(--border)" }}>
              {TYPE_LABELS[finding.type] || finding.type}
            </span>
          </div>
          <p className="font-medium text-sm" style={{ color: "white" }}>{finding.title}</p>
          {!expanded && (
            <p className="text-xs mt-1 line-clamp-2" style={{ color: "var(--muted)" }}>
              {finding.description}
            </p>
          )}
        </div>
        <div className="flex items-center gap-2 ml-2 shrink-0">
          <button onClick={(e) => { e.stopPropagation(); handleCopy(); }}
                  className="p-1.5 rounded transition-colors hover:bg-white/10"
                  title="Copy finding">
            {copied ? <Check size={13} color="var(--low)" /> : <Copy size={13} color="var(--muted)" />}
          </button>
          {expanded ? <ChevronUp size={14} color="var(--muted)" /> : <ChevronDown size={14} color="var(--muted)" />}
        </div>
      </div>

      {/* Expanded detail */}
      {expanded && (
        <div className="px-4 pb-4 pt-0 border-t" style={{ borderColor: "var(--border)" }}>
          <div className="grid gap-3 mt-3">
            {finding.url && (
              <Row label="URL">
                <a href={finding.url} target="_blank" rel="noreferrer"
                   className="flex items-center gap-1 text-xs break-all hover:underline"
                   style={{ color: "var(--accent)" }}>
                  {finding.url}
                  <ExternalLink size={10} />
                </a>
              </Row>
            )}
            <Row label="Description">
              <p className="text-xs leading-relaxed" style={{ color: "var(--body)" }}>{finding.description}</p>
            </Row>
            {finding.remediation && (
              <Row label="Remediation">
                <p className="text-xs leading-relaxed" style={{ color: "#7ee787" }}>{finding.remediation}</p>
              </Row>
            )}
            {finding.evidence && Object.keys(finding.evidence).length > 0 && (
              <Row label="Evidence">
                <pre className="text-xs overflow-auto max-h-48 p-3 rounded"
                     style={{ background: "var(--surface-2)", color: "#7ee787", border: "1px solid var(--border)" }}>
                  {JSON.stringify(finding.evidence, null, 2)}
                </pre>
              </Row>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex gap-3">
      <span className="text-xs font-semibold w-24 shrink-0 pt-0.5" style={{ color: "var(--muted)" }}>
        {label}
      </span>
      <div className="flex-1 min-w-0">{children}</div>
    </div>
  );
}
