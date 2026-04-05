"use client";
import { useState, useEffect, useCallback } from "react";
import { Download, Filter, RefreshCw, AlertCircle, ChevronDown } from "lucide-react";
import Navbar from "@/components/Navbar";
import FindingCard from "@/components/FindingCard";
import StatsBar from "@/components/StatsBar";
import { getScan, getReportUrl } from "@/lib/api";
import { Finding, ScanResult, Severity, SEVERITY_COLORS } from "@/lib/types";

const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

const TYPE_OPTIONS = [
  "all", "xss", "sqli", "ssrf", "cors", "redirect", "header",
  "exposed_file", "secret_in_js", "takeover", "subdomain", "open_port", "admin_panel",
];

const TYPE_LABELS: Record<string, string> = {
  all: "All Types", xss: "XSS", sqli: "SQLi", ssrf: "SSRF",
  cors: "CORS", redirect: "Open Redirect", header: "Headers",
  exposed_file: "Exposed Files", secret_in_js: "Secrets", takeover: "Takeover",
  subdomain: "Subdomain", open_port: "Open Port", admin_panel: "Admin Panel",
};

export default function ResultsPage() {
  const [scan, setScan] = useState<ScanResult | null>(null);
  const [scanId, setScanId] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [severityFilter, setSeverityFilter] = useState<Severity | "all">("all");
  const [typeFilter, setTypeFilter] = useState("all");
  const [sortBy, setSortBy] = useState<"severity" | "type">("severity");

  useEffect(() => {
    const id = localStorage.getItem("lastScanId");
    setScanId(id);
    if (id) loadScan(id);
    else { setLoading(false); setError("No scan found. Start a scan from the Scanner page."); }
  }, []);

  const loadScan = useCallback(async (id: string) => {
    setLoading(true);
    try {
      const data = await getScan(id);
      setScan(data);
      setError("");
    } catch (e: unknown) {
      setError((e as Error).message || "Failed to load scan");
    } finally {
      setLoading(false);
    }
  }, []);

  const refresh = () => { if (scanId) loadScan(scanId); };

  const filteredFindings = (scan?.findings ?? []).filter(f => {
    if (severityFilter !== "all" && f.severity !== severityFilter) return false;
    if (typeFilter !== "all" && f.type !== typeFilter) return false;
    return true;
  }).sort((a, b) => {
    if (sortBy === "severity") {
      return SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity);
    }
    return a.type.localeCompare(b.type);
  });

  return (
    <div className="min-h-screen flex flex-col">
      <Navbar />
      <main className="flex-1 max-w-5xl mx-auto w-full px-4 py-8">

        {/* Header */}
        <div className="flex items-center justify-between mb-6">
          <div>
            <h1 className="text-2xl font-bold" style={{ color: "white" }}>Scan Results</h1>
            {scan && (
              <p className="text-sm mt-0.5" style={{ color: "var(--muted)" }}>
                {scan.domain} · {scan.status === "complete" ? "Complete" : "Running..."} ·{" "}
                {new Date(scan.started_at).toLocaleString()}
              </p>
            )}
          </div>
          <div className="flex items-center gap-3">
            <button onClick={refresh}
                    className="p-2 rounded transition-colors hover:bg-white/10"
                    title="Refresh">
              <RefreshCw size={14} style={{ color: "var(--muted)" }} />
            </button>
            {scan && scanId && (
              <a href={getReportUrl(scanId)} download
                 className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium no-underline transition-colors"
                 style={{ background: "var(--accent)", color: "white" }}>
                <Download size={13} /> Download PDF
              </a>
            )}
          </div>
        </div>

        {loading && (
          <div className="flex items-center justify-center py-20" style={{ color: "var(--muted)" }}>
            <div className="w-6 h-6 border-2 border-t-transparent rounded-full animate-spin mr-3"
                 style={{ borderColor: "var(--border)", borderTopColor: "var(--accent)" }} />
            Loading results...
          </div>
        )}

        {error && !loading && (
          <div className="rounded-lg px-4 py-4 flex items-center gap-3"
               style={{ background: "rgba(226,75,74,0.1)", border: "1px solid rgba(226,75,74,0.3)", color: "#E24B4A" }}>
            <AlertCircle size={16} /> {error}
          </div>
        )}

        {scan && !loading && (
          <>
            {/* Stats */}
            <div className="mb-6">
              <StatsBar stats={scan.stats} />
            </div>

            {/* Filters */}
            <div className="rounded-lg p-3 mb-5 flex flex-wrap items-center gap-3"
                 style={{ background: "var(--surface)", border: "1px solid var(--border)" }}>
              <div className="flex items-center gap-1.5" style={{ color: "var(--muted)" }}>
                <Filter size={13} />
                <span className="text-xs">Filter:</span>
              </div>

              {/* Severity filter */}
              <div className="flex flex-wrap gap-1.5">
                {(["all", ...SEVERITY_ORDER] as const).map(sev => (
                  <button key={sev}
                          onClick={() => setSeverityFilter(sev)}
                          className="text-xs px-2.5 py-1 rounded transition-all"
                          style={{
                            background: severityFilter === sev
                              ? (sev === "all" ? "rgba(127,119,221,0.2)" : `${SEVERITY_COLORS[sev]}25`)
                              : "var(--surface-2)",
                            color: severityFilter === sev
                              ? (sev === "all" ? "var(--accent)" : SEVERITY_COLORS[sev])
                              : "var(--muted)",
                            border: `1px solid ${severityFilter === sev
                              ? (sev === "all" ? "rgba(127,119,221,0.4)" : `${SEVERITY_COLORS[sev]}50`)
                              : "var(--border)"}`,
                          }}>
                    {sev === "all" ? "All" : sev.charAt(0).toUpperCase() + sev.slice(1)}
                    {sev !== "all" && scan.stats.severity[sev] > 0 && (
                      <span className="ml-1 opacity-70">({scan.stats.severity[sev]})</span>
                    )}
                  </button>
                ))}
              </div>

              <div className="w-px h-4 mx-1" style={{ background: "var(--border)" }} />

              {/* Type filter */}
              <div className="relative">
                <select value={typeFilter} onChange={e => setTypeFilter(e.target.value)}
                        className="text-xs py-1 pl-2 pr-6 rounded appearance-none cursor-pointer outline-none"
                        style={{ background: "var(--surface-2)", color: "var(--muted)", border: "1px solid var(--border)" }}>
                  {TYPE_OPTIONS.map(t => (
                    <option key={t} value={t}>{TYPE_LABELS[t] || t}</option>
                  ))}
                </select>
                <ChevronDown size={10} className="absolute right-2 top-1/2 -translate-y-1/2 pointer-events-none"
                             style={{ color: "var(--muted)" }} />
              </div>

              <div className="w-px h-4 mx-1" style={{ background: "var(--border)" }} />

              {/* Sort */}
              <div className="flex items-center gap-1.5 text-xs" style={{ color: "var(--muted)" }}>
                <span>Sort:</span>
                {(["severity", "type"] as const).map(s => (
                  <button key={s} onClick={() => setSortBy(s)}
                          className="px-2 py-1 rounded transition-all"
                          style={{
                            background: sortBy === s ? "rgba(127,119,221,0.15)" : "var(--surface-2)",
                            color: sortBy === s ? "var(--accent)" : "var(--muted)",
                            border: `1px solid ${sortBy === s ? "rgba(127,119,221,0.3)" : "var(--border)"}`,
                          }}>
                    {s}
                  </button>
                ))}
              </div>

              <div className="ml-auto text-xs" style={{ color: "var(--muted)" }}>
                {filteredFindings.length} finding{filteredFindings.length !== 1 ? "s" : ""}
              </div>
            </div>

            {/* Findings list */}
            {filteredFindings.length === 0 ? (
              <div className="text-center py-16" style={{ color: "var(--muted)" }}>
                <p className="text-4xl mb-3">🎉</p>
                <p className="font-medium" style={{ color: "white" }}>No findings match the current filters</p>
                <p className="text-sm mt-1">Try adjusting the severity or type filter above</p>
              </div>
            ) : (
              <div className="flex flex-col gap-3">
                {filteredFindings.map((finding, i) => (
                  <FindingCard key={i} finding={finding} index={i + 1} />
                ))}
              </div>
            )}
          </>
        )}
      </main>
    </div>
  );
}
