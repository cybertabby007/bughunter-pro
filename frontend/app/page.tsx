"use client";
import { useState, useEffect, useRef, useCallback } from "react";
import { useRouter } from "next/navigation";
import {
  Shield, Search, AlertTriangle, Wifi, ChevronRight, Lock,
  Zap, Eye, Terminal,
} from "lucide-react";
import Navbar from "@/components/Navbar";
import SeverityBadge from "@/components/SeverityBadge";
import { startScan, createWebSocket } from "@/lib/api";
import { Finding, WsMessage, MODULE_LABELS, SEVERITY_COLORS } from "@/lib/types";

const MODULES = ["recon", "headers", "secrets", "xss", "sqli", "ssrf", "cors", "redirect", "takeover"];

export default function ScannerPage() {
  const router = useRouter();
  const [domain, setDomain] = useState("");
  const [agreed, setAgreed] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [currentModule, setCurrentModule] = useState<string | null>(null);
  const [completedModules, setCompletedModules] = useState<string[]>([]);
  const [progressMsg, setProgressMsg] = useState("");
  const [liveFindings, setLiveFindings] = useState<Finding[]>([]);
  const [scanComplete, setScanComplete] = useState(false);
  const [scanId, setScanId] = useState<string | null>(null);
  const [error, setError] = useState("");
  const wsRef = useRef<WebSocket | null>(null);
  const feedRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (feedRef.current) {
      feedRef.current.scrollTop = feedRef.current.scrollHeight;
    }
  }, [liveFindings.length]);

  const handleScan = useCallback(async () => {
    if (!domain.trim() || !agreed) return;
    const cleanDomain = domain.trim().toLowerCase().replace(/^https?:\/\//, "").split("/")[0];

    setError("");
    setScanning(true);
    setScanComplete(false);
    setLiveFindings([]);
    setCompletedModules([]);
    setCurrentModule("recon");
    setProgressMsg("Initialising scan...");

    try {
      const { scan_id } = await startScan(cleanDomain);
      setScanId(scan_id);
      localStorage.setItem("lastScanId", scan_id);
      localStorage.setItem("lastScanDomain", cleanDomain);

      const ws = createWebSocket(scan_id);
      wsRef.current = ws;

      ws.onmessage = (event) => {
        try {
          const msg: WsMessage = JSON.parse(event.data);
          if (msg.type === "finding") {
            setLiveFindings(prev => [...prev, msg.data as Finding]);
          } else if (msg.type === "progress") {
            const d = msg.data as { module: string; message: string };
            setProgressMsg(d.message);
            if (d.module && d.module !== "system") setCurrentModule(d.module);
          } else if (msg.type === "module_complete") {
            const d = msg.data as { module: string };
            setCompletedModules(prev => [...prev, d.module]);
          } else if (msg.type === "scan_complete") {
            setScanComplete(true);
            setScanning(false);
            setCurrentModule(null);
          } else if (msg.type === "error") {
            setError((msg.data as { message: string }).message || "Scan error");
            setScanning(false);
          }
        } catch { /* ignore parse errors */ }
      };

      ws.onerror = () => {
        setError("WebSocket connection failed. Is the backend running on port 8000?");
        setScanning(false);
      };

      const ping = setInterval(() => {
        if (ws.readyState === WebSocket.OPEN) ws.send("ping");
      }, 15000);
      ws.onclose = () => clearInterval(ping);
    } catch (e: unknown) {
      setError((e as Error).message || "Failed to start scan");
      setScanning(false);
    }
  }, [domain, agreed]);

  const moduleProgress = currentModule
    ? ((MODULES.indexOf(currentModule) + 1) / MODULES.length) * 100
    : 0;

  return (
    <div className="min-h-screen flex flex-col">
      <Navbar />
      <main className="flex-1 max-w-5xl mx-auto w-full px-4 py-8">

        {/* Hero */}
        <div className="text-center mb-10">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full text-xs mb-4"
               style={{ background: "rgba(127,119,221,0.12)", color: "var(--accent)", border: "1px solid rgba(127,119,221,0.3)" }}>
            <Zap size={11} /> Authorized Security Testing Only
          </div>
          <h1 className="text-4xl font-bold mb-3" style={{ color: "white" }}>
            Bug Bounty <span style={{ color: "var(--accent)" }}>Scanner</span>
          </h1>
          <p className="text-base max-w-xl mx-auto" style={{ color: "var(--muted)" }}>
            Professional automated security testing across 9 vulnerability modules.
            Stream results in real-time as each module completes.
          </p>
        </div>

        {/* Scanner card */}
        <div className="rounded-xl p-6 mb-6"
             style={{ background: "var(--surface)", border: "1px solid var(--border)" }}>
          <div className="flex gap-3 mb-4">
            <div className="flex-1 flex items-center gap-3 px-4 rounded-lg"
                 style={{ background: "var(--surface-2)", border: `1px solid ${scanning ? "var(--accent)" : "var(--border)"}` }}>
              <Search size={15} style={{ color: "var(--muted)" }} />
              <input
                type="text"
                value={domain}
                onChange={e => setDomain(e.target.value)}
                onKeyDown={e => e.key === "Enter" && !scanning && handleScan()}
                placeholder="example.com"
                disabled={scanning}
                className="flex-1 py-3 bg-transparent outline-none text-sm"
                style={{ color: "white" }}
              />
            </div>
            <button
              onClick={handleScan}
              disabled={!domain.trim() || !agreed || scanning}
              className="px-6 py-3 rounded-lg font-semibold text-sm transition-all flex items-center gap-2"
              style={{
                background: (!domain.trim() || !agreed || scanning) ? "var(--surface-2)" : "var(--accent)",
                color:      (!domain.trim() || !agreed || scanning) ? "var(--muted)"    : "white",
                cursor:     (!domain.trim() || !agreed || scanning) ? "not-allowed"     : "pointer",
              }}>
              {scanning ? (
                <>
                  <span className="w-3 h-3 border-2 border-t-transparent rounded-full inline-block animate-spin"
                        style={{ borderColor: "rgba(255,255,255,0.3)", borderTopColor: "white" }} />
                  Scanning...
                </>
              ) : (
                <><Zap size={14} /> Start Scan</>
              )}
            </button>
          </div>

          <label className="flex items-start gap-3 cursor-pointer">
            <input type="checkbox" checked={agreed} onChange={e => setAgreed(e.target.checked)}
                   className="mt-0.5" style={{ accentColor: "var(--accent)" }} />
            <span className="text-xs leading-relaxed" style={{ color: "var(--muted)" }}>
              <span style={{ color: "#EF9F27" }} className="font-semibold">Legal Disclaimer: </span>
              I confirm I own or have <strong style={{ color: "var(--body)" }}>explicit written permission</strong> to
              security test the target domain. Unauthorized scanning is illegal under the
              <strong style={{ color: "var(--body)" }}> Computer Misuse Act 1990</strong> and equivalent legislation.
              I take full responsibility for my actions.
            </span>
          </label>
        </div>

        {error && (
          <div className="rounded-lg px-4 py-3 mb-4 flex items-center gap-3 text-sm animate-fade-in"
               style={{ background: "rgba(226,75,74,0.1)", border: "1px solid rgba(226,75,74,0.3)", color: "#E24B4A" }}>
            <AlertTriangle size={15} /> {error}
          </div>
        )}

        {/* Progress panel */}
        {(scanning || scanComplete) && (
          <div className="rounded-xl p-5 mb-6 animate-fade-in"
               style={{ background: "var(--surface)", border: "1px solid var(--border)" }}>
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-2">
                <span className="w-2 h-2 rounded-full animate-pulse"
                      style={{ background: scanning ? "var(--accent)" : "var(--low)" }} />
                <span className="text-sm font-semibold" style={{ color: "white" }}>
                  {scanning ? "Scan In Progress" : "✓ Scan Complete"}
                </span>
              </div>
              {scanComplete && scanId && (
                <button onClick={() => router.push("/results")}
                        className="flex items-center gap-1.5 text-sm px-3 py-1.5 rounded"
                        style={{ background: "rgba(127,119,221,0.15)", color: "var(--accent)", border: "1px solid rgba(127,119,221,0.3)" }}>
                  View Full Results <ChevronRight size={13} />
                </button>
              )}
            </div>

            <div className="h-1.5 rounded-full mb-3 overflow-hidden" style={{ background: "var(--surface-2)" }}>
              <div className="h-full rounded-full transition-all duration-700"
                   style={{
                     width: scanComplete ? "100%" : `${Math.max(4, moduleProgress)}%`,
                     background: scanComplete ? "var(--low)" : "var(--accent)",
                   }} />
            </div>

            <div className="flex flex-wrap gap-2 mb-3">
              {MODULES.map(mod => {
                const done   = completedModules.includes(mod);
                const active = currentModule === mod && scanning;
                return (
                  <span key={mod} className="text-xs px-2 py-1 rounded transition-all"
                        style={{
                          background: done ? "rgba(29,158,117,0.15)" : active ? "rgba(127,119,221,0.15)" : "var(--surface-2)",
                          color: done ? "var(--low)" : active ? "var(--accent)" : "var(--muted)",
                          border: `1px solid ${done ? "rgba(29,158,117,0.3)" : active ? "rgba(127,119,221,0.3)" : "var(--border)"}`,
                        }}>
                    {done ? "✓ " : active ? "⟳ " : ""}{MODULE_LABELS[mod] || mod}
                  </span>
                );
              })}
            </div>

            {progressMsg && (
              <p className="text-xs flex items-center gap-2" style={{ color: "var(--muted)" }}>
                <Terminal size={11} /> {progressMsg}
              </p>
            )}
          </div>
        )}

        {/* Live findings feed */}
        {liveFindings.length > 0 && (
          <div className="rounded-xl animate-fade-in"
               style={{ background: "var(--surface)", border: "1px solid var(--border)" }}>
            <div className="flex items-center justify-between px-4 py-3"
                 style={{ borderBottom: "1px solid var(--border)" }}>
              <div className="flex items-center gap-2">
                <Eye size={14} style={{ color: "var(--accent)" }} />
                <span className="text-sm font-semibold" style={{ color: "white" }}>Live Feed</span>
                <span className="text-xs px-1.5 py-0.5 rounded"
                      style={{ background: "rgba(127,119,221,0.15)", color: "var(--accent)" }}>
                  {liveFindings.length}
                </span>
              </div>
              <div className="flex gap-3 text-xs">
                {(["critical", "high", "medium", "low"] as const).map(sev => {
                  const count = liveFindings.filter(f => f.severity === sev).length;
                  return count > 0 ? (
                    <span key={sev} style={{ color: SEVERITY_COLORS[sev] }}>{count} {sev}</span>
                  ) : null;
                })}
              </div>
            </div>
            <div ref={feedRef} className="overflow-y-auto max-h-96">
              {[...liveFindings].reverse().map((finding, i) => (
                <div key={i} className="flex items-start gap-3 px-4 py-3 border-b animate-fade-in"
                     style={{ borderColor: "var(--border)" }}>
                  <SeverityBadge severity={finding.severity} size="sm" />
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-medium truncate" style={{ color: "white" }}>{finding.title}</p>
                    <p className="text-xs mt-0.5 line-clamp-1" style={{ color: "var(--muted)" }}>{finding.description}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Feature grid */}
        {!scanning && !scanComplete && (
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 mt-8">
            {[
              { icon: Shield, label: "9 Scan Modules",      desc: "Recon, Headers, Secrets, XSS, SQLi, SSRF, CORS, Redirects & Subdomain Takeover" },
              { icon: Wifi,   label: "Real-Time Streaming",  desc: "WebSocket delivers findings live as each module completes" },
              { icon: Lock,   label: "PDF Reports",          desc: "Professional reports with CVSS scores, PoC steps and remediation guidance" },
            ].map(({ icon: Icon, label, desc }) => (
              <div key={label} className="p-4 rounded-lg"
                   style={{ background: "var(--surface)", border: "1px solid var(--border)" }}>
                <div className="w-8 h-8 rounded flex items-center justify-center mb-3"
                     style={{ background: "rgba(127,119,221,0.12)" }}>
                  <Icon size={16} style={{ color: "var(--accent)" }} />
                </div>
                <p className="text-sm font-semibold mb-1" style={{ color: "white" }}>{label}</p>
                <p className="text-xs leading-relaxed" style={{ color: "var(--muted)" }}>{desc}</p>
              </div>
            ))}
          </div>
        )}
      </main>
    </div>
  );
}
