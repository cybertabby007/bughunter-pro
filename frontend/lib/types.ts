export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface Finding {
  type: string;
  subtype?: string;
  severity: Severity;
  title: string;
  description: string;
  remediation?: string;
  url?: string;
  evidence?: Record<string, unknown>;
}

export interface ScanStats {
  severity: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
    total: number;
  };
  by_type: Record<string, number>;
}

export interface ScanResult {
  scan_id: string;
  domain: string;
  status: "running" | "complete" | "error";
  started_at: string;
  findings: Finding[];
  progress: ProgressEvent[];
  modules_complete: string[];
  stats: ScanStats;
}

export interface ProgressEvent {
  module: string;
  step: string;
  message: string;
}

export interface WsMessage {
  type: "finding" | "progress" | "module_complete" | "scan_complete" | "error" | "pong";
  data: unknown;
  ts: string;
}

export const SEVERITY_COLORS: Record<Severity, string> = {
  critical: "#E24B4A",
  high:     "#EF9F27",
  medium:   "#3B82F6",
  low:      "#1D9E75",
  info:     "#888888",
};

export const SEVERITY_BG: Record<Severity, string> = {
  critical: "rgba(226,75,74,0.15)",
  high:     "rgba(239,159,39,0.15)",
  medium:   "rgba(59,130,246,0.15)",
  low:      "rgba(29,158,117,0.15)",
  info:     "rgba(136,136,136,0.15)",
};

export const MODULE_LABELS: Record<string, string> = {
  recon:    "Reconnaissance",
  headers:  "Security Headers",
  secrets:  "Secrets & Files",
  xss:      "XSS Hunter",
  sqli:     "SQL Injection",
  ssrf:     "SSRF Detector",
  cors:     "CORS Config",
  redirect: "Open Redirect",
  takeover: "Subdomain Takeover",
  system:   "System",
};
