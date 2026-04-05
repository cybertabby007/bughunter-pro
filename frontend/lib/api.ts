const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";
const WS_BASE  = API_BASE.replace(/^http/, "ws");

export async function startScan(domain: string): Promise<{ scan_id: string; domain: string }> {
  const res = await fetch(`${API_BASE}/scan`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ domain }),
  });
  if (!res.ok) throw new Error(`Failed to start scan: ${res.status}`);
  return res.json();
}

export async function getScan(scanId: string) {
  const res = await fetch(`${API_BASE}/scan/${scanId}`);
  if (!res.ok) throw new Error(`Failed to fetch scan: ${res.status}`);
  return res.json();
}

export function getReportUrl(scanId: string): string {
  return `${API_BASE}/report/${scanId}`;
}

export function createWebSocket(scanId: string): WebSocket {
  return new WebSocket(`${WS_BASE}/ws/${scanId}`);
}
