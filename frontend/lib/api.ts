const API_BASE = process.env.NEXT_PUBLIC_API_URL || "";

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
  let wsBase: string;
  if (process.env.NEXT_PUBLIC_API_URL) {
    wsBase = process.env.NEXT_PUBLIC_API_URL.replace(/^http/, "ws");
  } else if (typeof window !== "undefined") {
    const proto = window.location.protocol === "https:" ? "wss" : "ws";
    wsBase = `${proto}://${window.location.host}`;
  } else {
    wsBase = "ws://localhost:8000";
  }
  return new WebSocket(`${wsBase}/ws/${scanId}`);
}
