"""
BugHunter Pro — FastAPI backend with WebSocket real-time streaming.
"""

import asyncio
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any

import os

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from fastapi.staticfiles import StaticFiles

from scanner import cors as cors_mod
from scanner import headers as headers_mod
from scanner import recon as recon_mod
from scanner import redirect as redirect_mod
from scanner import report as report_mod
from scanner import secrets as secrets_mod
from scanner import sqli as sqli_mod
from scanner import ssrf as ssrf_mod
from scanner import takeover as takeover_mod
from scanner import xss as xss_mod

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s — %(message)s")
logger = logging.getLogger("bughunter")

app = FastAPI(title="BugHunter Pro API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── In-memory scan store ──────────────────────────────────────────────────────
# Structure: scan_id → {"domain", "status", "started_at", "findings", "progress", "ws_connections"}
scans: dict[str, dict] = {}
ws_connections: dict[str, list[WebSocket]] = {}


# ── REST endpoints ────────────────────────────────────────────────────────────

@app.post("/scan")
async def start_scan(payload: dict):
    """
    Start a new scan.
    Body: {"domain": "example.com"}
    Returns: {"scan_id": "..."}

    LEGAL NOTICE: Only scan targets you own or have explicit written permission to test.
    Unauthorized scanning is illegal under the Computer Misuse Act 1990.
    """
    domain = payload.get("domain", "").strip().lower()
    domain = domain.replace("https://", "").replace("http://", "").split("/")[0]

    if not domain or "." not in domain:
        return {"error": "Invalid domain"}

    scan_id = str(uuid.uuid4())
    scans[scan_id] = {
        "domain": domain,
        "status": "running",
        "started_at": datetime.now(timezone.utc).isoformat(),
        "findings": [],
        "progress": [],
        "modules_complete": [],
    }
    ws_connections[scan_id] = []

    # Run scan asynchronously
    asyncio.create_task(_run_scan(scan_id, domain))
    logger.info("Scan %s started for %s", scan_id, domain)

    return {"scan_id": scan_id, "domain": domain, "status": "running"}


@app.get("/scan/{scan_id}")
async def get_scan(scan_id: str):
    """Get all scan results for a given scan_id."""
    if scan_id not in scans:
        return {"error": "Scan not found"}
    scan = scans[scan_id]
    return {
        "scan_id": scan_id,
        "domain": scan["domain"],
        "status": scan["status"],
        "started_at": scan["started_at"],
        "findings": scan["findings"],
        "progress": scan["progress"],
        "modules_complete": scan["modules_complete"],
        "stats": _compute_stats(scan["findings"]),
    }


@app.get("/report/{scan_id}")
async def download_report(scan_id: str):
    """Generate and download a PDF report for the scan."""
    if scan_id not in scans:
        return Response(content=b"Scan not found", status_code=404)

    scan = scans[scan_id]
    try:
        pdf_bytes = report_mod.generate_pdf(
            scan_id=scan_id,
            domain=scan["domain"],
            findings=scan["findings"],
            scan_started=scan["started_at"],
        )
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="bughunter-{scan["domain"]}-{scan_id[:8]}.pdf"'},
        )
    except Exception as e:
        logger.error("PDF generation failed: %s", e)
        return Response(content=b"Report generation failed", status_code=500)


# ── WebSocket endpoint ────────────────────────────────────────────────────────

@app.websocket("/ws/{scan_id}")
async def websocket_endpoint(websocket: WebSocket, scan_id: str):
    await websocket.accept()

    if scan_id not in ws_connections:
        ws_connections[scan_id] = []
    ws_connections[scan_id].append(websocket)

    # Send existing findings immediately on connect (catch-up)
    if scan_id in scans:
        for finding in scans[scan_id]["findings"]:
            await _ws_send(websocket, "finding", finding)
        for prog in scans[scan_id]["progress"]:
            await _ws_send(websocket, "progress", prog)

    try:
        while True:
            # Keep connection alive — client sends pings
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text(json.dumps({"type": "pong"}))
    except WebSocketDisconnect:
        ws_connections[scan_id].remove(websocket)
    except Exception:
        try:
            ws_connections[scan_id].remove(websocket)
        except ValueError:
            pass


# ── Scan orchestrator ─────────────────────────────────────────────────────────

async def _run_scan(scan_id: str, domain: str):
    scan = scans[scan_id]

    async def emit(event_type: str, data: Any):
        """Stream an event to all connected WebSocket clients and store it."""
        msg = {"type": event_type, "data": data, "ts": datetime.now(timezone.utc).isoformat()}

        if event_type == "finding":
            scan["findings"].append(data)
        elif event_type == "progress":
            scan["progress"].append(data)
        elif event_type == "module_complete":
            scan["modules_complete"].append(data.get("module"))

        dead = []
        for ws in ws_connections.get(scan_id, []):
            try:
                await ws.send_text(json.dumps(msg, default=str))
            except Exception:
                dead.append(ws)
        for ws in dead:
            try:
                ws_connections[scan_id].remove(ws)
            except ValueError:
                pass

    try:
        await emit("progress", {"module": "system", "step": "start",
                                  "message": f"🚀 BugHunter Pro scan started for {domain}"})

        # Module 1: Recon
        await emit("progress", {"module": "system", "step": "recon",
                                  "message": "Starting reconnaissance engine..."})
        recon_results = await recon_mod.run_recon(domain, emit)
        subdomains = recon_results.get("subdomains", [])
        endpoints  = recon_results.get("endpoints", [])

        # Module 2: Security Headers
        await emit("progress", {"module": "system", "step": "headers",
                                  "message": "Checking security headers..."})
        await headers_mod.run_headers(domain, subdomains, emit)

        # Module 3: Secrets & Exposed Files
        await emit("progress", {"module": "system", "step": "secrets",
                                  "message": "Scanning for exposed files and secrets..."})
        await secrets_mod.run_secrets(domain, endpoints, emit)

        # Module 4: XSS
        await emit("progress", {"module": "system", "step": "xss",
                                  "message": "Hunting for XSS vulnerabilities..."})
        await xss_mod.run_xss(domain, endpoints, emit)

        # Module 5: SQL Injection
        await emit("progress", {"module": "system", "step": "sqli",
                                  "message": "Testing for SQL injection..."})
        await sqli_mod.run_sqli(domain, endpoints, emit)

        # Module 6: SSRF
        await emit("progress", {"module": "system", "step": "ssrf",
                                  "message": "Detecting SSRF vulnerabilities..."})
        await ssrf_mod.run_ssrf(domain, endpoints, emit)

        # Module 7: CORS
        await emit("progress", {"module": "system", "step": "cors",
                                  "message": "Checking CORS misconfigurations..."})
        await cors_mod.run_cors(domain, endpoints, emit)

        # Module 8: Open Redirect
        await emit("progress", {"module": "system", "step": "redirect",
                                  "message": "Testing for open redirects..."})
        await redirect_mod.run_redirect(domain, endpoints, emit)

        # Module 9: Subdomain Takeover
        await emit("progress", {"module": "system", "step": "takeover",
                                  "message": "Checking for subdomain takeover vulnerabilities..."})
        await takeover_mod.run_takeover(domain, subdomains, emit)

        scan["status"] = "complete"
        stats = _compute_stats(scan["findings"])
        await emit("scan_complete", {
            "scan_id": scan_id,
            "domain": domain,
            "total_findings": len(scan["findings"]),
            "stats": stats,
            "message": f"✅ Scan complete. Found {len(scan['findings'])} issues.",
        })
        logger.info("Scan %s complete. %d findings.", scan_id, len(scan["findings"]))

    except Exception as e:
        logger.error("Scan %s failed: %s", scan_id, e, exc_info=True)
        scan["status"] = "error"
        await emit("error", {"message": str(e)})


def _compute_stats(findings: list[dict]) -> dict:
    stats: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": len(findings)}
    by_type: dict[str, int] = {}
    for f in findings:
        sev = f.get("severity", "info")
        stats[sev] = stats.get(sev, 0) + 1
        t = f.get("type", "other")
        by_type[t] = by_type.get(t, 0) + 1
    return {"severity": stats, "by_type": by_type}


async def _ws_send(ws: WebSocket, event_type: str, data: Any):
    try:
        await ws.send_text(json.dumps({"type": event_type, "data": data, "ts": datetime.now(timezone.utc).isoformat()}, default=str))
    except Exception:
        pass


# ── Serve Next.js static export (must be mounted last) ───────────────────────
_static_dir = os.path.join(os.path.dirname(__file__), "static")
if os.path.exists(_static_dir):
    app.mount("/", StaticFiles(directory=_static_dir, html=True), name="frontend")


if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=port)
