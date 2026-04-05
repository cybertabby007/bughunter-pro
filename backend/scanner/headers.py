"""
Security Headers Checker — checks HTTP security headers, cookie flags, and TLS settings.
"""

import asyncio
import logging
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

import httpx
import ssl
import socket

logger = logging.getLogger(__name__)
TIMEOUT = httpx.Timeout(10.0)
RATE_LIMIT_DELAY = 0.3


async def run_headers(domain: str, subdomains: list[dict], emit) -> list[dict]:
    findings = []

    targets = [f"https://{domain}"]
    for s in subdomains:
        if s.get("alive"):
            targets.append(f"https://{s['subdomain']}")
    targets = list(set(targets))[:20]  # cap

    await emit("progress", {"module": "headers", "step": "check", "message": f"Checking headers on {len(targets)} hosts..."})

    tasks = [_check_headers(t, emit) for t in targets]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    for r in results:
        if isinstance(r, list):
            findings.extend(r)

    await emit("module_complete", {"module": "headers", "results": findings})
    return findings


async def _check_headers(url: str, emit) -> list[dict]:
    findings = []
    domain = urlparse(url).netloc

    try:
        async with httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=True, verify=False) as client:
            resp = await client.get(url)
            headers = {k.lower(): v for k, v in resp.headers.items()}
            status = resp.status_code

        # ── Missing security headers ──────────────────────────────────────────
        missing_checks = [
            ("content-security-policy", "Content-Security-Policy (CSP) Missing", "medium",
             "No CSP header. Attackers can inject scripts from any origin.",
             "Add: Content-Security-Policy: default-src 'self'"),
            ("strict-transport-security", "HSTS Missing", "medium",
             "No HSTS header. Users may be downgraded to HTTP by MITM attackers.",
             "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains"),
            ("x-frame-options", "X-Frame-Options Missing", "low",
             "No X-Frame-Options. Page may be embedded in iframes (clickjacking).",
             "Add: X-Frame-Options: DENY"),
            ("x-content-type-options", "X-Content-Type-Options Missing", "low",
             "No X-Content-Type-Options. Browser may MIME-sniff responses.",
             "Add: X-Content-Type-Options: nosniff"),
            ("referrer-policy", "Referrer-Policy Missing", "info",
             "No Referrer-Policy. Sensitive URL data may leak to third parties.",
             "Add: Referrer-Policy: strict-origin-when-cross-origin"),
            ("permissions-policy", "Permissions-Policy Missing", "info",
             "No Permissions-Policy header to restrict browser feature access.",
             "Add: Permissions-Policy: camera=(), microphone=(), geolocation=()"),
        ]

        for header_name, title, severity, description, remediation in missing_checks:
            if header_name not in headers:
                f = _make_finding(url, title, severity, description, remediation, {"header": header_name, "present": False})
                findings.append(f)
                await emit("finding", f)

        # ── Dangerous header values ───────────────────────────────────────────

        # ACAO: *
        acao = headers.get("access-control-allow-origin", "")
        if acao == "*":
            f = _make_finding(url, "CORS: Access-Control-Allow-Origin: *", "high",
                "Wildcard CORS policy allows any origin to read responses. Can expose authenticated data if credentials are also allowed.",
                "Restrict ACAO to specific trusted origins.",
                {"header": "access-control-allow-origin", "value": acao})
            findings.append(f)
            await emit("finding", f)

        # Server version disclosure
        server = headers.get("server", "")
        if server and any(c.isdigit() for c in server):
            f = _make_finding(url, "Server Version Disclosure", "low",
                f"Server header reveals version info: '{server}'. Aids fingerprinting.",
                "Configure server to return a generic value or remove the header.",
                {"header": "server", "value": server})
            findings.append(f)
            await emit("finding", f)

        # X-Powered-By
        xpb = headers.get("x-powered-by", "")
        if xpb:
            f = _make_finding(url, "Technology Disclosure via X-Powered-By", "info",
                f"X-Powered-By reveals: '{xpb}'. Helps attackers target known CVEs.",
                "Remove X-Powered-By header from server configuration.",
                {"header": "x-powered-by", "value": xpb})
            findings.append(f)
            await emit("finding", f)

        # Cookie checks
        set_cookies = resp.headers.get_list("set-cookie") if hasattr(resp.headers, "get_list") else []
        if not set_cookies:
            raw_cookies = headers.get("set-cookie", "")
            set_cookies = [raw_cookies] if raw_cookies else []

        for cookie_str in set_cookies:
            cookie_name = cookie_str.split("=")[0].strip()
            flags = cookie_str.lower()

            if "secure" not in flags and url.startswith("https"):
                f = _make_finding(url, f"Cookie Missing Secure Flag: {cookie_name}", "medium",
                    f"Cookie '{cookie_name}' lacks the Secure flag. May be transmitted over HTTP.",
                    "Add Secure flag to all cookies set on HTTPS pages.",
                    {"cookie": cookie_name, "value": cookie_str[:200]})
                findings.append(f)
                await emit("finding", f)

            if "httponly" not in flags:
                f = _make_finding(url, f"Cookie Missing HttpOnly Flag: {cookie_name}", "medium",
                    f"Cookie '{cookie_name}' lacks HttpOnly. Accessible via JavaScript (XSS risk).",
                    "Add HttpOnly flag to all session/auth cookies.",
                    {"cookie": cookie_name, "value": cookie_str[:200]})
                findings.append(f)
                await emit("finding", f)

            if "samesite" not in flags:
                f = _make_finding(url, f"Cookie Missing SameSite Flag: {cookie_name}", "low",
                    f"Cookie '{cookie_name}' lacks SameSite. May be sent in CSRF attacks.",
                    "Add SameSite=Strict or SameSite=Lax to cookies.",
                    {"cookie": cookie_name, "value": cookie_str[:200]})
                findings.append(f)
                await emit("finding", f)

        # ── HTTP → HTTPS redirect check ──────────────────────────────────────
        http_url = url.replace("https://", "http://")
        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(5.0), follow_redirects=False, verify=False) as client:
                http_resp = await client.get(http_url)
                if http_resp.status_code not in [301, 302, 307, 308]:
                    f = _make_finding(url, "HTTP Not Redirecting to HTTPS", "medium",
                        f"HTTP version returned {http_resp.status_code} instead of redirect to HTTPS.",
                        "Configure server to redirect all HTTP traffic to HTTPS.",
                        {"http_status": http_resp.status_code})
                    findings.append(f)
                    await emit("finding", f)
        except Exception:
            pass

        # ── SSL certificate check ────────────────────────────────────────────
        ssl_findings = await _check_ssl(domain)
        for sf in ssl_findings:
            findings.append(sf)
            await emit("finding", sf)

        await asyncio.sleep(RATE_LIMIT_DELAY)

    except Exception as e:
        logger.warning("Header check failed for %s: %s", url, e)

    return findings


async def _check_ssl(domain: str) -> list[dict]:
    findings = []
    try:
        ctx = ssl.create_default_context()
        loop = asyncio.get_event_loop()

        def _get_cert():
            with ctx.wrap_socket(socket.create_connection((domain, 443), timeout=5), server_hostname=domain) as ssock:
                return ssock.getpeercert()

        cert = await loop.run_in_executor(None, _get_cert)
        if cert:
            not_after_str = cert.get("notAfter", "")
            if not_after_str:
                not_after = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                days_left = (not_after - datetime.now(timezone.utc)).days
                if days_left < 30:
                    sev = "high" if days_left < 7 else "medium"
                    f = _make_finding(f"https://{domain}", "SSL Certificate Expiring Soon", sev,
                        f"SSL certificate expires in {days_left} days ({not_after_str}).",
                        "Renew the SSL certificate before expiry.",
                        {"days_left": days_left, "expires": not_after_str})
                    findings.append(f)
    except ssl.SSLCertVerificationError:
        f = _make_finding(f"https://{domain}", "Self-Signed or Invalid SSL Certificate", "high",
            "SSL certificate is self-signed or fails verification. Users will see browser warnings.",
            "Install a valid certificate from a trusted Certificate Authority.",
            {})
        findings.append(f)
    except Exception as e:
        logger.debug("SSL check failed for %s: %s", domain, e)

    return findings


def _make_finding(url: str, title: str, severity: str, description: str, remediation: str, evidence: dict) -> dict:
    return {
        "type": "header",
        "url": url,
        "title": title,
        "severity": severity,
        "description": description,
        "remediation": remediation,
        "evidence": evidence,
    }
