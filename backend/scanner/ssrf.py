"""
SSRF Detector — finds Server-Side Request Forgery vulnerabilities.
"""

import asyncio
import logging
import re
import time
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import httpx

logger = logging.getLogger(__name__)
TIMEOUT = httpx.Timeout(10.0)
RATE_LIMIT_DELAY = 0.5

# Parameters that often control URLs/destinations
SSRF_PARAMS = [
    "url", "link", "src", "href", "path", "dest", "redirect", "uri",
    "source", "target", "image", "load", "fetch", "request", "host",
    "page", "file", "document", "root", "folder", "dir", "domain",
    "callback", "next", "goto", "return", "out",
]

SSRF_PAYLOADS = [
    ("localhost_ipv4",  "http://127.0.0.1/"),
    ("localhost_name",  "http://localhost/"),
    ("all_zeros",       "http://0.0.0.0/"),
    ("localhost_ipv6",  "http://[::1]/"),
    ("aws_metadata",    "http://169.254.169.254/"),
    ("aws_meta_data",   "http://169.254.169.254/latest/meta-data/"),
    ("aws_iam_creds",   "http://169.254.169.254/latest/meta-data/iam/security-credentials/"),
    ("gcp_metadata",    "http://metadata.google.internal/"),
    ("alibaba_meta",    "http://100.100.100.200/"),
    ("private_192",     "http://192.168.0.1/"),
    ("private_10",      "http://10.0.0.1/"),
    ("file_passwd",     "file:///etc/passwd"),
    ("file_hosts",      "file:///etc/hosts"),
    ("redis_gopher",    "gopher://localhost:6379/_INFO"),
]

# Patterns in responses that confirm SSRF to cloud metadata
CLOUD_META_PATTERNS = [
    r"ami-id",
    r"instance-id",
    r"instance-type",
    r"local-hostname",
    r"local-ipv4",
    r"iam/security-credentials",
    r"computeMetadata",
    r"project-id",
    r"serviceaccounts",
    r"root:.*:0:0:",         # /etc/passwd
    r"localhost.*localhost",  # /etc/hosts
]


async def run_ssrf(domain: str, endpoints: list[str], emit) -> list[dict]:
    findings = []

    await emit("progress", {"module": "ssrf", "step": "collect", "message": "Collecting SSRF-prone parameters..."})

    test_targets = []

    # From discovered endpoints with params
    for url in endpoints[:50]:
        parsed = urlparse(url)
        if parsed.query:
            params = parse_qs(parsed.query)
            ssrf_params = {k: v for k, v in params.items() if k.lower() in SSRF_PARAMS}
            if ssrf_params:
                test_targets.append((url, ssrf_params))

    # Add common SSRF endpoints from the base domain
    for param in SSRF_PARAMS[:8]:
        test_targets.append((f"https://{domain}/?{param}=http://example.com", {param: ["http://example.com"]}))

    await emit("progress", {"module": "ssrf", "step": "test", "message": f"Testing {len(test_targets)} endpoints for SSRF..."})

    tasks = [_test_ssrf(url, params, emit) for url, params in test_targets[:20]]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    for r in results:
        if isinstance(r, list):
            findings.extend(r)

    await emit("module_complete", {"module": "ssrf", "results": findings})
    return findings


async def _test_ssrf(url: str, params: dict, emit) -> list[dict]:
    findings = []

    # Get baseline
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=True, verify=False) as client:
            baseline_resp = await client.get(url)
            baseline_size = len(baseline_resp.content)
            baseline_time_start = time.monotonic()
            await client.get(url)
            baseline_time = time.monotonic() - baseline_time_start
    except Exception:
        return findings

    for param_name in list(params.keys())[:3]:
        for payload_name, payload_url in SSRF_PAYLOADS:
            test_params = dict(params)
            test_params[param_name] = [payload_url]

            parsed = urlparse(url)
            test_url = urlunparse(parsed._replace(query=urlencode(test_params, doseq=True)))

            try:
                start = time.monotonic()
                async with httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=True, verify=False) as client:
                    resp = await client.get(test_url)
                elapsed = time.monotonic() - start

                resp_text = resp.text

                # Check for cloud metadata indicators
                for pattern in CLOUD_META_PATTERNS:
                    if re.search(pattern, resp_text, re.IGNORECASE):
                        sev = "critical" if "metadata" in payload_name else "high"
                        finding = {
                            "type": "ssrf",
                            "subtype": payload_name,
                            "severity": sev,
                            "title": f"SSRF — Cloud Metadata Accessible via '{param_name}'",
                            "description": (
                                f"The parameter '{param_name}' at {url} fetches URLs on the server's behalf. "
                                f"Payload '{payload_url}' returned cloud metadata content, "
                                f"indicating the server can reach internal services."
                            ),
                            "remediation": (
                                "Validate and whitelist allowed URL destinations. "
                                "Block requests to private IP ranges and metadata endpoints. "
                                "Use a URL allowlist rather than a denylist."
                            ),
                            "evidence": {
                                "url": test_url,
                                "parameter": param_name,
                                "payload": payload_url,
                                "matched_pattern": pattern,
                                "response_snippet": resp_text[:500],
                            },
                        }
                        findings.append(finding)
                        await emit("finding", finding)
                        break

                # Time-based detection: internal closed port vs open
                # Significant response time difference can indicate internal network access
                if not findings and elapsed > baseline_time + 3:
                    finding = {
                        "type": "ssrf",
                        "subtype": "time_based",
                        "severity": "medium",
                        "title": f"Possible SSRF (Time-Based) via '{param_name}'",
                        "description": (
                            f"Parameter '{param_name}' with payload '{payload_url}' caused {elapsed:.1f}s delay "
                            f"(baseline: {baseline_time:.1f}s). Server may be attempting internal connections."
                        ),
                        "remediation": "Validate URL parameters. Block SSRF via network-level controls and application allowlists.",
                        "evidence": {
                            "url": test_url,
                            "parameter": param_name,
                            "payload": payload_url,
                            "response_time": round(elapsed, 2),
                            "baseline_time": round(baseline_time, 2),
                        },
                    }
                    findings.append(finding)
                    await emit("finding", finding)

                await asyncio.sleep(RATE_LIMIT_DELAY)
            except Exception as e:
                logger.debug("SSRF test error %s: %s", test_url, e)

    return findings
