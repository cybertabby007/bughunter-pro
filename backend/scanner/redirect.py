"""
Open Redirect Checker — detects unvalidated redirect parameters.
"""

import asyncio
import logging
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import httpx

logger = logging.getLogger(__name__)
TIMEOUT = httpx.Timeout(10.0)
RATE_LIMIT_DELAY = 0.4

REDIRECT_PARAMS = [
    "redirect", "url", "next", "return", "goto", "link", "target",
    "redir", "redirect_uri", "callback", "continue", "dest",
    "destination", "forward", "to", "out", "view", "from",
    "return_to", "returnUrl", "redirectUrl", "nextUrl",
]

REDIRECT_PAYLOADS = [
    "https://attacker.com",
    "//attacker.com",
    "\\/\\/attacker.com",
    "/\\attacker.com",
    "%2F%2Fattacker.com",
    "https://attacker.com%23.target.com",
    "https://target.com@attacker.com",
    "javascript:alert(1)",
    "//attacker.com/%2F..",
    "https://attacker%E3%80%82com",
]

ATTACKER_DOMAIN = "attacker.com"


async def run_redirect(domain: str, endpoints: list[str], emit) -> list[dict]:
    findings = []

    await emit("progress", {"module": "redirect", "step": "collect", "message": "Collecting redirect parameters..."})

    test_targets = []

    for url in endpoints[:100]:
        parsed = urlparse(url)
        if parsed.query:
            params = parse_qs(parsed.query)
            redir_params = {k: v for k, v in params.items() if k.lower() in REDIRECT_PARAMS}
            if redir_params:
                test_targets.append((url, redir_params))

    # Also check common redirect paths on base domain
    for param in REDIRECT_PARAMS[:6]:
        test_targets.append((
            f"https://{domain}/login?{param}=https://example.com",
            {param: ["https://example.com"]}
        ))

    test_targets = test_targets[:30]

    await emit("progress", {"module": "redirect", "step": "test", "message": f"Testing {len(test_targets)} redirect endpoints..."})

    tasks = [_test_redirect(url, params, domain, emit) for url, params in test_targets]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    for r in results:
        if isinstance(r, list):
            findings.extend(r)

    await emit("module_complete", {"module": "redirect", "results": findings})
    return findings


async def _test_redirect(url: str, params: dict, original_domain: str, emit) -> list[dict]:
    findings = []
    confirmed_params = set()

    for param_name in list(params.keys())[:3]:
        if param_name in confirmed_params:
            continue

        for payload in REDIRECT_PAYLOADS:
            test_params = dict(params)
            test_params[param_name] = [payload]

            parsed = urlparse(url)
            test_url = urlunparse(parsed._replace(query=urlencode(test_params, doseq=True)))

            try:
                async with httpx.AsyncClient(
                    timeout=TIMEOUT,
                    follow_redirects=False,
                    verify=False,
                ) as client:
                    resp = await client.get(test_url)

                    # Check if we got a redirect
                    if resp.status_code in [301, 302, 303, 307, 308]:
                        location = resp.headers.get("location", "")

                        # Check if redirect goes to attacker domain
                        if _redirects_to_attacker(location):
                            finding = {
                                "type": "redirect",
                                "subtype": "open_redirect",
                                "severity": "medium",
                                "title": f"Open Redirect via '{param_name}'",
                                "description": (
                                    f"The parameter '{param_name}' at {url} redirects users to arbitrary external URLs. "
                                    f"Payload '{payload}' caused redirect to '{location}'. "
                                    "Attackers use this for phishing — sending users to malicious sites via trusted links."
                                ),
                                "remediation": (
                                    "Validate redirect destinations against an allowlist of trusted domains. "
                                    "Use relative paths for internal redirects. "
                                    "If external redirects are needed, require explicit user confirmation."
                                ),
                                "evidence": {
                                    "url": test_url,
                                    "parameter": param_name,
                                    "payload": payload,
                                    "location": location,
                                    "status_code": resp.status_code,
                                },
                            }
                            findings.append(finding)
                            await emit("finding", finding)
                            confirmed_params.add(param_name)
                            break

                await asyncio.sleep(RATE_LIMIT_DELAY)
            except Exception as e:
                logger.debug("Redirect test error %s: %s", test_url, e)

    return findings


def _redirects_to_attacker(location: str) -> bool:
    if not location:
        return False
    location_lower = location.lower()
    return (
        ATTACKER_DOMAIN in location_lower
        or location.startswith("//attacker")
        or location.startswith("/\\")
        or location.startswith("\\/")
        or "javascript:" in location_lower
    )
