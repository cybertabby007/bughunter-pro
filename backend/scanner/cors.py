"""
CORS Misconfiguration Checker — tests for dangerous cross-origin resource sharing policies.
"""

import asyncio
import logging
from urllib.parse import urlparse

import httpx

logger = logging.getLogger(__name__)
TIMEOUT = httpx.Timeout(10.0)
RATE_LIMIT_DELAY = 0.3

ORIGIN_PAYLOADS = [
    ("attacker_domain",    "https://attacker.com"),
    ("null_origin",        "null"),
    ("subdomain_prefix",   None),   # computed per target: https://{domain}.attacker.com
    ("subdomain_suffix",   None),   # computed per target: https://attacker{domain}
]

API_ENDPOINTS_TO_TEST = [
    "/", "/api", "/api/v1", "/api/v2", "/graphql",
    "/user", "/account", "/profile", "/me",
]


async def run_cors(domain: str, endpoints: list[str], emit) -> list[dict]:
    findings = []

    await emit("progress", {"module": "cors", "step": "test", "message": "Testing CORS policies..."})

    targets = list(set(
        [f"https://{domain}{path}" for path in API_ENDPOINTS_TO_TEST]
        + [u for u in endpoints if urlparse(u).path in API_ENDPOINTS_TO_TEST][:10]
    ))[:20]

    tasks = [_test_cors(target, domain, emit) for target in targets]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    for r in results:
        if isinstance(r, list):
            findings.extend(r)

    await emit("module_complete", {"module": "cors", "results": findings})
    return findings


async def _test_cors(url: str, domain: str, emit) -> list[dict]:
    findings = []

    origins_to_test = [
        ("attacker_domain",     "https://attacker.com"),
        ("null_origin",         "null"),
        ("subdomain_prefix",    f"https://{domain}.attacker.com"),
        ("subdomain_suffix",    f"https://attacker{domain}"),
    ]

    try:
        async with httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=True, verify=False) as client:
            for origin_label, origin in origins_to_test:
                headers = {"Origin": origin}
                try:
                    resp = await client.get(url, headers=headers)
                    resp_headers = {k.lower(): v for k, v in resp.headers.items()}

                    acao = resp_headers.get("access-control-allow-origin", "")
                    acac = resp_headers.get("access-control-allow-credentials", "").lower()
                    acam = resp_headers.get("access-control-allow-methods", "")

                    # Critical: origin reflected AND credentials allowed
                    if acao == origin and acac == "true":
                        finding = {
                            "type": "cors",
                            "subtype": "origin_reflection_with_credentials",
                            "severity": "critical",
                            "title": f"CORS: Origin Reflected with Credentials Allowed at {url}",
                            "description": (
                                f"The server reflects the Origin '{origin}' in Access-Control-Allow-Origin "
                                "AND sets Access-Control-Allow-Credentials: true. "
                                "An attacker can read authenticated API responses from any web page, "
                                "potentially stealing session data or sensitive user information."
                            ),
                            "remediation": (
                                "Maintain an explicit whitelist of allowed origins. "
                                "Never use dynamic origin reflection with credentials enabled. "
                                "Validate the Origin header against a server-side allowlist."
                            ),
                            "evidence": {
                                "url": url,
                                "tested_origin": origin,
                                "acao": acao,
                                "acac": acac,
                            },
                        }
                        findings.append(finding)
                        await emit("finding", finding)

                    # High: origin reflected without credentials
                    elif acao == origin:
                        finding = {
                            "type": "cors",
                            "subtype": "origin_reflection",
                            "severity": "high",
                            "title": f"CORS: Origin Reflected at {url}",
                            "description": (
                                f"The server reflects arbitrary Origin headers in ACAO. "
                                f"Tested with '{origin}' — server returned ACAO: {acao}. "
                                "Without credentials this is lower risk, but could expose non-auth data."
                            ),
                            "remediation": "Whitelist specific trusted origins instead of reflecting the incoming Origin header.",
                            "evidence": {
                                "url": url,
                                "tested_origin": origin,
                                "acao": acao,
                            },
                        }
                        findings.append(finding)
                        await emit("finding", finding)

                    # High: null origin allowed with credentials
                    elif acao == "null" and acac == "true":
                        finding = {
                            "type": "cors",
                            "subtype": "null_origin_with_credentials",
                            "severity": "high",
                            "title": f"CORS: Null Origin Accepted with Credentials at {url}",
                            "description": (
                                "The server accepts the 'null' origin with credentials. "
                                "Sandboxed iframes send null as their origin — an attacker can exploit this "
                                "from a sandboxed page to read authenticated responses."
                            ),
                            "remediation": "Never allow 'null' as a trusted CORS origin.",
                            "evidence": {
                                "url": url,
                                "tested_origin": "null",
                                "acao": acao,
                                "acac": acac,
                            },
                        }
                        findings.append(finding)
                        await emit("finding", finding)

                    # Medium: wildcard methods
                    if acam == "*":
                        finding = {
                            "type": "cors",
                            "subtype": "wildcard_methods",
                            "severity": "medium",
                            "title": f"CORS: All Methods Allowed at {url}",
                            "description": (
                                "Access-Control-Allow-Methods: * allows all HTTP methods cross-origin, "
                                "including DELETE, PUT, PATCH which may have side effects."
                            ),
                            "remediation": "Specify only required HTTP methods in Access-Control-Allow-Methods.",
                            "evidence": {
                                "url": url,
                                "acam": acam,
                            },
                        }
                        if finding not in findings:
                            findings.append(finding)
                            await emit("finding", finding)

                    await asyncio.sleep(RATE_LIMIT_DELAY)
                except Exception as e:
                    logger.debug("CORS test error %s [%s]: %s", url, origin, e)

    except Exception as e:
        logger.warning("CORS test client error for %s: %s", url, e)

    return findings
