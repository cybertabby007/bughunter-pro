"""
Subdomain Takeover Detector — identifies subdomains pointing to unclaimed external services.
"""

import asyncio
import logging

import dns.resolver
import httpx

logger = logging.getLogger(__name__)
TIMEOUT = httpx.Timeout(10.0)
RATE_LIMIT_DELAY = 0.3

# Fingerprints: service_name → (cname_patterns, response_fingerprint)
TAKEOVER_FINGERPRINTS = [
    ("GitHub Pages",    ["github.io"],              "There isn't a GitHub Pages site here"),
    ("Heroku",          ["herokuapp.com"],           "No such app"),
    ("AWS S3",          ["s3.amazonaws.com",
                         "s3-website"],              "NoSuchBucket"),
    ("Azure",           ["azurewebsites.net",
                         "cloudapp.net"],            "404 Web Site not found"),
    ("Shopify",         ["myshopify.com"],           "Sorry, this shop is currently unavailable"),
    ("Fastly",          ["fastly.net"],              "Fastly error: unknown domain"),
    ("SendGrid",        ["sendgrid.net"],            "The domain you are looking for does not exist"),
    ("Pantheon",        ["pantheonsite.io",
                         "getpantheon.com"],         "404 error unknown site"),
    ("Tumblr",          ["tumblr.com"],              "There's nothing here"),
    ("WordPress.com",   ["wordpress.com"],           "Do you want to register"),
    ("Ghost",           ["ghost.io"],                "The thing you were looking for is no longer here"),
    ("Surge.sh",        ["surge.sh"],                "project not found"),
    ("Readme.io",       ["readme.io",
                         "readmessl.com"],           "Project doesnt exist"),
    ("Zendesk",         ["zendesk.com"],             "Help Center Closed"),
    ("Intercom",        ["intercom.io",
                         "custom.intercom.io"],      "Uh oh. That page doesn't exist."),
    ("Cargo",           ["cargocollective.com"],     "404 Not Found"),
    ("UserVoice",       ["uservoice.com"],           "This UserVoice subdomain is currently available!"),
    ("Bitbucket",       ["bitbucket.io"],            "Repository not found"),
]


async def run_takeover(domain: str, subdomains: list[dict], emit) -> list[dict]:
    findings = []

    await emit("progress", {"module": "takeover", "step": "check", "message": f"Checking {len(subdomains)} subdomains for takeover vulnerabilities..."})

    tasks = [_check_takeover(s, emit) for s in subdomains[:50] if s.get("subdomain")]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    for r in results:
        if isinstance(r, dict):
            findings.append(r)

    await emit("module_complete", {"module": "takeover", "results": findings})
    return findings


async def _check_takeover(subdomain_info: dict, emit) -> dict | None:
    subdomain = subdomain_info.get("subdomain", "")
    cname = subdomain_info.get("cname") or await _get_cname(subdomain)

    if not cname:
        return None

    cname_lower = cname.lower()

    for service, cname_patterns, fingerprint in TAKEOVER_FINGERPRINTS:
        if any(pattern in cname_lower for pattern in cname_patterns):
            # Check if the response contains the takeover fingerprint
            is_vulnerable = await _check_fingerprint(subdomain, fingerprint)
            if is_vulnerable:
                finding = {
                    "type": "takeover",
                    "severity": "high",
                    "title": f"Subdomain Takeover: {subdomain} → {service}",
                    "description": (
                        f"The subdomain '{subdomain}' has a CNAME record pointing to '{cname}' ({service}), "
                        f"but the service shows: \"{fingerprint}\". "
                        "This indicates the service account has been deleted/unclaimed, "
                        "allowing an attacker to claim the external service and serve content "
                        "under the trusted subdomain."
                    ),
                    "remediation": (
                        f"Either remove the DNS CNAME record for '{subdomain}' "
                        f"or re-claim the {service} service and point it back to this subdomain."
                    ),
                    "evidence": {
                        "subdomain": subdomain,
                        "cname": cname,
                        "service": service,
                        "fingerprint": fingerprint,
                    },
                }
                await emit("finding", finding)
                return finding

    return None


async def _get_cname(subdomain: str) -> str | None:
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3
        resolver.lifetime = 3
        answers = resolver.resolve(subdomain, "CNAME")
        return str(answers[0]).rstrip(".")
    except Exception:
        return None


async def _check_fingerprint(subdomain: str, fingerprint: str) -> bool:
    for scheme in ["https", "http"]:
        try:
            async with httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=True, verify=False) as client:
                resp = await client.get(f"{scheme}://{subdomain}/")
                if fingerprint.lower() in resp.text.lower():
                    return True
            await asyncio.sleep(RATE_LIMIT_DELAY)
        except Exception:
            continue
    return False
