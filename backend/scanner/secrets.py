"""
Exposed Files & Secrets Scanner — checks for sensitive file exposures and secret leakage in JS.
"""

import asyncio
import logging
import re
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)
TIMEOUT = httpx.Timeout(10.0)
RATE_LIMIT_DELAY = 0.3

SENSITIVE_PATHS = [
    "/.env", "/.env.local", "/.env.production", "/.env.backup",
    "/.git/config", "/.git/HEAD", "/.git/COMMIT_EDITMSG",
    "/.gitignore", "/.svn/entries",
    "/wp-config.php", "/wp-config.php.bak", "/config.php",
    "/configuration.php", "/config.yml", "/config.yaml", "/config.json",
    "/database.yml", "/db.php", "/settings.py", "/local_settings.py",
    "/app/config/database.yml", "/backup.sql", "/backup.zip",
    "/dump.sql", "/database.sql", "/db_backup.sql",
    "/.htaccess", "/.htpasswd", "/server-status",
    "/phpinfo.php", "/info.php", "/test.php", "/debug.php",
    "/composer.json", "/composer.lock", "/package.json",
    "/package-lock.json", "/yarn.lock", "/Gemfile",
    "/requirements.txt", "/Dockerfile", "/docker-compose.yml",
    "/nginx.conf", "/apache.conf",
    "/.bash_history", "/.ssh/id_rsa", "/.ssh/known_hosts",
    "/id_rsa", "/private.key", "/server.key",
    "/crossdomain.xml", "/clientaccesspolicy.xml",
]

# Severity ratings for specific paths
CRITICAL_PATHS = {"/.git/config", "/.env", "/.env.local", "/.env.production",
                  "/.ssh/id_rsa", "/id_rsa", "/private.key", "/server.key",
                  "/wp-config.php", "/database.yml", "/backup.sql", "/dump.sql", "/database.sql"}
HIGH_PATHS = {"/.env.backup", "/.git/HEAD", "/.htpasswd", "/db_backup.sql",
              "/config.yml", "/config.yaml", "/local_settings.py"}

# Secret regex patterns
SECRET_PATTERNS = [
    ("AWS Access Key",         "critical", r"AKIA[0-9A-Z]{16}"),
    ("AWS Secret Key",         "critical", r"(?i)aws.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]"),
    ("Google API Key",         "high",     r"AIza[0-9A-Za-z\-_]{35}"),
    ("Firebase Key",           "high",     r"AAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{140}"),
    ("Stripe Publishable Key", "medium",   r"pk_(test|live)_[0-9a-zA-Z]{24}"),
    ("Stripe Secret Key",      "critical", r"sk_(test|live)_[0-9a-zA-Z]{24}"),
    ("GitHub Token",           "critical", r"ghp_[0-9a-zA-Z]{36}"),
    ("GitHub OAuth Token",     "critical", r"gho_[0-9a-zA-Z]{36}"),
    ("Slack Token",            "high",     r"xox[baprs]\-[0-9a-zA-Z]{10,48}"),
    ("Slack Webhook",          "high",     r"https://hooks\.slack\.com/services/[A-Z0-9]{9}/[A-Z0-9]{9}/[a-zA-Z0-9]{24}"),
    ("Twilio SID",             "high",     r"AC[a-zA-Z0-9]{32}"),
    ("SendGrid API Key",       "high",     r"SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}"),
    ("Mailgun API Key",        "high",     r"key-[0-9a-zA-Z]{32}"),
    ("JWT Token",              "medium",   r"eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.?[A-Za-z0-9\-_.+/=]*"),
    ("RSA Private Key",        "critical", r"-----BEGIN RSA PRIVATE KEY-----"),
    ("Private Key",            "critical", r"-----BEGIN PRIVATE KEY-----"),
    ("Generic Password",       "high",     r"(?i)password\s*[=:]\s*['\"][^'\"]{6,}['\"]"),
    ("Generic API Key",        "high",     r"(?i)api[_-]?key\s*[=:]\s*['\"][^'\"]{10,}['\"]"),
    ("Generic Secret",         "high",     r"(?i)secret\s*[=:]\s*['\"][^'\"]{8,}['\"]"),
    ("Database URL",           "critical", r"(mysql|postgresql|mongodb|redis)://[^\s'\"]+"),
    ("Internal IP Address",    "low",      r"(192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.)\d+\.\d+"),
    ("Email Address",          "info",     r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"),
]


async def run_secrets(domain: str, endpoints: list[str], emit) -> list[dict]:
    findings = []
    base_urls = [f"https://{domain}", f"http://{domain}"]

    await emit("progress", {"module": "secrets", "step": "file_check", "message": f"Checking {len(SENSITIVE_PATHS)} sensitive file paths..."})

    for base_url in base_urls[:1]:
        tasks = [_check_path(base_url, path, emit) for path in SENSITIVE_PATHS]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, dict):
                findings.append(r)

    await emit("progress", {"module": "secrets", "step": "js_analysis", "message": "Analysing JavaScript files for secrets..."})

    js_files = [u for u in endpoints if u.endswith(".js")][:30]
    js_tasks = [_analyse_js(url, emit) for url in js_files]
    js_results = await asyncio.gather(*js_tasks, return_exceptions=True)
    for r in js_results:
        if isinstance(r, list):
            findings.extend(r)

    await emit("module_complete", {"module": "secrets", "results": findings})
    return findings


async def _check_path(base_url: str, path: str, emit) -> dict | None:
    url = base_url.rstrip("/") + path
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=False, verify=False) as client:
            resp = await client.get(url)
            await asyncio.sleep(RATE_LIMIT_DELAY)

            if resp.status_code == 200 and len(resp.content) > 0:
                # Determine severity
                if path in CRITICAL_PATHS:
                    severity = "critical"
                elif path in HIGH_PATHS:
                    severity = "high"
                else:
                    severity = "medium"

                # Bump severity if secrets detected in content
                text = resp.text[:5000]
                for pat_name, pat_sev, pattern in SECRET_PATTERNS:
                    match = re.search(pattern, text)
                    if match:
                        severity = "critical"
                        break

                # Truncate sensitive content — show only first 500 chars for display
                preview = resp.text[:500] if resp.text else ""

                finding = {
                    "type": "exposed_file",
                    "url": url,
                    "path": path,
                    "severity": severity,
                    "title": f"Exposed Sensitive File: {path}",
                    "description": f"The file {path} is publicly accessible and may contain sensitive information.",
                    "remediation": "Restrict access to this file via server configuration or remove it from the web root.",
                    "evidence": {
                        "url": url,
                        "status_code": resp.status_code,
                        "content_length": len(resp.content),
                        "preview": preview,
                    },
                }
                await emit("finding", finding)
                return finding
    except Exception as e:
        logger.debug("Path check failed %s: %s", url, e)

    return None


async def _analyse_js(url: str, emit) -> list[dict]:
    findings = []
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT, verify=False) as client:
            resp = await client.get(url)
            if resp.status_code != 200:
                return findings

            content = resp.text[:200_000]  # max 200KB per JS file

            for pat_name, severity, pattern in SECRET_PATTERNS:
                matches = re.findall(pattern, content)
                if matches:
                    # Deduplicate
                    unique = list(set(str(m) for m in matches))[:5]
                    finding = {
                        "type": "secret_in_js",
                        "url": url,
                        "severity": severity,
                        "title": f"{pat_name} Found in JavaScript",
                        "description": f"Potential {pat_name} detected in {url}",
                        "remediation": "Remove secrets from client-side code. Use environment variables server-side.",
                        "evidence": {
                            "file": url,
                            "pattern": pat_name,
                            "matches": [m[:100] for m in unique],
                        },
                    }
                    findings.append(finding)
                    await emit("finding", finding)

            await asyncio.sleep(RATE_LIMIT_DELAY)
    except Exception as e:
        logger.debug("JS analysis failed %s: %s", url, e)

    return findings
