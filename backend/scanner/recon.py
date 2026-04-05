"""
Recon Engine — subdomain discovery, port scanning, URL/endpoint discovery.
All scanning is async and non-blocking with a 10-second per-request timeout.
"""

import asyncio
import json
import logging
import re
from typing import AsyncGenerator, Optional
from urllib.parse import urljoin, urlparse

import dns.resolver
import httpx
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

TIMEOUT = httpx.Timeout(10.0)
COMMON_PORTS = [80, 443, 8080, 8443, 3000, 8000, 9000]

ADMIN_PATHS = [
    "/admin", "/administrator", "/dashboard", "/panel",
    "/cp", "/manage", "/backend", "/login", "/signin",
    "/auth", "/user/login", "/admin/login",
]

API_PATHS = [
    "/api", "/v1", "/v2", "/v3", "/graphql", "/swagger",
    "/api-docs", "/swagger-ui.html", "/openapi.json",
    "/api/v1", "/api/v2", "/rest",
]

RATE_LIMIT_DELAY = 0.3  # seconds between requests


async def run_recon(domain: str, emit) -> dict:
    """
    Run full recon on the target domain.
    emit(event_type, data) streams progress back to the caller.
    """
    results = {
        "subdomains": [],
        "ports": [],
        "endpoints": [],
        "admin_panels": [],
        "api_endpoints": [],
        "robots": [],
        "sitemap": [],
    }

    await emit("progress", {"module": "recon", "step": "subdomain_discovery", "message": "Starting subdomain discovery via crt.sh..."})

    subdomains = await discover_subdomains(domain, emit)
    results["subdomains"] = subdomains

    await emit("progress", {"module": "recon", "step": "port_scan", "message": f"Probing ports on {len(subdomains) + 1} hosts..."})

    all_hosts = [domain] + [s["subdomain"] for s in subdomains if s.get("alive")]
    port_results = await scan_ports(all_hosts[:10], emit)  # cap at 10 to avoid abuse
    results["ports"] = port_results

    await emit("progress", {"module": "recon", "step": "crawl", "message": "Crawling target for endpoints..."})

    crawl_data = await crawl_target(f"https://{domain}", emit)
    results["endpoints"] = crawl_data["endpoints"]
    results["admin_panels"] = crawl_data["admin_panels"]
    results["api_endpoints"] = crawl_data["api_endpoints"]
    results["robots"] = await fetch_robots(f"https://{domain}")
    results["sitemap"] = await fetch_sitemap(f"https://{domain}")

    await emit("module_complete", {"module": "recon", "results": results})
    return results


# ─────────────────────────── Subdomain Discovery ────────────────────────────

async def discover_subdomains(domain: str, emit) -> list[dict]:
    subdomains_raw: set[str] = set()

    # 1. crt.sh certificate transparency
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=True) as client:
            resp = await client.get(f"https://crt.sh/?q=%.{domain}&output=json")
            if resp.status_code == 200:
                entries = resp.json()
                for entry in entries:
                    name = entry.get("name_value", "")
                    for n in name.split("\n"):
                        n = n.strip().lower().lstrip("*.")
                        if n.endswith(domain) and n != domain:
                            subdomains_raw.add(n)
                await emit("progress", {"module": "recon", "step": "crtsh", "message": f"Found {len(subdomains_raw)} subdomains via crt.sh"})
    except Exception as e:
        logger.warning("crt.sh failed: %s", e)

    # 2. DNS brute-force a small common list
    common_prefixes = [
        "www", "mail", "ftp", "smtp", "pop", "api", "dev", "staging",
        "test", "beta", "app", "static", "cdn", "admin", "blog", "shop",
        "vpn", "remote", "secure", "portal", "m", "mobile", "support",
        "help", "git", "gitlab", "jenkins", "jira", "confluence",
    ]
    brute_tasks = [_dns_brute(f"{p}.{domain}") for p in common_prefixes]
    brute_results = await asyncio.gather(*brute_tasks, return_exceptions=True)
    for sub, result in zip(common_prefixes, brute_results):
        if isinstance(result, str):
            subdomains_raw.add(f"{sub}.{domain}")

    await emit("progress", {"module": "recon", "step": "dns_brute", "message": f"Total unique subdomains: {len(subdomains_raw)}"})

    # 3. Probe each subdomain
    probe_tasks = [_probe_subdomain(s, domain) for s in list(subdomains_raw)[:50]]
    probed = await asyncio.gather(*probe_tasks, return_exceptions=True)

    results = []
    for item in probed:
        if isinstance(item, dict):
            results.append(item)
            if item.get("alive"):
                await emit("finding", {
                    "type": "subdomain",
                    "severity": "info",
                    "title": f"Live subdomain: {item['subdomain']}",
                    "description": f"Status {item.get('status_code')} | IP: {item.get('ip')} | Server: {item.get('server', 'unknown')}",
                    "evidence": item,
                })

    return results


async def _dns_brute(fqdn: str) -> Optional[str]:
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3
        resolver.lifetime = 3
        answers = resolver.resolve(fqdn, "A")
        return str(answers[0])
    except Exception:
        return None


async def _probe_subdomain(subdomain: str, parent_domain: str) -> dict:
    record = {"subdomain": subdomain, "alive": False, "ip": None, "cname": None, "status_code": None, "title": None, "server": None}
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3
        resolver.lifetime = 3

        # A record
        try:
            a_records = resolver.resolve(subdomain, "A")
            record["ip"] = str(a_records[0])
        except Exception:
            pass

        # CNAME
        try:
            cname_records = resolver.resolve(subdomain, "CNAME")
            record["cname"] = str(cname_records[0])
        except Exception:
            pass

        if not record["ip"] and not record["cname"]:
            return record

        # HTTP probe
        for scheme in ["https", "http"]:
            try:
                async with httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=True, verify=False) as client:
                    resp = await client.get(f"{scheme}://{subdomain}/")
                    record["alive"] = True
                    record["status_code"] = resp.status_code
                    record["server"] = resp.headers.get("server", "")
                    soup = BeautifulSoup(resp.text[:4096], "html.parser")
                    title_tag = soup.find("title")
                    record["title"] = title_tag.text.strip()[:80] if title_tag else ""
                    break
            except Exception:
                continue

        await asyncio.sleep(RATE_LIMIT_DELAY)
    except Exception as e:
        logger.debug("Probe failed for %s: %s", subdomain, e)

    return record


# ─────────────────────────── Port & Service Discovery ───────────────────────

async def scan_ports(hosts: list[str], emit) -> list[dict]:
    results = []
    for host in hosts:
        host_results = {"host": host, "open_ports": []}
        tasks = [_check_port(host, port) for port in COMMON_PORTS]
        port_checks = await asyncio.gather(*tasks, return_exceptions=True)
        for port, info in zip(COMMON_PORTS, port_checks):
            if isinstance(info, dict) and info.get("open"):
                host_results["open_ports"].append(info)
                if port not in [80, 443]:
                    await emit("finding", {
                        "type": "open_port",
                        "severity": "low",
                        "title": f"Non-standard port open: {host}:{port}",
                        "description": f"Service detected on port {port}. Server: {info.get('server', 'unknown')}",
                        "evidence": info,
                    })
        results.append(host_results)
        await asyncio.sleep(RATE_LIMIT_DELAY)
    return results


async def _check_port(host: str, port: int) -> dict:
    scheme = "https" if port in [443, 8443] else "http"
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(5.0), verify=False) as client:
            resp = await client.get(f"{scheme}://{host}:{port}/", follow_redirects=False)
            return {
                "open": True,
                "port": port,
                "scheme": scheme,
                "status_code": resp.status_code,
                "server": resp.headers.get("server", ""),
                "powered_by": resp.headers.get("x-powered-by", ""),
            }
    except Exception:
        return {"open": False, "port": port}


# ─────────────────────────── URL & Endpoint Discovery ───────────────────────

async def crawl_target(base_url: str, emit, max_depth: int = 3) -> dict:
    visited: set[str] = set()
    all_endpoints: list[str] = []
    admin_panels: list[dict] = []
    api_endpoints: list[dict] = []

    queue = [(base_url, 0)]
    domain = urlparse(base_url).netloc

    async with httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=True, verify=False) as client:
        while queue:
            url, depth = queue.pop(0)
            if url in visited or depth > max_depth or len(visited) > 200:
                continue
            visited.add(url)
            await asyncio.sleep(RATE_LIMIT_DELAY)

            try:
                resp = await client.get(url)
                content_type = resp.headers.get("content-type", "")
                if "text/html" not in content_type and "javascript" not in content_type:
                    continue

                all_endpoints.append(url)
                soup = BeautifulSoup(resp.text, "html.parser")

                # Collect links
                for tag in soup.find_all(["a", "link"], href=True):
                    href = tag["href"]
                    abs_url = urljoin(url, href)
                    if urlparse(abs_url).netloc == domain and abs_url not in visited:
                        queue.append((abs_url, depth + 1))

                # Collect forms
                for form in soup.find_all("form"):
                    action = form.get("action", "")
                    all_endpoints.append(urljoin(url, action))

                # JS files
                for script in soup.find_all("script", src=True):
                    src = urljoin(url, script["src"])
                    if urlparse(src).netloc == domain:
                        all_endpoints.append(src)

            except Exception as e:
                logger.debug("Crawl error at %s: %s", url, e)

        # Check admin panels
        for path in ADMIN_PATHS:
            check_url = f"{base_url.rstrip('/')}{path}"
            if check_url not in visited:
                try:
                    resp = await client.get(check_url)
                    if resp.status_code in [200, 301, 302, 403, 401]:
                        panel = {"url": check_url, "status": resp.status_code}
                        admin_panels.append(panel)
                        await emit("finding", {
                            "type": "admin_panel",
                            "severity": "medium" if resp.status_code in [200, 403] else "low",
                            "title": f"Admin panel discovered: {path}",
                            "description": f"Admin path {check_url} returned HTTP {resp.status_code}",
                            "evidence": panel,
                        })
                    await asyncio.sleep(RATE_LIMIT_DELAY)
                except Exception:
                    pass

        # Check API endpoints
        for path in API_PATHS:
            check_url = f"{base_url.rstrip('/')}{path}"
            if check_url not in visited:
                try:
                    resp = await client.get(check_url)
                    if resp.status_code in [200, 301, 302, 403, 401]:
                        ep = {"url": check_url, "status": resp.status_code}
                        api_endpoints.append(ep)
                        await emit("finding", {
                            "type": "api_endpoint",
                            "severity": "info",
                            "title": f"API endpoint discovered: {path}",
                            "description": f"API path {check_url} returned HTTP {resp.status_code}",
                            "evidence": ep,
                        })
                    await asyncio.sleep(RATE_LIMIT_DELAY)
                except Exception:
                    pass

    return {
        "endpoints": list(set(all_endpoints))[:500],
        "admin_panels": admin_panels,
        "api_endpoints": api_endpoints,
    }


async def fetch_robots(base_url: str) -> list[str]:
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT, verify=False) as client:
            resp = await client.get(f"{base_url}/robots.txt")
            if resp.status_code == 200:
                lines = resp.text.splitlines()
                return [l.split(":", 1)[1].strip() for l in lines if l.startswith(("Disallow:", "Allow:"))]
    except Exception:
        pass
    return []


async def fetch_sitemap(base_url: str) -> list[str]:
    urls = []
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT, verify=False) as client:
            resp = await client.get(f"{base_url}/sitemap.xml")
            if resp.status_code == 200:
                soup = BeautifulSoup(resp.text, "xml")
                urls = [loc.text for loc in soup.find_all("loc")][:100]
    except Exception:
        pass
    return urls
