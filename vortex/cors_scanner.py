"""CORS misconfiguration scanner.

Tests URLs for common CORS misconfigurations by injecting malicious Origin
headers and inspecting the Access-Control-* response headers.
"""

import asyncio
import json
import logging
import random

import aiohttp
from colorama import Fore, Style

from vortex.utils import stop_event, display_banner
from vortex.user_agents import USER_AGENTS

# Test Origins to inject
_TEST_ORIGINS = [
    "https://evil.com",
    "null",
]

_SEVERITY_CRITICAL = "CRITICAL"
_SEVERITY_HIGH = "HIGH"
_SEVERITY_MEDIUM = "MEDIUM"


def _get_evil_origin(target_url):
    """Return a domain-specific evil origin for the given target URL."""
    try:
        from urllib.parse import urlparse
        host = urlparse(target_url).netloc or target_url
        return f"https://{host}.evil.com"
    except Exception:
        return "https://target.evil.com"


async def _check_url_cors(session, url, proxy=None, timeout=10, random_ua=False):
    """Return a list of CORS findings for a single URL."""
    req_kwargs = {}
    if proxy:
        req_kwargs["proxy"] = proxy

    headers_base = {}
    if random_ua:
        headers_base["User-Agent"] = random.choice(USER_AGENTS)

    findings = []
    evil_origin = _get_evil_origin(url)
    test_origins = [evil_origin] + _TEST_ORIGINS

    for origin in test_origins:
        if stop_event.is_set():
            break
        headers = {**headers_base, "Origin": origin}
        try:
            async with session.get(
                url,
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=timeout),
                allow_redirects=True,
                **req_kwargs,
            ) as resp:
                acao = resp.headers.get("Access-Control-Allow-Origin", "")
                acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()

                if not acao:
                    continue

                reflected = acao == origin or acao == "*"
                if not reflected:
                    continue

                credentials = acac == "true"
                if origin == "null" and acao == "null":
                    severity = _SEVERITY_MEDIUM
                    desc = "null origin reflected"
                elif reflected and credentials:
                    severity = _SEVERITY_CRITICAL
                    desc = f"Origin '{origin}' reflected with credentials=true"
                else:
                    severity = _SEVERITY_HIGH
                    desc = f"Origin '{origin}' reflected"

                findings.append({
                    "url": url,
                    "origin_tested": origin,
                    "acao": acao,
                    "acac": acac,
                    "severity": severity,
                    "description": desc,
                })
        except Exception as exc:
            logging.debug(f"CORS check error for {url}: {exc}")

    return findings


async def check_cors(
    urls,
    output_file=None,
    output_format="txt",
    proxy=None,
    timeout=10,
    random_ua=False,
    rate_limit=None,
    max_threads=20,
):
    """Test *urls* for CORS misconfigurations.

    Parameters
    ----------
    urls : list[str]
        Target URLs to test.
    output_file : str or None
        Path to write results.
    output_format : str
        ``'json'`` or ``'txt'``.

    Returns
    -------
    list[dict]
        CORS findings.
    """
    display_banner()
    print(
        f"{Fore.CYAN}[*] Testing {len(urls)} URL(s) for CORS "
        f"misconfigurations...{Style.RESET_ALL}"
    )

    all_findings = []
    sem = asyncio.Semaphore(max_threads)
    connector = aiohttp.TCPConnector(ssl=False)

    async def handle(url):
        if stop_event.is_set():
            return
        async with sem:
            async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False)) as session:
                findings = await _check_url_cors(session, url, proxy, timeout, random_ua)
                for f in findings:
                    sev = f["severity"]
                    color = (
                        Fore.RED if sev == _SEVERITY_CRITICAL
                        else Fore.YELLOW if sev == _SEVERITY_HIGH
                        else Fore.MAGENTA
                    )
                    print(
                        f"{color}[!] CORS [{sev}]: {f['url']} | "
                        f"{f['description']}{Style.RESET_ALL}"
                    )
                all_findings.extend(findings)
            if rate_limit:
                await asyncio.sleep(1.0 / rate_limit)

    async with aiohttp.ClientSession(connector=connector):
        await asyncio.gather(*[handle(u) for u in urls])

    if not all_findings:
        print(f"{Fore.GREEN}[✔] No CORS misconfigurations detected.{Style.RESET_ALL}")

    if output_file and all_findings:
        with open(output_file, "w") as fh:
            if output_format == "json":
                json.dump(all_findings, fh, indent=2)
            else:
                for f in all_findings:
                    fh.write(
                        f"[{f['severity']}] {f['url']} | {f['description']}\n"
                    )

    print(
        f"{Fore.CYAN}[✔] CORS scan complete — "
        f"{len(all_findings)} finding(s).{Style.RESET_ALL}"
    )
    return all_findings
