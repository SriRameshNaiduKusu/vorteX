"""SSRF (Server-Side Request Forgery) scanner.

Tests URL parameters with SSRF payloads, including:
- Internal IP addresses (127.0.0.1, localhost, etc.)
- Cloud metadata service URLs (AWS, GCP, Azure)
- Protocol smuggling payloads (file://, gopher://, dict://)

Detects potential SSRF by checking for internal content or metadata
indicators in the response body.
"""

import asyncio
import json
import logging
import random
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse

import aiohttp
from colorama import Fore, Style
from tqdm import tqdm

from vortex.payloads import load_payloads
from vortex.utils import stop_event, display_banner
from vortex.user_agents import USER_AGENTS

# Patterns that indicate a successful SSRF response
_SSRF_INDICATORS = [
    # AWS metadata
    "ami-id",
    "instance-id",
    "instance-type",
    "security-credentials",
    "iam/security-credentials",
    "user-data",
    # GCP metadata
    "computeMetadata",
    "google-compute-engine",
    "instance/id",
    "project/project-id",
    # Azure metadata
    "azure",
    "subscriptionId",
    "resourceGroupName",
    # Linux file content
    "root:x:0:0",
    "root:!",
    "127.0.0.1",
    "localhost",
    # Internal service banners
    "ElasticSearch",
    "X-Powered-By: Express",
    "Server: Apache",
    "Redis",
]


def _looks_like_ssrf(body: str) -> tuple[bool, str]:
    """Check if response body contains SSRF indicator strings."""
    body_lower = body.lower()
    for indicator in _SSRF_INDICATORS:
        if indicator.lower() in body_lower:
            return True, indicator
    return False, ""


async def _test_url(
    session,
    url: str,
    payloads: list[str],
    proxy=None,
    timeout: float = 10,
    random_ua: bool = False,
    rate_limit=None,
) -> list[dict]:
    """Test a single URL's parameters with SSRF payloads."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    if not params:
        return []

    req_kwargs = {}
    if proxy:
        req_kwargs["proxy"] = proxy

    headers = {}
    if random_ua:
        headers["User-Agent"] = random.choice(USER_AGENTS)

    findings = []

    for param in params:
        for payload in payloads:
            if stop_event.is_set():
                return findings
            test_params = {k: v[0] for k, v in params.items()}
            test_params[param] = payload
            new_query = urlencode(test_params)
            test_url = urlunparse(parsed._replace(query=new_query))
            try:
                async with session.get(
                    test_url,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=timeout),
                    allow_redirects=True,
                    **req_kwargs,
                ) as resp:
                    try:
                        body = await resp.text(errors="replace")
                    except Exception:
                        body = ""
                    found, indicator = _looks_like_ssrf(body)
                    if found:
                        findings.append({
                            "url": url,
                            "parameter": param,
                            "payload": payload,
                            "indicator": indicator,
                            "severity": "HIGH",
                            "status": resp.status,
                        })
                        break
            except Exception as exc:
                logging.debug(f"SSRF test error for {test_url}: {exc}")
            if rate_limit:
                await asyncio.sleep(1.0 / rate_limit)

    return findings


async def scan_ssrf(
    urls,
    output_file=None,
    output_format="txt",
    proxy=None,
    timeout: float = 10,
    random_ua: bool = False,
    rate_limit=None,
    max_threads: int = 20,
    fast: bool = False,
):
    """Scan *urls* for SSRF vulnerabilities.

    Parameters
    ----------
    urls : list[str]
        Target URLs to test.
    output_file : str or None
        Path to write results.
    output_format : str
        ``'json'`` or ``'txt'``.
    fast : bool
        If True, use a reduced payload set (first 15 payloads).

    Returns
    -------
    list[dict]
        SSRF findings.
    """
    display_banner()
    all_payloads = load_payloads("ssrf.txt")
    payloads = all_payloads[:15] if fast else all_payloads
    print(
        f"{Fore.CYAN}[*] Testing {len(urls)} URL(s) for SSRF vulnerabilities "
        f"({len(payloads)} payloads){' [fast mode]' if fast else ''}...{Style.RESET_ALL}"
    )

    all_findings: list[dict] = []
    sem = asyncio.Semaphore(max_threads)

    async def handle(url, pbar):
        if stop_event.is_set():
            pbar.update(1)
            return
        async with sem:
            async with aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=False)
            ) as session:
                findings = await _test_url(
                    session, url, payloads, proxy, timeout, random_ua, rate_limit
                )
                for f in findings:
                    tqdm.write(
                        f"{Fore.RED}[!] SSRF [{f['severity']}]: {f['url']} | "
                        f"param={f['parameter']} | indicator={f['indicator']}{Style.RESET_ALL}"
                    )
                all_findings.extend(findings)
        pbar.update(1)

    with tqdm(total=len(urls), desc="SSRF Scan", ncols=80) as pbar:
        await asyncio.gather(*[handle(u, pbar) for u in urls])

    if not all_findings:
        print(f"{Fore.GREEN}[✔] No SSRF vulnerabilities detected.{Style.RESET_ALL}")

    if output_file and all_findings:
        with open(output_file, "w", encoding="utf-8") as fh:
            if output_format == "json":
                json.dump(all_findings, fh, indent=2)
            else:
                for f in all_findings:
                    fh.write(
                        f"[{f['severity']}] {f['url']} | param={f['parameter']} | "
                        f"payload={f['payload']} | indicator={f['indicator']}\n"
                    )

    print(
        f"{Fore.CYAN}[✔] SSRF scan complete — {len(all_findings)} finding(s).{Style.RESET_ALL}"
    )
    return all_findings
