"""CRLF (Carriage Return Line Feed) Injection scanner.

Injects CRLF payloads into URL query parameters and checks whether injected
headers (e.g., Set-Cookie, X-Injected, Location) appear in the HTTP response
headers, or whether the response body contains HTTP response splitting artefacts.

Uses ``allow_redirects=False`` to catch Location header injections before the
HTTP client follows them.
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

# Markers injected by the payloads and how to describe them
_CRLF_MARKERS: list[tuple[str, str]] = [
    ("crlftest=vortex", "Set-Cookie injection"),
    ("vortex-crlf-test", "Header injection"),
    ("evil.com", "Location header injection"),
]


def _check_crlf(resp_headers: dict, body: str) -> tuple[bool, str]:
    """Check if CRLF injection succeeded by examining response headers and body.

    Parameters
    ----------
    resp_headers : dict
        HTTP response headers (header name → value, case-insensitive values).
    body : str
        HTTP response body.

    Returns
    -------
    tuple[bool, str]
        ``(True, description)`` if injection was detected, else ``(False, \"\")``.
    """
    for _header_name, header_value in resp_headers.items():
        for marker, description in _CRLF_MARKERS:
            if marker in header_value.lower():
                return True, description
    # Check body for HTTP response splitting (XSS via CRLF)
    if "<script>alert(1)</script>" in body.lower():
        return True, "HTTP response splitting (XSS via CRLF)"
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
    """Test a single URL's query parameters with CRLF payloads."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    if not params:
        return []

    req_kwargs: dict = {}
    if proxy:
        req_kwargs["proxy"] = proxy

    headers: dict = {}
    if random_ua:
        headers["User-Agent"] = random.choice(USER_AGENTS)

    findings: list[dict] = []

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
                    allow_redirects=False,
                    **req_kwargs,
                ) as resp:
                    resp_headers = dict(resp.headers)
                    try:
                        body = await resp.text(errors="replace")
                    except Exception:
                        body = ""
                    found, evidence = _check_crlf(resp_headers, body)
                    if found:
                        findings.append({
                            "url": url,
                            "parameter": param,
                            "payload": payload,
                            "severity": "HIGH",
                            "evidence": evidence,
                            "status": resp.status,
                        })
                        # One finding per parameter is enough
                        break
            except Exception as exc:
                logging.debug(f"CRLF test error for {test_url}: {exc}")
            if rate_limit:
                await asyncio.sleep(1.0 / rate_limit)

    return findings


async def scan_crlf(
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
    """Scan *urls* for CRLF injection vulnerabilities.

    Parameters
    ----------
    urls : list[str]
        Target URLs to test.
    output_file : str or None
        Path to write results.
    output_format : str
        ``'json'`` or ``'txt'``.
    fast : bool
        If True, use the first 10 payloads only.

    Returns
    -------
    list[dict]
        CRLF findings.
    """
    display_banner()
    all_payloads = load_payloads("crlf.txt")
    payloads = all_payloads[:10] if fast else all_payloads
    print(
        f"{Fore.CYAN}[*] Testing {len(urls)} URL(s) for CRLF injection "
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
                        f"{Fore.RED}[!] CRLF [HIGH]: {f['url']} | "
                        f"param={f['parameter']} | evidence={f['evidence']}{Style.RESET_ALL}"
                    )
                all_findings.extend(findings)
        pbar.update(1)

    with tqdm(total=len(urls), desc="CRLF Scan", ncols=80) as pbar:
        await asyncio.gather(*[handle(u, pbar) for u in urls])

    if not all_findings:
        print(f"{Fore.GREEN}[✔] No CRLF injection vulnerabilities detected.{Style.RESET_ALL}")

    if output_file and all_findings:
        with open(output_file, "w", encoding="utf-8") as fh:
            if output_format == "json":
                json.dump(all_findings, fh, indent=2)
            else:
                for f in all_findings:
                    fh.write(
                        f"[{f['severity']}] {f['url']} | param={f['parameter']} | "
                        f"payload={f['payload']} | evidence={f['evidence']}\n"
                    )

    print(
        f"{Fore.CYAN}[✔] CRLF scan complete — {len(all_findings)} finding(s).{Style.RESET_ALL}"
    )
    return all_findings
