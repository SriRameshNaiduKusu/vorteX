"""Reflected XSS scanner.

Tests URL parameters with XSS payloads and checks if the payload is reflected
in the HTTP response. Supports context-aware detection (attribute, script tag,
HTML body) and a fast mode with a reduced payload set.
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

# Markers used to detect reflection context
_ATTR_PATTERNS = ['"', "'", "onerror=", "onload=", "onfocus="]
_SCRIPT_PATTERNS = ["</script>", "<script>", "alert("]
_SENTINEL = "vx_xss_"

_SEVERITY = "HIGH"


def _detect_context(payload: str, body: str) -> str:
    """Return a human-readable context description for a reflected payload."""
    lower = body.lower()
    payload_lower = payload.lower()
    idx = lower.find(payload_lower)
    if idx == -1:
        return "html body"
    surrounding = body[max(0, idx - 30): idx + len(payload) + 30]
    if any(p in surrounding for p in _SCRIPT_PATTERNS):
        return "inside <script> tag"
    if "<" in surrounding and "=" in surrounding:
        return "inside HTML attribute"
    return "html body"


async def _test_url(
    session,
    url: str,
    payloads: list[str],
    proxy=None,
    timeout: float = 10,
    random_ua: bool = False,
    rate_limit=None,
) -> list[dict]:
    """Test a single URL's parameters with XSS payloads."""
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
                    if payload.lower() in body.lower():
                        context = _detect_context(payload, body)
                        findings.append({
                            "url": url,
                            "parameter": param,
                            "payload": payload,
                            "severity": _SEVERITY,
                            "context": context,
                            "status": resp.status,
                        })
                        # One finding per parameter is enough
                        break
            except Exception as exc:
                logging.debug(f"XSS test error for {test_url}: {exc}")
            if rate_limit:
                await asyncio.sleep(1.0 / rate_limit)

    return findings


async def scan_xss(
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
    """Scan *urls* for reflected XSS vulnerabilities.

    Parameters
    ----------
    urls : list[str]
        Target URLs to test.
    output_file : str or None
        Path to write results.
    output_format : str
        ``'json'`` or ``'txt'``.
    fast : bool
        If True, use a reduced payload set (first 20 payloads).

    Returns
    -------
    list[dict]
        XSS findings.
    """
    display_banner()
    all_payloads = load_payloads("xss.txt")
    payloads = all_payloads[:20] if fast else all_payloads
    print(
        f"{Fore.CYAN}[*] Testing {len(urls)} URL(s) for reflected XSS "
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
                        f"{Fore.RED}[!] XSS [{f['severity']}]: {f['url']} | "
                        f"param={f['parameter']} | context={f['context']}{Style.RESET_ALL}"
                    )
                all_findings.extend(findings)
        pbar.update(1)

    with tqdm(total=len(urls), desc="XSS Scan", ncols=80) as pbar:
        await asyncio.gather(*[handle(u, pbar) for u in urls])

    if not all_findings:
        print(f"{Fore.GREEN}[✔] No reflected XSS vulnerabilities detected.{Style.RESET_ALL}")

    if output_file and all_findings:
        with open(output_file, "w", encoding="utf-8") as fh:
            if output_format == "json":
                json.dump(all_findings, fh, indent=2)
            else:
                for f in all_findings:
                    fh.write(
                        f"[{f['severity']}] {f['url']} | param={f['parameter']} | "
                        f"payload={f['payload']} | context={f['context']}\n"
                    )

    print(
        f"{Fore.CYAN}[✔] XSS scan complete — {len(all_findings)} finding(s).{Style.RESET_ALL}"
    )
    return all_findings
