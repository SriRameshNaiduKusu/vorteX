"""Open redirect detection module.

Tests URL parameters for open redirect vulnerabilities by injecting
common redirect payloads and checking the Location header or final URL.
"""

import asyncio
import json
import logging
import random
from urllib.parse import urlparse, urlencode, parse_qs

import aiohttp
from colorama import Fore, Style
from tqdm import tqdm

from vortex.utils import stop_event, display_banner
from vortex.user_agents import USER_AGENTS

# Common redirect parameter names to test
REDIRECT_PARAMS = [
    "url", "redirect", "redirect_url", "next", "goto", "target",
    "dest", "destination", "rurl", "return", "returnUrl", "return_url",
    "continue", "out", "view", "redir", "callback", "link", "to",
    "forward", "location",
]

# Reduced set of the most common redirect params for fast mode / URLs without query params
REDIRECT_PARAMS_FAST = ["url", "redirect", "next", "goto", "return"]

# Redirect test payloads
REDIRECT_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "/\\evil.com",
    "https:evil.com",
    "//evil.com/%2f..",
    "https://evil.com%23@target.com",
]

# Reduced payloads for fast mode
REDIRECT_PAYLOADS_FAST = [
    "https://evil.com",
    "//evil.com",
    "/\\evil.com",
]

_EVIL_HOST = "evil.com"


def _location_points_to_evil(location):
    """Return True if the Location header points to the evil host."""
    if not location:
        return False
    try:
        parsed = urlparse(location)
        host = parsed.netloc.lower().lstrip("www.")
        if _EVIL_HOST in host:
            return True
        # Handle protocol-relative or path-based tricks
        if location.startswith("//"):
            host2 = location[2:].split("/")[0].lower()
            if _EVIL_HOST in host2:
                return True
    except Exception:
        pass
    return False


async def _test_param(session, url, param, payload, proxy=None, timeout=10, random_ua=False):
    """Inject *payload* into *param* of *url* and check for open redirect."""
    parsed = urlparse(url)
    query = parse_qs(parsed.query, keep_blank_values=True)
    query[param] = [payload]
    new_query = urlencode(query, doseq=True)
    test_url = parsed._replace(query=new_query).geturl()

    headers = {}
    if random_ua:
        headers["User-Agent"] = random.choice(USER_AGENTS)
    req_kwargs = {}
    if proxy:
        req_kwargs["proxy"] = proxy

    try:
        async with session.get(
            test_url,
            headers=headers,
            timeout=aiohttp.ClientTimeout(total=timeout),
            allow_redirects=False,
            **req_kwargs,
        ) as resp:
            location = resp.headers.get("Location", "")
            if resp.status in (301, 302, 303, 307, 308) and _location_points_to_evil(location):
                return {
                    "url": url,
                    "test_url": test_url,
                    "param": param,
                    "payload": payload,
                    "status": resp.status,
                    "location": location,
                    "severity": "HIGH",
                }
    except Exception as exc:
        logging.debug(f"Open redirect test error {test_url}: {exc}")
    return None


async def check_open_redirect(
    urls,
    params=None,
    payloads=None,
    output_file=None,
    output_format="txt",
    proxy=None,
    timeout=10,
    random_ua=False,
    rate_limit=None,
    max_threads=20,
    fast=False,
):
    """Test *urls* for open redirect vulnerabilities.

    Parameters
    ----------
    urls : list[str]
        Target URLs to test.
    params : list[str] or None
        Parameter names to inject.  Defaults to :data:`REDIRECT_PARAMS`.
    payloads : list[str] or None
        Redirect payloads.  Defaults to :data:`REDIRECT_PAYLOADS`.
    output_file : str or None
        Path to write results.
    output_format : str
        ``'json'`` or ``'txt'``.
    fast : bool
        If True, use reduced parameter and payload sets, and only test the
        full parameter list on URLs that already have query parameters.

    Returns
    -------
    list[dict]
        Findings.
    """
    display_banner()

    if fast:
        default_params = REDIRECT_PARAMS_FAST
        default_payloads = REDIRECT_PAYLOADS_FAST
    else:
        default_params = REDIRECT_PARAMS
        default_payloads = REDIRECT_PAYLOADS

    test_params = params if params is not None else default_params
    test_payloads = payloads if payloads is not None else default_payloads

    print(
        f"{Fore.CYAN}[*] Testing {len(urls)} URL(s) for open redirects "
        f"({len(test_params)} params × {len(test_payloads)} payloads"
        f"{' [fast mode]' if fast else ''})...{Style.RESET_ALL}"
    )

    findings = []
    sem = asyncio.Semaphore(max_threads)

    async def handle(url, pbar):
        if stop_event.is_set():
            pbar.update(1)
            return
        # In fast mode (when params were not explicitly provided), use full param
        # list only for URLs that already have query parameters; use the fast
        # (reduced) list for URLs without query parameters.
        if fast and params is None:
            has_query = bool(urlparse(url).query)
            url_params = REDIRECT_PARAMS if has_query else REDIRECT_PARAMS_FAST
        else:
            url_params = test_params
        async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False)) as session:
            for param in url_params:
                for payload in test_payloads:
                    if stop_event.is_set():
                        pbar.update(1)
                        return
                    async with sem:
                        result = await _test_param(
                            session, url, param, payload, proxy, timeout, random_ua
                        )
                        if result:
                            findings.append(result)
                            tqdm.write(
                                f"{Fore.RED}[!] Open Redirect [{result['severity']}]: "
                                f"{result['url']} → param={param} payload={payload} "
                                f"Location={result['location']}{Style.RESET_ALL}"
                            )
                        if rate_limit:
                            await asyncio.sleep(1.0 / rate_limit)
        pbar.update(1)

    with tqdm(total=len(urls), desc="Open Redirect", ncols=80) as pbar:
        await asyncio.gather(*[handle(u, pbar) for u in urls])

    if not findings:
        print(f"{Fore.GREEN}[✔] No open redirect vulnerabilities detected.{Style.RESET_ALL}")

    if output_file and findings:
        with open(output_file, "w") as fh:
            if output_format == "json":
                json.dump(findings, fh, indent=2)
            else:
                for f in findings:
                    fh.write(
                        f"[{f['severity']}] {f['url']} | param={f['param']} "
                        f"payload={f['payload']} → {f['location']}\n"
                    )

    print(
        f"{Fore.CYAN}[✔] Open redirect scan complete — "
        f"{len(findings)} finding(s).{Style.RESET_ALL}"
    )
    return findings
