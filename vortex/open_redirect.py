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

from vortex.utils import stop_event, display_banner
from vortex.user_agents import USER_AGENTS

# Common redirect parameter names to test
REDIRECT_PARAMS = [
    "url", "redirect", "redirect_url", "next", "goto", "target",
    "dest", "destination", "rurl", "return", "returnUrl", "return_url",
    "continue", "out", "view", "redir", "callback", "link", "to",
    "forward", "location",
]

# Redirect test payloads
REDIRECT_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "/\\evil.com",
    "https:evil.com",
    "//evil.com/%2f..",
    "https://evil.com%23@target.com",
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

    Returns
    -------
    list[dict]
        Findings.
    """
    display_banner()
    test_params = params if params is not None else REDIRECT_PARAMS
    test_payloads = payloads if payloads is not None else REDIRECT_PAYLOADS

    print(
        f"{Fore.CYAN}[*] Testing {len(urls)} URL(s) for open redirects "
        f"({len(test_params)} params × {len(test_payloads)} payloads)...{Style.RESET_ALL}"
    )

    findings = []
    sem = asyncio.Semaphore(max_threads)
    connector = aiohttp.TCPConnector(ssl=False)

    async def handle(url):
        if stop_event.is_set():
            return
        async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False)) as session:
            for param in test_params:
                for payload in test_payloads:
                    if stop_event.is_set():
                        return
                    async with sem:
                        result = await _test_param(
                            session, url, param, payload, proxy, timeout, random_ua
                        )
                        if result:
                            findings.append(result)
                            print(
                                f"{Fore.RED}[!] Open Redirect [{result['severity']}]: "
                                f"{result['url']} → param={param} payload={payload} "
                                f"Location={result['location']}{Style.RESET_ALL}"
                            )
                        if rate_limit:
                            await asyncio.sleep(1.0 / rate_limit)

    async with aiohttp.ClientSession(connector=connector):
        await asyncio.gather(*[handle(u) for u in urls])

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
