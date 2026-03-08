"""Local File Inclusion (LFI) / Path Traversal scanner.

Tests URL parameters with path traversal payloads and detects common file
content signatures in the HTTP response (e.g., ``/etc/passwd``, ``win.ini``).
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

# File content signatures that indicate a successful LFI
_LFI_INDICATORS = [
    # Linux /etc/passwd
    ("root:x:0:0:", "Linux /etc/passwd"),
    ("root:!:0:0:", "Linux /etc/shadow"),
    ("daemon:x:", "Linux /etc/passwd"),
    ("nobody:x:", "Linux /etc/passwd"),
    # Linux /etc/hosts / resolv.conf
    ("127.0.0.1 localhost", "/etc/hosts"),
    ("nameserver ", "/etc/resolv.conf"),
    # /proc
    ("/bin/bash", "/proc/self/environ or /etc/passwd"),
    ("HOSTNAME=", "/proc/self/environ"),
    ("PATH=/usr", "/proc/self/environ"),
    # Windows files
    ("[boot loader]", "Windows boot.ini"),
    ("[operating systems]", "Windows boot.ini"),
    ("[extensions]", "Windows win.ini"),
    ("[fonts]", "Windows win.ini"),
    ("[mci extensions]", "Windows win.ini"),
    ("[files]", "Windows system.ini"),
    ("<configuration>", "Windows web.config"),
    # Generic indicators
    ("for 16-bit app support", "Windows win.ini"),
    ("MSDOS.SYS", "Windows system files"),
]


def _detect_lfi(body: str) -> tuple[bool, str]:
    """Return (found, file_type) if an LFI indicator is present in body."""
    for pattern, file_type in _LFI_INDICATORS:
        if pattern in body:
            return True, file_type
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
    """Test a single URL's parameters with LFI payloads."""
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
                    found, file_type = _detect_lfi(body)
                    if found:
                        findings.append({
                            "url": url,
                            "parameter": param,
                            "payload": payload,
                            "file_type": file_type,
                            "severity": "HIGH",
                            "status": resp.status,
                        })
                        break
            except Exception as exc:
                logging.debug(f"LFI test error for {test_url}: {exc}")
            if rate_limit:
                await asyncio.sleep(1.0 / rate_limit)

    return findings


async def scan_lfi(
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
    """Scan *urls* for Local File Inclusion / path traversal vulnerabilities.

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
        LFI findings.
    """
    display_banner()
    all_payloads = load_payloads("lfi.txt")
    payloads = all_payloads[:20] if fast else all_payloads
    print(
        f"{Fore.CYAN}[*] Testing {len(urls)} URL(s) for LFI/path traversal "
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
                        f"{Fore.RED}[!] LFI [{f['severity']}]: {f['url']} | "
                        f"param={f['parameter']} | file={f['file_type']}{Style.RESET_ALL}"
                    )
                all_findings.extend(findings)
        pbar.update(1)

    with tqdm(total=len(urls), desc="LFI Scan", ncols=80) as pbar:
        await asyncio.gather(*[handle(u, pbar) for u in urls])

    if not all_findings:
        print(f"{Fore.GREEN}[✔] No LFI vulnerabilities detected.{Style.RESET_ALL}")

    if output_file and all_findings:
        with open(output_file, "w", encoding="utf-8") as fh:
            if output_format == "json":
                json.dump(all_findings, fh, indent=2)
            else:
                for f in all_findings:
                    fh.write(
                        f"[{f['severity']}] {f['url']} | param={f['parameter']} | "
                        f"payload={f['payload']} | file={f['file_type']}\n"
                    )

    print(
        f"{Fore.CYAN}[✔] LFI scan complete — {len(all_findings)} finding(s).{Style.RESET_ALL}"
    )
    return all_findings
