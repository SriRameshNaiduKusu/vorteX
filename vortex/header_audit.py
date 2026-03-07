"""Security header audit module.

Checks URLs for the presence of recommended HTTP security headers and
provides a letter grade (A–F).
"""

import asyncio
import json
import logging
import random

import aiohttp
from colorama import Fore, Style

from vortex.utils import stop_event, display_banner
from vortex.user_agents import USER_AGENTS

# Expected security headers and their descriptions
SECURITY_HEADERS = {
    "Content-Security-Policy":           "Prevents XSS and data injection attacks",
    "Strict-Transport-Security":         "Enforces HTTPS connections",
    "X-Content-Type-Options":            "Prevents MIME-sniffing",
    "X-Frame-Options":                   "Prevents clickjacking",
    "X-XSS-Protection":                  "Browser XSS filter (legacy)",
    "Referrer-Policy":                   "Controls referrer information",
    "Permissions-Policy":                "Controls browser feature access",
    "Cross-Origin-Opener-Policy":        "Isolates browsing context",
    "Cross-Origin-Resource-Policy":      "Controls cross-origin resource access",
    "Cross-Origin-Embedder-Policy":      "Enables cross-origin isolation",
}

_TOTAL_HEADERS = len(SECURITY_HEADERS)


def _grade(present_count):
    """Return a letter grade based on how many headers are present."""
    ratio = present_count / _TOTAL_HEADERS
    if ratio >= 0.9:
        return "A"
    if ratio >= 0.7:
        return "B"
    if ratio >= 0.5:
        return "C"
    if ratio >= 0.3:
        return "D"
    return "F"


async def _audit_url(session, url, proxy=None, timeout=10, random_ua=False):
    """Return the audit result for a single *url*."""
    headers = {}
    if random_ua:
        headers["User-Agent"] = random.choice(USER_AGENTS)
    req_kwargs = {}
    if proxy:
        req_kwargs["proxy"] = proxy
    try:
        async with session.get(
            url,
            headers=headers,
            timeout=aiohttp.ClientTimeout(total=timeout),
            allow_redirects=True,
            **req_kwargs,
        ) as resp:
            resp_headers = {k.lower(): v for k, v in resp.headers.items()}
            present = {}
            missing = {}
            for header, desc in SECURITY_HEADERS.items():
                val = resp_headers.get(header.lower())
                if val:
                    present[header] = val
                else:
                    missing[header] = desc
            grade = _grade(len(present))
            return {
                "url": url,
                "grade": grade,
                "present": present,
                "missing": missing,
                "score": f"{len(present)}/{_TOTAL_HEADERS}",
            }
    except Exception as exc:
        logging.debug(f"Header audit error for {url}: {exc}")
        return {"url": url, "grade": "F", "present": {}, "missing": dict(SECURITY_HEADERS), "score": f"0/{_TOTAL_HEADERS}", "error": str(exc)}


def _print_result(result):
    """Pretty-print a single URL audit result."""
    grade = result["grade"]
    grade_color = (
        Fore.GREEN if grade in ("A", "B")
        else Fore.YELLOW if grade == "C"
        else Fore.RED
    )
    print(
        f"\n{Fore.CYAN}[*] {result['url']} — "
        f"Grade: {grade_color}{grade}{Style.RESET_ALL} "
        f"({result['score']}){Style.RESET_ALL}"
    )
    for header in result["present"]:
        print(f"  {Fore.GREEN}✅ {header}{Style.RESET_ALL}")
    for header in result["missing"]:
        print(f"  {Fore.RED}❌ {header}{Style.RESET_ALL}")


async def audit_headers(
    urls,
    output_file=None,
    output_format="txt",
    proxy=None,
    timeout=10,
    random_ua=False,
    rate_limit=None,
    max_threads=20,
):
    """Audit HTTP security headers for each URL in *urls*.

    Parameters
    ----------
    urls : list[str]
        Target URLs to audit.
    output_file : str or None
        Path to write results.
    output_format : str
        ``'json'`` or ``'txt'``.

    Returns
    -------
    list[dict]
        Audit results per URL.
    """
    display_banner()
    print(
        f"{Fore.CYAN}[*] Auditing security headers on "
        f"{len(urls)} URL(s)...{Style.RESET_ALL}"
    )

    results = []
    sem = asyncio.Semaphore(max_threads)

    async def handle(url):
        if stop_event.is_set():
            return
        async with sem:
            async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False)) as session:
                result = await _audit_url(session, url, proxy, timeout, random_ua)
                results.append(result)
                _print_result(result)
            if rate_limit:
                await asyncio.sleep(1.0 / rate_limit)

    await asyncio.gather(*[handle(u) for u in urls])

    if output_file and results:
        with open(output_file, "w") as fh:
            if output_format == "json":
                json.dump(results, fh, indent=2)
            else:
                for r in results:
                    fh.write(
                        f"[{r['grade']}] {r['url']} ({r['score']})\n"
                        f"  Present : {', '.join(r['present'].keys()) or 'none'}\n"
                        f"  Missing : {', '.join(r['missing'].keys()) or 'none'}\n\n"
                    )

    print(
        f"{Fore.CYAN}[✔] Header audit complete — "
        f"{len(results)} URL(s) analysed.{Style.RESET_ALL}"
    )
    return results
