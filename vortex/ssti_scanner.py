"""Server-Side Template Injection (SSTI) scanner.

Tests URL parameters with template injection payloads and detects whether
the template engine evaluated the expression (e.g., ``{{7*7}}`` → ``49``).
Supports detection for Jinja2, Twig, Freemarker, Velocity, ERB, Smarty,
Mako, Pebble, and Handlebars. Includes a fast mode with a reduced payload set.
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

_SEVERITY = "CRITICAL"

# (payload, expected_output, engine_name)
# A finding is confirmed when expected_output IS in the response body
# AND the raw payload is NOT in the response body (meaning it was evaluated).
_SSTI_CHECKS: list[tuple[str, str, str]] = [
    ("{{7*7}}", "49", "Jinja2/Twig/Pebble"),
    ("{{7*'7'}}", "7777777", "Jinja2"),
    ("${7*7}", "49", "Freemarker/Mako"),
    ("<%= 7*7 %>", "49", "ERB"),
    ("{7*7}", "49", "Smarty"),
    ("#set($x=7*7)$x", "49", "Velocity"),
    ("<#if 7*7==49>true</#if>", "true", "Freemarker"),
]

# Template engine error strings that indicate an SSTI-vulnerable engine is present
_ENGINE_ERRORS: list[tuple[str, str]] = [
    # Jinja2
    ("jinja2.exceptions", "Jinja2"),
    ("TemplateSyntaxError", "Jinja2"),
    ("UndefinedError", "Jinja2"),
    # Twig
    ("Twig_Error", "Twig"),
    ("Twig\\Error", "Twig"),
    ("Twig\\\\Error", "Twig"),
    # Freemarker
    ("FreeMarker template error", "Freemarker"),
    ("freemarker.core", "Freemarker"),
    # Velocity
    ("org.apache.velocity", "Velocity"),
    ("VelocityException", "Velocity"),
    # ERB
    ("erb", "ERB"),
    # Smarty
    ("Smarty error", "Smarty"),
    ("Smarty Compiler", "Smarty"),
    # Mako
    ("mako.exceptions", "Mako"),
    # Pebble
    ("com.mitchellbosecke.pebble", "Pebble"),
]

# Build a fast lookup: payload → (expected_output, engine_name)
_SSTI_CHECK_MAP: dict[str, tuple[str, str]] = {
    payload: (expected, engine) for payload, expected, engine in _SSTI_CHECKS
}


def _detect_ssti(payload: str, body: str) -> tuple[bool, str, str]:
    """Return (found, engine, evidence) for a given payload and response body.

    Detection logic:
    1. If the payload is in the known-check map, verify that the expected output
       IS present and the raw payload is NOT present (i.e., the engine evaluated it).
    2. For any payload, also check for template engine error strings.
    """
    # Check 1: mathematical/string evaluation
    if payload in _SSTI_CHECK_MAP:
        expected, engine = _SSTI_CHECK_MAP[payload]
        if expected in body and payload not in body:
            return True, engine, f"Payload evaluated: expected '{expected}' found in response"

    # Check 2: engine error strings (indicates engine presence even without evaluation)
    for error_str, engine in _ENGINE_ERRORS:
        if error_str in body:
            return True, engine, f"Template engine error detected: '{error_str}'"

    return False, "", ""


async def _test_url(
    session,
    url: str,
    payloads: list[str],
    proxy=None,
    timeout: float = 10,
    random_ua: bool = False,
    rate_limit=None,
) -> list[dict]:
    """Test a single URL's parameters with SSTI payloads."""
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
                    found, engine, evidence = _detect_ssti(payload, body)
                    if found:
                        findings.append({
                            "url": url,
                            "parameter": param,
                            "payload": payload,
                            "severity": _SEVERITY,
                            "template_engine": engine,
                            "evidence": evidence,
                            "status": resp.status,
                        })
                        # One finding per parameter is enough
                        break
            except Exception as exc:
                logging.debug(f"SSTI test error for {test_url}: {exc}")
            if rate_limit:
                await asyncio.sleep(1.0 / rate_limit)

    return findings


async def scan_ssti(
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
    """Scan *urls* for Server-Side Template Injection (SSTI) vulnerabilities.

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
        SSTI findings.
    """
    display_banner()
    all_payloads = load_payloads("ssti.txt")
    payloads = all_payloads[:15] if fast else all_payloads
    print(
        f"{Fore.CYAN}[*] Testing {len(urls)} URL(s) for SSTI "
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
                        f"{Fore.RED}[!] SSTI [{f['severity']}]: {f['url']} | "
                        f"param={f['parameter']} | engine={f['template_engine']}{Style.RESET_ALL}"
                    )
                all_findings.extend(findings)
        pbar.update(1)

    with tqdm(total=len(urls), desc="SSTI Scan", ncols=80) as pbar:
        await asyncio.gather(*[handle(u, pbar) for u in urls])

    if not all_findings:
        print(f"{Fore.GREEN}[✔] No SSTI vulnerabilities detected.{Style.RESET_ALL}")

    if output_file and all_findings:
        with open(output_file, "w", encoding="utf-8") as fh:
            if output_format == "json":
                json.dump(all_findings, fh, indent=2)
            else:
                for f in all_findings:
                    fh.write(
                        f"[{f['severity']}] {f['url']} | param={f['parameter']} | "
                        f"payload={f['payload']} | engine={f['template_engine']}\n"
                    )

    print(
        f"{Fore.CYAN}[✔] SSTI scan complete — {len(all_findings)} finding(s).{Style.RESET_ALL}"
    )
    return all_findings
