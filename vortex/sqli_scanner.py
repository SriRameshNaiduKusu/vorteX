"""SQL Injection scanner.

Tests URL parameters with SQLi payloads and detects:
- Error-based SQLi via DB error strings in responses
- Time-based blind SQLi via response delays (with ``--deep`` mode)

Supports MySQL, PostgreSQL, MSSQL, Oracle, and SQLite error detection.
"""

import asyncio
import json
import logging
import random
import time
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse

import aiohttp
from colorama import Fore, Style
from tqdm import tqdm

from vortex.payloads import load_payloads
from vortex.utils import stop_event, display_banner
from vortex.user_agents import USER_AGENTS

# DB error signatures for error-based detection
_ERROR_PATTERNS: list[tuple[str, str]] = [
    # MySQL
    ("you have an error in your sql syntax", "MySQL"),
    ("warning: mysql_", "MySQL"),
    ("unclosed quotation mark after the character string", "MySQL"),
    ("mysql_fetch_array()", "MySQL"),
    ("mysql_num_rows()", "MySQL"),
    ("supplied argument is not a valid mysql", "MySQL"),
    # PostgreSQL
    ("pg_query()", "PostgreSQL"),
    ("pg_exec()", "PostgreSQL"),
    ("postgresql query failed", "PostgreSQL"),
    ("error: parser: parse error", "PostgreSQL"),
    ("unterminated quoted string", "PostgreSQL"),
    ("syntax error at or near", "PostgreSQL"),
    # MSSQL
    ("microsoft ole db provider for odbc drivers", "MSSQL"),
    ("microsoft ole db provider for sql server", "MSSQL"),
    ("unclosed quotation mark after the character string", "MSSQL"),
    ("[microsoft][odbc sql server driver]", "MSSQL"),
    ("odbc sql server driver", "MSSQL"),
    ("mssql_query()", "MSSQL"),
    # Oracle
    ("ora-00933", "Oracle"),
    ("ora-01756", "Oracle"),
    ("ora-00907", "Oracle"),
    ("ora-00942", "Oracle"),
    ("oracle error", "Oracle"),
    ("oracle driver", "Oracle"),
    # SQLite
    ("sqlite_array()", "SQLite"),
    ("sqlite error", "SQLite"),
    ("warning: sqlite_query()", "SQLite"),
    ("near \"syntax error\"", "SQLite"),
    # Generic
    ("sql syntax", "Generic SQL"),
    ("sql error", "Generic SQL"),
    ("syntax error", "Generic SQL"),
    ("database error", "Generic SQL"),
    ("db error", "Generic SQL"),
    ("invalid query", "Generic SQL"),
    ("division by zero", "Generic SQL"),
]

# Time-based payloads for deep mode
_TIME_PAYLOADS = [
    "' AND SLEEP(5)--",
    "\" AND SLEEP(5)--",
    "'; SELECT SLEEP(5)--",
    "1; WAITFOR DELAY '0:0:5'--",
    "' OR SLEEP(5)--",
    "1 AND SLEEP(5)",
    "'; SELECT pg_sleep(5)--",
]
_TIME_THRESHOLD = 4.5  # seconds


def _detect_sqli_error(body: str) -> tuple[bool, str]:
    """Return (found, db_type) if a SQL error pattern is detected in body."""
    body_lower = body.lower()
    for pattern, db_type in _ERROR_PATTERNS:
        if pattern in body_lower:
            return True, db_type
    return False, ""


async def _test_url_error(
    session,
    url: str,
    payloads: list[str],
    proxy=None,
    timeout: float = 10,
    random_ua: bool = False,
    rate_limit=None,
) -> list[dict]:
    """Test a single URL for error-based SQLi."""
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
                    found, db_type = _detect_sqli_error(body)
                    if found:
                        findings.append({
                            "url": url,
                            "parameter": param,
                            "payload": payload,
                            "type": "error-based",
                            "db_type": db_type,
                            "severity": "HIGH",
                            "status": resp.status,
                        })
                        break
            except Exception as exc:
                logging.debug(f"SQLi error-based test error for {test_url}: {exc}")
            if rate_limit:
                await asyncio.sleep(1.0 / rate_limit)

    return findings


async def _test_url_time(
    session,
    url: str,
    proxy=None,
    timeout: float = 15,
    random_ua: bool = False,
    rate_limit=None,
) -> list[dict]:
    """Test a single URL for time-based blind SQLi."""
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
        for payload in _TIME_PAYLOADS:
            if stop_event.is_set():
                return findings
            test_params = {k: v[0] for k, v in params.items()}
            test_params[param] = payload
            new_query = urlencode(test_params)
            test_url = urlunparse(parsed._replace(query=new_query))
            t0 = time.monotonic()
            try:
                async with session.get(
                    test_url,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=timeout),
                    allow_redirects=True,
                    **req_kwargs,
                ) as resp:
                    await resp.read()
                    elapsed = time.monotonic() - t0
                    if elapsed >= _TIME_THRESHOLD:
                        findings.append({
                            "url": url,
                            "parameter": param,
                            "payload": payload,
                            "type": "time-based blind",
                            "db_type": "Unknown",
                            "severity": "HIGH",
                            "elapsed": round(elapsed, 2),
                        })
                        break
            except asyncio.TimeoutError:
                elapsed = time.monotonic() - t0
                if elapsed >= _TIME_THRESHOLD:
                    findings.append({
                        "url": url,
                        "parameter": param,
                        "payload": payload,
                        "type": "time-based blind",
                        "db_type": "Unknown",
                        "severity": "HIGH",
                        "elapsed": round(elapsed, 2),
                    })
                    break
            except Exception as exc:
                logging.debug(f"SQLi time-based test error for {test_url}: {exc}")
            if rate_limit:
                await asyncio.sleep(1.0 / rate_limit)

    return findings


async def scan_sqli(
    urls,
    output_file=None,
    output_format="txt",
    proxy=None,
    timeout: float = 10,
    random_ua: bool = False,
    rate_limit=None,
    max_threads: int = 20,
    fast: bool = False,
    deep: bool = False,
):
    """Scan *urls* for SQL injection vulnerabilities.

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
    deep : bool
        If True, also run time-based blind SQLi detection.

    Returns
    -------
    list[dict]
        SQLi findings.
    """
    display_banner()
    all_payloads = load_payloads("sqli.txt")
    payloads = all_payloads[:20] if fast else all_payloads
    modes = ["error-based"] + (["time-based blind"] if deep else [])
    print(
        f"{Fore.CYAN}[*] Testing {len(urls)} URL(s) for SQL injection "
        f"({len(payloads)} payloads, modes: {', '.join(modes)})"
        f"{' [fast mode]' if fast else ''}...{Style.RESET_ALL}"
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
                findings = await _test_url_error(
                    session, url, payloads, proxy, timeout, random_ua, rate_limit
                )
                if deep and not findings:
                    time_findings = await _test_url_time(
                        session, url, proxy, timeout + 10, random_ua, rate_limit
                    )
                    findings.extend(time_findings)
                for f in findings:
                    tqdm.write(
                        f"{Fore.RED}[!] SQLi [{f['severity']}]: {f['url']} | "
                        f"param={f['parameter']} | type={f['type']} | db={f['db_type']}{Style.RESET_ALL}"
                    )
                all_findings.extend(findings)
        pbar.update(1)

    with tqdm(total=len(urls), desc="SQLi Scan", ncols=80) as pbar:
        await asyncio.gather(*[handle(u, pbar) for u in urls])

    if not all_findings:
        print(f"{Fore.GREEN}[✔] No SQL injection vulnerabilities detected.{Style.RESET_ALL}")

    if output_file and all_findings:
        with open(output_file, "w", encoding="utf-8") as fh:
            if output_format == "json":
                json.dump(all_findings, fh, indent=2)
            else:
                for f in all_findings:
                    fh.write(
                        f"[{f['severity']}] {f['url']} | param={f['parameter']} | "
                        f"type={f['type']} | db={f['db_type']}\n"
                    )

    print(
        f"{Fore.CYAN}[✔] SQLi scan complete — {len(all_findings)} finding(s).{Style.RESET_ALL}"
    )
    return all_findings
