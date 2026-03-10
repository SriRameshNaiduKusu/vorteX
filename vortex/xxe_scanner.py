"""XXE (XML External Entity) Injection scanner.

Sends XML payloads as POST request bodies (with application/xml and text/xml
content types) and checks responses for file disclosure indicators or XML
parser error messages. Also tests XML payloads injected into URL query
parameters for endpoints that parse XML from params.
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

# File content signatures that confirm a successful XXE (file disclosure)
_XXE_FILE_INDICATORS: list[tuple[str, str]] = [
    ("root:x:0:0", "/etc/passwd"),
    ("root:!:", "/etc/shadow"),
    ("127.0.0.1", "/etc/hosts"),
    ("nameserver ", "/etc/resolv.conf"),
    ("[fonts]", "Windows win.ini"),
    ("[extensions]", "Windows win.ini"),
    ("[boot loader]", "Windows boot.ini"),
    ("for 16-bit app support", "Windows win.ini"),
    ("PATH=", "/proc/self/environ"),
    ("HOSTNAME=", "/proc/self/environ"),
    ("ami-id", "AWS metadata"),
    ("instance-id", "Cloud metadata"),
    ("security-credentials", "AWS IAM credentials"),
    ("project-id", "GCP metadata"),
]

# XML parser error strings — server processes XML (likely exploitable)
_XML_ERROR_PATTERNS: list[str] = [
    "XML parsing error",
    "XML parse error",
    "DOCTYPE not allowed",
    "DOCTYPE declaration not allowed",
    "ENTITY not allowed",
    "parser error",
    "SAXParseException",
    "XMLSyntaxError",
    "libxml",
    "lxml",
    "simplexml",
    "DOMDocument",
    "not well-formed",
    "invalid XML",
]


def _check_xxe_response(body: str) -> tuple[str, str]:
    """Return (severity, evidence) if XXE indicators are found in the response body.

    Returns (\"CRITICAL\", evidence) when file content is present, or
    (\"HIGH\", evidence) when XML parser errors are detected.
    Returns (\"\", \"\") when no indicators are found.
    """
    for pattern, file_name in _XXE_FILE_INDICATORS:
        if pattern in body:
            return "CRITICAL", f"File disclosed: {file_name}"
    for pattern in _XML_ERROR_PATTERNS:
        if pattern in body:
            return "HIGH", f"XML parser error detected: '{pattern}'"
    return "", ""


async def _test_url(
    session,
    url: str,
    payloads: list[str],
    proxy=None,
    timeout: float = 10,
    random_ua: bool = False,
    rate_limit=None,
) -> list[dict]:
    """Test a single URL for XXE vulnerabilities.

    Sends each payload:
    1. As the POST body with Content-Type: application/xml.
    2. As the POST body with Content-Type: text/xml.
    3. As the value of each query parameter (GET, for apps that parse XML params).
    """
    req_kwargs: dict = {}
    if proxy:
        req_kwargs["proxy"] = proxy

    headers: dict = {}
    if random_ua:
        headers["User-Agent"] = random.choice(USER_AGENTS)

    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    findings: list[dict] = []

    for payload in payloads:
        if stop_event.is_set():
            return findings

        # 1 & 2: POST body with XML content types
        for content_type in ("application/xml", "text/xml"):
            if stop_event.is_set():
                return findings
            post_headers = {**headers, "Content-Type": content_type}
            try:
                async with session.post(
                    url,
                    data=payload.encode("utf-8"),
                    headers=post_headers,
                    timeout=aiohttp.ClientTimeout(total=timeout),
                    allow_redirects=True,
                    **req_kwargs,
                ) as resp:
                    try:
                        body = await resp.text(errors="replace")
                    except Exception:
                        body = ""
                    severity, evidence = _check_xxe_response(body)
                    if severity:
                        findings.append({
                            "url": url,
                            "payload": payload,
                            "severity": severity,
                            "evidence": evidence,
                            "method": "POST",
                            "content_type": content_type,
                            "status": resp.status,
                        })
                        # One finding per URL is sufficient
                        return findings
            except Exception as exc:
                logging.debug(f"XXE POST test error for {url}: {exc}")
            if rate_limit:
                await asyncio.sleep(1.0 / rate_limit)

        # 3: GET with payload injected into each query parameter
        if params:
            for param in params:
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
                        severity, evidence = _check_xxe_response(body)
                        if severity:
                            findings.append({
                                "url": url,
                                "payload": payload,
                                "severity": severity,
                                "evidence": evidence,
                                "method": "GET",
                                "content_type": "N/A",
                                "status": resp.status,
                            })
                            return findings
                except Exception as exc:
                    logging.debug(f"XXE GET param test error for {test_url}: {exc}")
                if rate_limit:
                    await asyncio.sleep(1.0 / rate_limit)

    return findings


async def scan_xxe(
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
    """Scan *urls* for XXE (XML External Entity) injection vulnerabilities.

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
        XXE findings.
    """
    display_banner()
    all_payloads = load_payloads("xxe.txt")
    payloads = all_payloads[:10] if fast else all_payloads
    print(
        f"{Fore.CYAN}[*] Testing {len(urls)} URL(s) for XXE injection "
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
                        f"{Fore.RED}[!] XXE [{f['severity']}]: {f['url']} | "
                        f"evidence={f['evidence']} | method={f['method']}{Style.RESET_ALL}"
                    )
                all_findings.extend(findings)
        pbar.update(1)

    with tqdm(total=len(urls), desc="XXE Scan", ncols=80) as pbar:
        await asyncio.gather(*[handle(u, pbar) for u in urls])

    if not all_findings:
        print(f"{Fore.GREEN}[✔] No XXE vulnerabilities detected.{Style.RESET_ALL}")

    if output_file and all_findings:
        with open(output_file, "w", encoding="utf-8") as fh:
            if output_format == "json":
                json.dump(all_findings, fh, indent=2)
            else:
                for f in all_findings:
                    fh.write(
                        f"[{f['severity']}] {f['url']} | "
                        f"method={f['method']} | payload={f['payload']} | "
                        f"evidence={f['evidence']}\n"
                    )

    print(
        f"{Fore.CYAN}[✔] XXE scan complete — {len(all_findings)} finding(s).{Style.RESET_ALL}"
    )
    return all_findings
