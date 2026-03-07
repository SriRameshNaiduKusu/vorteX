"""Sensitive file and path detection module.

Checks target base URLs for commonly exposed sensitive files and endpoints.
"""

import asyncio
import json
import logging
import random

import aiohttp
from colorama import Fore, Style

from vortex.utils import stop_event, display_banner
from vortex.user_agents import USER_AGENTS

# Built-in list of sensitive paths
SENSITIVE_PATHS = [
    "/.env",
    "/.git/config",
    "/.git/HEAD",
    "/.gitignore",
    "/.htaccess",
    "/.htpasswd",
    "/wp-config.php.bak",
    "/web.config",
    "/config.php.bak",
    "/server-status",
    "/server-info",
    "/phpinfo.php",
    "/info.php",
    "/.DS_Store",
    "/Thumbs.db",
    "/robots.txt",
    "/sitemap.xml",
    "/crossdomain.xml",
    "/clientaccesspolicy.xml",
    "/swagger.json",
    "/swagger-ui.html",
    "/openapi.json",
    "/openapi.yaml",
    "/api-docs",
    "/graphql",
    "/graphiql",
    "/.well-known/security.txt",
    "/backup.zip",
    "/backup.tar.gz",
    "/database.sql",
    "/debug",
    "/trace",
    "/elmah.axd",
    "/actuator",
    "/actuator/health",
    "/actuator/env",
    "/.aws/credentials",
    "/config.json",
    "/config.yaml",
    "/config.yml",
    "/settings.py",
    "/local_settings.py",
    "/.npmrc",
    "/.bash_history",
    "/id_rsa",
    "/id_dsa",
]

# Minimum content-length to consider a 200 response "real" (not a soft 404)
_MIN_CONTENT_LENGTH = 10


async def _check_path(session, base_url, path, proxy=None, timeout=10, random_ua=False):
    """Return a finding dict if *base_url + path* returns a meaningful response."""
    url = base_url.rstrip("/") + path
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
            allow_redirects=False,
            **req_kwargs,
        ) as resp:
            status = resp.status
            content_type = resp.headers.get("Content-Type", "")
            body = await resp.read()
            actual_length = len(body)

            # Report 200 responses with non-trivial content
            if status == 200 and actual_length >= _MIN_CONTENT_LENGTH:
                return {
                    "url": url,
                    "status": status,
                    "content_length": actual_length,
                    "content_type": content_type,
                }
    except Exception as exc:
        logging.debug(f"Sensitive file check error {url}: {exc}")
    return None


async def scan_sensitive_files(
    urls,
    paths=None,
    output_file=None,
    output_format="txt",
    proxy=None,
    timeout=10,
    random_ua=False,
    rate_limit=None,
    max_threads=20,
):
    """Check each base URL for sensitive files.

    Parameters
    ----------
    urls : list[str]
        Base URLs to check (e.g. ``['https://example.com']``).
    paths : list[str] or None
        Paths to probe.  Defaults to :data:`SENSITIVE_PATHS`.
    output_file : str or None
        Path to write results.
    output_format : str
        ``'json'`` or ``'txt'``.

    Returns
    -------
    list[dict]
        Findings with ``url``, ``status``, ``content_length``, and
        ``content_type``.
    """
    display_banner()
    probe_paths = paths if paths is not None else SENSITIVE_PATHS
    print(
        f"{Fore.CYAN}[*] Scanning {len(urls)} target(s) for sensitive files "
        f"({len(probe_paths)} paths each)...{Style.RESET_ALL}"
    )

    findings = []
    sem = asyncio.Semaphore(max_threads)

    async def check_base(base_url):
        async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False)) as session:
            for path in probe_paths:
                if stop_event.is_set():
                    return
                async with sem:
                    result = await _check_path(session, base_url, path, proxy, timeout, random_ua)
                    if result:
                        findings.append(result)
                        print(
                            f"{Fore.RED}[!] Sensitive file found: "
                            f"{result['url']} "
                            f"(HTTP {result['status']}, "
                            f"{result['content_length']} bytes, "
                            f"{result['content_type']}){Style.RESET_ALL}"
                        )
                    if rate_limit:
                        await asyncio.sleep(1.0 / rate_limit)

    await asyncio.gather(*[check_base(u) for u in urls])

    if not findings:
        print(f"{Fore.GREEN}[✔] No sensitive files found.{Style.RESET_ALL}")

    if output_file and findings:
        with open(output_file, "w") as fh:
            if output_format == "json":
                json.dump(findings, fh, indent=2)
            else:
                for f in findings:
                    fh.write(
                        f"[{f['status']}] {f['url']} "
                        f"({f['content_length']} bytes)\n"
                    )

    print(
        f"{Fore.CYAN}[✔] Sensitive file scan complete — "
        f"{len(findings)} finding(s).{Style.RESET_ALL}"
    )
    return findings
