"""Wayback Machine URL mining via the CDX API.

Discovers historical URLs for a domain using the Internet Archive's CDX API.
"""

import asyncio
import json
import logging

import aiohttp
from colorama import Fore, Style

from vortex.utils import stop_event, display_banner

# File extensions considered interesting for bug bounty recon
INTERESTING_EXTENSIONS = {
    ".js", ".php", ".asp", ".aspx", ".json", ".xml", ".env",
    ".bak", ".config", ".conf", ".yaml", ".yml", ".log", ".sql",
    ".zip", ".tar", ".gz", ".txt", ".csv",
}


async def wayback_enum(
    domain,
    output_file=None,
    output_format="txt",
    proxy=None,
    timeout=30,
    random_ua=False,
    rate_limit=None,
    filter_extensions=None,
):
    """Discover historical URLs from the Wayback Machine CDX API.

    Parameters
    ----------
    domain : str
        The apex domain (e.g. ``'example.com'``).
    output_file : str or None
        Path to write results.
    output_format : str
        ``'json'`` or ``'txt'``.
    filter_extensions : set or None
        If provided, only return URLs whose path ends with one of these
        extensions.  Defaults to :data:`INTERESTING_EXTENSIONS`.

    Returns
    -------
    list[str]
        Unique historical URLs.
    """
    display_banner()
    print(
        f"{Fore.CYAN}[*] Mining Wayback Machine for historical URLs: "
        f"{domain}{Style.RESET_ALL}"
    )

    cdx_url = (
        f"https://web.archive.org/cdx/search/cdx"
        f"?url=*.{domain}/*&output=json&fl=original&collapse=urlkey&limit=5000"
    )
    req_kwargs = {}
    if proxy:
        req_kwargs["proxy"] = proxy

    urls = []
    connector = aiohttp.TCPConnector(ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        try:
            async with session.get(
                cdx_url, timeout=aiohttp.ClientTimeout(total=timeout), **req_kwargs
            ) as resp:
                if resp.status != 200:
                    print(
                        f"{Fore.YELLOW}[⚠] Wayback CDX returned HTTP {resp.status}. "
                        f"Skipping.{Style.RESET_ALL}"
                    )
                    return []
                data = await resp.json(content_type=None)
        except asyncio.TimeoutError:
            print(f"{Fore.YELLOW}[⚠] Wayback Machine query timed out.{Style.RESET_ALL}")
            return []
        except Exception as exc:
            logging.warning(f"Wayback query failed: {exc}")
            print(f"{Fore.YELLOW}[⚠] Wayback query error: {exc}{Style.RESET_ALL}")
            return []

    # The first row is a header row ["original"]
    seen = set()
    extensions = filter_extensions if filter_extensions is not None else INTERESTING_EXTENSIONS
    for row in data[1:]:  # skip header
        if stop_event.is_set():
            break
        if not row:
            continue
        url = row[0]
        if url in seen:
            continue
        seen.add(url)
        if extensions:
            # Check if URL path ends with one of the interesting extensions
            path = url.split("?")[0]
            if not any(path.lower().endswith(ext) for ext in extensions):
                continue
        urls.append(url)

    print(
        f"{Fore.GREEN}[✔] Wayback Machine: {len(urls)} URL(s) discovered "
        f"for {domain}{Style.RESET_ALL}"
    )
    for u in urls[:20]:  # preview first 20
        print(f"  {Fore.GREEN}→ {u}{Style.RESET_ALL}")
    if len(urls) > 20:
        print(f"  {Fore.CYAN}  ... and {len(urls) - 20} more{Style.RESET_ALL}")

    if output_file:
        with open(output_file, "w") as fh:
            if output_format == "json":
                json.dump(urls, fh, indent=2)
            else:
                fh.write("\n".join(urls) + "\n")

    return urls
