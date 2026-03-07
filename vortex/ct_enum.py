"""Certificate Transparency log mining via crt.sh.

Passively discovers subdomains by querying the crt.sh public CT log API.
"""

import asyncio
import json
import logging

import aiohttp
from colorama import Fore, Style

from vortex.utils import display_banner


def _extract_names(name_value):
    """Yield clean hostnames from a crt.sh ``name_value`` field."""
    for name in name_value.splitlines():
        name = name.strip().lstrip("*.")
        if name:
            yield name


async def ct_search(
    domain,
    output_file=None,
    output_format="txt",
    proxy=None,
    timeout=15,
    random_ua=False,
    rate_limit=None,
    resolve=False,
):
    """Query crt.sh for subdomains of *domain*.

    Parameters
    ----------
    domain : str
        The apex domain to search (e.g. ``'example.com'``).
    output_file : str or None
        Path to write results.
    output_format : str
        ``'json'`` or ``'txt'``.
    resolve : bool
        When True, attempt to resolve each discovered subdomain.

    Returns
    -------
    list[str]
        Unique subdomain names discovered.
    """
    display_banner()
    print(f"{Fore.CYAN}[*] Querying Certificate Transparency logs for: {domain}{Style.RESET_ALL}")

    url = f"https://crt.sh/?q=%.{domain}&output=json"
    req_kwargs = {}
    if proxy:
        req_kwargs["proxy"] = proxy

    found = set()

    connector = aiohttp.TCPConnector(ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        try:
            async with session.get(
                url, timeout=aiohttp.ClientTimeout(total=timeout), **req_kwargs
            ) as resp:
                if resp.status != 200:
                    print(
                        f"{Fore.YELLOW}[⚠] crt.sh returned HTTP {resp.status}. "
                        f"Skipping.{Style.RESET_ALL}"
                    )
                    return []
                data = await resp.json(content_type=None)
        except asyncio.TimeoutError:
            print(f"{Fore.YELLOW}[⚠] crt.sh query timed out.{Style.RESET_ALL}")
            return []
        except Exception as exc:
            logging.warning(f"CT log query failed: {exc}")
            print(f"{Fore.YELLOW}[⚠] CT log query error: {exc}{Style.RESET_ALL}")
            return []

    for entry in data:
        name_value = entry.get("name_value", "")
        for name in _extract_names(name_value):
            if domain in name:
                found.add(name)

    subdomains = sorted(found)
    print(
        f"{Fore.GREEN}[✔] CT logs: {len(subdomains)} unique subdomain(s) "
        f"discovered for {domain}{Style.RESET_ALL}"
    )
    for sub in subdomains:
        print(f"  {Fore.GREEN}→ {sub}{Style.RESET_ALL}")

    if output_file:
        with open(output_file, "w") as fh:
            if output_format == "json":
                json.dump(subdomains, fh, indent=2)
            else:
                fh.write("\n".join(subdomains) + "\n")

    return subdomains
