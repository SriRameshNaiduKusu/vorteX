"""HTTP liveness probing module.

Makes async HEAD (falling back to GET) requests to a list of targets and
returns only the hosts that are actively serving HTTP(S).  Also detects
wildcard DNS responses and deduplicates them so that downstream phases are
not flooded with thousands of identical entries.
"""

from __future__ import annotations

import asyncio
import logging
import random
from collections import Counter
from urllib.parse import urlparse

import aiohttp
from colorama import Fore, Style

from vortex.user_agents import USER_AGENTS

# Fraction of alive hosts that must share the same (status, content-length)
# signature before the group is considered a wildcard response.
_WILDCARD_THRESHOLD = 0.75


def _normalise_target(target: str) -> str:
    """Return a bare hostname/IP (no scheme, no path) from *target*.

    Handles both raw hostnames (``sub.example.com``) and full URLs
    (``https://sub.example.com/path``).
    """
    if "://" in target:
        parsed = urlparse(target)
        host = parsed.netloc or target
    else:
        host = target

    # Strip port if present (handles IPv6 addresses too)
    if host.startswith("["):
        bracket_end = host.find("]")
        if bracket_end != -1:
            host = host[1:bracket_end]
    elif ":" in host:
        host = host.rsplit(":", 1)[0]

    return host


async def _probe_one(
    session: aiohttp.ClientSession,
    target: str,
    sem: asyncio.Semaphore,
    timeout: float,
    proxy: str | None,
    random_ua: bool,
) -> tuple[str, int | None, int | None] | None:
    """Probe a single target.

    Tries ``https://`` first, then ``http://`` on failure.

    Returns ``(url, status_code, content_length)`` on success or ``None``
    when both schemes are unreachable.
    """
    host = _normalise_target(target)
    req_kwargs: dict = {}
    if proxy:
        req_kwargs["proxy"] = proxy

    headers: dict[str, str] = {}
    if random_ua:
        headers["User-Agent"] = random.choice(USER_AGENTS)

    client_timeout = aiohttp.ClientTimeout(total=timeout)

    for scheme in ("https", "http"):
        url = f"{scheme}://{host}"
        async with sem:
            for method in ("HEAD", "GET"):
                try:
                    async with session.request(
                        method,
                        url,
                        headers=headers,
                        timeout=client_timeout,
                        allow_redirects=True,
                        ssl=False,
                        **req_kwargs,
                    ) as resp:
                        content_length: int | None = None
                        cl_header = resp.headers.get("Content-Length")
                        if cl_header is not None:
                            try:
                                content_length = int(cl_header)
                            except ValueError:
                                pass
                        return url, resp.status, content_length
                except (aiohttp.ClientError, asyncio.TimeoutError, OSError):
                    # HEAD not supported → try GET; scheme unreachable → next scheme
                    continue
    return None


async def probe_alive(
    targets: list[str],
    max_threads: int = 50,
    timeout: float = 5.0,
    proxy: str | None = None,
    random_ua: bool = False,
    max_targets: int = 5000,
) -> list[str]:
    """Probe *targets* with HTTP HEAD/GET and return only live hosts.

    Args:
        targets:     List of subdomains or full URLs to probe.
        max_threads: Maximum concurrent HTTP connections.
        timeout:     Per-request timeout in seconds.
        proxy:       Optional HTTP/SOCKS proxy URL.
        random_ua:   Rotate User-Agent strings when ``True``.
        max_targets: Safety cap on the number of live targets returned.
                     If more hosts respond than this value a warning is
                     printed and the list is truncated.

    Returns:
        List of live URLs (``scheme://host``) that returned any HTTP status.
    """
    if not targets:
        return []

    total = len(targets)
    alive_count = 0
    results: list[tuple[str, int, int | None]] = []  # (url, status, content_length)

    sem = asyncio.Semaphore(max_threads)
    connector = aiohttp.TCPConnector(ssl=False, limit=max_threads)

    print(
        f"{Fore.CYAN}[*] HTTP Probe: checking {total} targets "
        f"(threads={max_threads}, timeout={timeout}s)…{Style.RESET_ALL}"
    )

    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [
            _probe_one(session, t, sem, timeout, proxy, random_ua)
            for t in targets
        ]

        probed = 0
        for coro in asyncio.as_completed(tasks):
            result = await coro
            probed += 1

            if result is not None:
                alive_count += 1
                results.append(result)

            # Simple progress counter (print every 50 probes or on the last one)
            if probed % 50 == 0 or probed == total:
                print(
                    f"\r{Fore.CYAN}[*] Probing: {probed}/{total} — {alive_count} alive so far…"
                    f"{Style.RESET_ALL}",
                    end="",
                    flush=True,
                )

    print()  # newline after the progress line

    # ── Wildcard detection ────────────────────────────────────────────────────
    wildcard_filtered = 0
    if results:
        sig_counter: Counter[tuple[int, int | None]] = Counter(
            (status, cl) for _, status, cl in results
        )
        dominant_sig, dominant_count = sig_counter.most_common(1)[0]
        if dominant_count / len(results) >= _WILDCARD_THRESHOLD:
            # Keep one representative for the dominant signature; discard rest
            kept_dominant = False
            deduped: list[tuple[str, int, int | None]] = []
            for url, status, cl in results:
                if (status, cl) == dominant_sig:
                    if not kept_dominant:
                        deduped.append((url, status, cl))
                        kept_dominant = True
                    else:
                        wildcard_filtered += 1
                else:
                    deduped.append((url, status, cl))
            results = deduped
            print(
                f"{Fore.YELLOW}[⚠] Wildcard detected: {dominant_count} subdomains returned "
                f"identical responses (status={dominant_sig[0]}, "
                f"content-length={dominant_sig[1]}) — "
                f"filtered to {len(results)} unique hosts{Style.RESET_ALL}"
            )

    live_urls = [url for url, _, _ in results]

    print(
        f"{Fore.CYAN}[✔] HTTP Probe: {alive_count}/{total} alive "
        f"({wildcard_filtered} wildcards filtered){Style.RESET_ALL}"
    )

    # ── Safety cap ───────────────────────────────────────────────────────────
    if len(live_urls) > max_targets:
        logging.warning(
            "HTTP probe returned %d live hosts — truncating to %d (--max-probe-targets)",
            len(live_urls),
            max_targets,
        )
        print(
            f"{Fore.YELLOW}[⚠] {len(live_urls)} live hosts exceed the safety cap of "
            f"{max_targets}. Truncating. Use --max-probe-targets to raise this limit."
            f"{Style.RESET_ALL}"
        )
        live_urls = live_urls[:max_targets]

    return live_urls
