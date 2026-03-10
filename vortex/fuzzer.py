import asyncio
import json
import logging
import random
import string
import time
from urllib.parse import urlparse

import aiohttp
from tqdm import tqdm
from colorama import Fore, Style

from vortex.utils import stop_event, display_banner
from vortex.user_agents import USER_AGENTS

# Tolerance in bytes for soft-404 / wildcard body-length comparison.
_WILDCARD_TOLERANCE = 50


def _random_path(length: int = 10) -> str:
    """Return a random alphanumeric string suitable for a probe path segment."""
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=length))


async def _detect_wildcard(session, base_url, timeout_obj, proxy=None, random_ua=False):
    """Probe *base_url* with two gibberish paths to detect wildcard / catch-all routing.

    Returns:
        ``(True, baseline_status, baseline_length)`` when both probes return HTTP 200
        and their body lengths are within :data:`_WILDCARD_TOLERANCE` bytes of each
        other (indicating a soft-404 / catch-all host).

        ``(False, 0, 0)`` otherwise.
    """
    req_kwargs = {}
    if proxy:
        req_kwargs["proxy"] = proxy
    headers = {}
    if random_ua:
        headers["User-Agent"] = random.choice(USER_AGENTS)

    probe_paths = [
        f"vortex-wildcard-{_random_path(8)}",
        f"vortex-wildcard-{_random_path(8)}",
    ]

    lengths = []
    statuses = []
    for path in probe_paths:
        probe_url = f"{base_url.rstrip('/')}/{path}"
        try:
            async with session.get(
                probe_url,
                timeout=timeout_obj,
                ssl=False,
                headers=headers or None,
                allow_redirects=True,
                **req_kwargs,
            ) as resp:
                statuses.append(resp.status)
                body = await resp.read()
                lengths.append(len(body))
        except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as exc:
            logging.debug(f"Wildcard probe error for {probe_url}: {exc}")
            return False, 0, 0

    if len(statuses) != 2:
        return False, 0, 0

    if statuses[0] == 200 and statuses[1] == 200:
        if abs(lengths[0] - lengths[1]) <= _WILDCARD_TOLERANCE:
            baseline_len = (lengths[0] + lengths[1]) // 2
            return True, 200, baseline_len

    return False, 0, 0


async def fetch_directory(url, session, sem, proxy=None, timeout=10, random_ua=False,
                          client_timeout=None, wildcard_hosts=None):
    """Fetch a single directory probe URL.

    Uses HEAD for non-wildcard hosts (faster — no body transfer).  Falls back to
    GET when the server responds with 405 Method Not Allowed.  For wildcard hosts
    a GET is always used so the response body length can be compared against the
    baseline captured during wildcard detection.

    Args:
        url: Full URL to probe.
        session: :class:`aiohttp.ClientSession` instance.
        sem: :class:`asyncio.Semaphore` controlling concurrency.
        proxy: Optional proxy URL string.
        timeout: Timeout in seconds (used only when *client_timeout* is ``None``).
        random_ua: Randomise the ``User-Agent`` header when ``True``.
        client_timeout: Pre-built :class:`aiohttp.ClientTimeout` object.  When
            ``None`` a new one is created from *timeout* (backward-compatible).
        wildcard_hosts: Mapping of ``base_url → (baseline_status, baseline_length)``
            produced by the wildcard-detection phase.  When ``None`` no soft-404
            filtering is applied.

    Returns:
        ``(url, status)`` tuple on a genuine hit, ``None`` otherwise.
    """
    if client_timeout is None:
        client_timeout = aiohttp.ClientTimeout(total=timeout)

    async with sem:
        if stop_event.is_set():
            return None
        req_kwargs = {}
        if proxy:
            req_kwargs["proxy"] = proxy
        headers = {}
        if random_ua:
            headers["User-Agent"] = random.choice(USER_AGENTS)

        # Determine whether this host is a known wildcard responder.
        base_url = None
        baseline_length = None
        if wildcard_hosts:
            # Extract scheme + host from the URL to look up the wildcard dict.
            try:
                parsed = urlparse(url)
                base_url = f"{parsed.scheme}://{parsed.netloc}"
            except Exception:
                pass
            if base_url and base_url in wildcard_hosts:
                _, baseline_length = wildcard_hosts[base_url]

        is_wildcard_host = baseline_length is not None

        try:
            async with session.get(
                url,
                timeout=client_timeout,
                ssl=False,
                headers=headers or None,
                allow_redirects=True,
                **req_kwargs,
            ) as resp:
                status = resp.status
                if status not in (200, 301, 302, 403):
                    # Release body without reading it.
                    await resp.release()
                    return None

                if is_wildcard_host and status == 200:
                    # Read body to compare length against the wildcard baseline.
                    body = await resp.read()
                    body_len = len(body)
                    if abs(body_len - baseline_length) <= _WILDCARD_TOLERANCE:
                        # Soft-404 — suppress.
                        logging.debug(
                            f"[wildcard-filtered] {url} "
                            f"({status}, {body_len}B ≈ {baseline_length}B baseline)"
                        )
                        return None
                else:
                    # Don't need the body — release it to avoid memory overhead.
                    await resp.release()

                return url, status
        except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as exc:
            logging.debug(f"Error fetching {url}: {exc}")
            return None


async def directory_fuzzing(base_urls, wordlist, max_threads, output_file,
                             output_format="txt", proxy=None, timeout=10,
                             random_ua=False, rate_limit=None):
    display_banner()
    print(f"{Fore.CYAN}[*] Fuzzing directories on {len(base_urls)} target(s)...{Style.RESET_ALL}")

    with open(wordlist) as f:
        paths = [line.strip() for line in f if line.strip()]
    all_urls_to_fuzz = [
        f"{base_url.rstrip('/')}/{path}"
        for base_url in base_urls
        for path in paths
    ]

    total = len(all_urls_to_fuzz)

    # Scale warning — give the user a heads-up before a very long scan.
    if total > 100_000:
        print(
            f"{Fore.YELLOW}[⚠] Large scan detected: {total:,} URLs to fuzz "
            f"(~{len(base_urls)} targets × {len(paths):,} paths).{Style.RESET_ALL}"
        )
        print(
            f"{Fore.CYAN}[ℹ] Tip: Use --fast for quicker scans, or --skip fuzz to skip fuzzing.{Style.RESET_ALL}"
        )

    sem = asyncio.Semaphore(max_threads)
    # Create one ClientTimeout object and reuse it for every request.
    client_timeout = aiohttp.ClientTimeout(total=timeout)

    results = []
    found_urls = []
    start_time = time.monotonic()

    connector = aiohttp.TCPConnector(limit=max_threads, ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:

        # ── Phase 0: wildcard / soft-404 detection ───────────────────────────
        unique_base_urls = list({base_url.rstrip("/") for base_url in base_urls})
        print(
            f"{Fore.CYAN}[*] Running wildcard detection on {len(unique_base_urls)} host(s)...{Style.RESET_ALL}"
        )

        wildcard_hosts: dict[str, tuple[int, int]] = {}

        async def _probe(base):
            return base, await _detect_wildcard(
                session, base, client_timeout, proxy=proxy, random_ua=random_ua
            )

        probe_tasks = [_probe(b) for b in unique_base_urls]
        with tqdm(total=len(unique_base_urls), desc="Wildcard check", ncols=80) as wbar:
            for coro in asyncio.as_completed(probe_tasks):
                base, (is_wc, wc_status, wc_len) = await coro
                if is_wc:
                    wildcard_hosts[base] = (wc_status, wc_len)
                    tqdm.write(
                        f"{Fore.YELLOW}[⚠] Wildcard detected: {base} "
                        f"({wc_status}, ~{wc_len} bytes) — filtering soft 404s{Style.RESET_ALL}"
                    )
                wbar.update(1)

        if wildcard_hosts:
            print(
                f"{Fore.YELLOW}[⚠] {len(wildcard_hosts)} wildcard host(s) detected — "
                f"soft-404 filtering active.{Style.RESET_ALL}"
            )
        else:
            print(f"{Fore.GREEN}[✔] No wildcard hosts detected.{Style.RESET_ALL}")

        # ── Phase 1: directory fuzzing ────────────────────────────────────────
        with tqdm(total=total, desc="Fuzzing", ncols=80) as bar:
            tasks = [
                fetch_directory(
                    url, session, sem,
                    proxy=proxy, timeout=timeout, random_ua=random_ua,
                    client_timeout=client_timeout, wildcard_hosts=wildcard_hosts,
                )
                for url in all_urls_to_fuzz
            ]
            for coro in asyncio.as_completed(tasks):
                if stop_event.is_set():
                    break
                result = await coro
                if result:
                    url, status = result
                    tqdm.write(f"{Fore.GREEN}[✔] Found: {url} ({status}){Style.RESET_ALL}")
                    results.append({"url": url, "status": status})
                    found_urls.append(url)
                bar.update(1)
                if rate_limit:
                    await asyncio.sleep(1.0 / rate_limit)

    # Derive filtered count from total processed minus genuine hits.
    # We count how many 200-responses were suppressed by comparing found vs
    # what an unfiltered run would have produced.  The simplest proxy is just
    # to track it inside fetch_directory; but to keep the function return type
    # unchanged we compute an approximation here.
    elapsed = time.monotonic() - start_time
    elapsed_str = (
        f"{int(elapsed // 60)}m {int(elapsed % 60)}s"
        if elapsed >= 60
        else f"{elapsed:.1f}s"
    )
    req_per_sec = total / elapsed if elapsed > 0 else 0

    print(
        f"{Fore.GREEN}[✔] Fuzzing complete — {total:,} requests in {elapsed_str} "
        f"({req_per_sec:.0f} req/s){Style.RESET_ALL}"
    )
    print(
        f"{Fore.GREEN}[✔] Found: {len(found_urls)} valid result(s) | "
        f"Wildcard hosts: {len(wildcard_hosts)}/{len(unique_base_urls)}{Style.RESET_ALL}"
    )

    if output_file:
        with open(output_file, "a") as f:
            if output_format == "json":
                json.dump(results, f, indent=2)
            else:
                f.write("\n".join(f"{r['url']} ({r['status']})" for r in results) + "\n")

    return found_urls
