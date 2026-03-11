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


async def _auto_calibrate(session, base_url, timeout_obj, proxy=None, random_ua=False):
    """Send 3 random probe requests to *base_url* and derive filter values.

    Used when ``--auto-calibrate`` is requested.  Sends three gibberish-path
    GET requests and inspects body size, word count, and line count.  If all
    three probes return HTTP 200 with consistent responses, the baseline values
    are returned so the caller can build filter sets automatically.

    Returns:
        A dict with keys ``'sizes'``, ``'words'``, ``'lines'`` (each a ``set``
        of ints) when calibration succeeds, or ``None`` on failure / inconsistent
        probes.
    """
    req_kwargs = {}
    if proxy:
        req_kwargs["proxy"] = proxy
    headers = {}
    if random_ua:
        headers["User-Agent"] = random.choice(USER_AGENTS)

    probe_paths = [f"vortex-probe-{_random_path(10)}" for _ in range(3)]

    sizes = []
    word_counts = []
    line_counts = []

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
                if resp.status != 200:
                    return None
                body = await resp.read()
                body_text = body.decode("utf-8", errors="replace")
                sizes.append(len(body))
                word_counts.append(len(body_text.split()))
                line_counts.append(body_text.count("\n") + 1)
        except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as exc:
            logging.debug(f"Auto-calibrate probe error for {probe_url}: {exc}")
            return None

    if len(sizes) != 3:
        return None

    # Only auto-filter if all three probes agree within tolerance.
    if (
        max(sizes) - min(sizes) <= _WILDCARD_TOLERANCE
        and max(word_counts) - min(word_counts) <= 5
        and max(line_counts) - min(line_counts) <= 2
    ):
        # Use the median (middle) value for each metric.
        sorted_sizes = sorted(sizes)
        sorted_words = sorted(word_counts)
        sorted_lines = sorted(line_counts)
        return {
            "sizes": {sorted_sizes[1]},
            "words": {sorted_words[1]},
            "lines": {sorted_lines[1]},
        }

    return None


async def fetch_directory(url, session, sem, proxy=None, timeout=10, random_ua=False,
                          client_timeout=None, wildcard_hosts=None,
                          filter_size=None, filter_words=None,
                          filter_lines=None, filter_codes=None):
    """Fetch a single directory probe URL.

    Uses GET for all requests so filters and wildcard detection can inspect the
    response body when needed.

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
        filter_size: Set of body sizes (bytes) to filter out.
        filter_words: Set of word counts to filter out.
        filter_lines: Set of line counts to filter out.
        filter_codes: Set of HTTP status codes to filter out.

    Returns:
        ``(url, status, body_size, word_count, line_count)`` tuple on a genuine
        hit, ``None`` otherwise.
    """
    if client_timeout is None:
        client_timeout = aiohttp.ClientTimeout(total=timeout)

    # Determine whether any body-based processing is required.
    needs_body = bool(
        wildcard_hosts or filter_size or filter_words or filter_lines
    )

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

                # Apply status-code filter before reading the body.
                if filter_codes and status in filter_codes:
                    logging.debug(f"[filter-code] {url} ({status})")
                    await resp.release()
                    return None

                if status not in (200, 301, 302, 403):
                    await resp.release()
                    return None

                body_size = 0
                word_count = 0
                line_count = 0

                if needs_body:
                    body = await resp.read()
                    body_size = len(body)

                    # Wildcard / soft-404 check.
                    if is_wildcard_host and status == 200:
                        if abs(body_size - baseline_length) <= _WILDCARD_TOLERANCE:
                            logging.debug(
                                f"[wildcard-filtered] {url} "
                                f"({status}, {body_size}B ≈ {baseline_length}B baseline)"
                            )
                            return None

                    # Body-content filters (words / lines) require decoding.
                    if filter_words or filter_lines:
                        body_text = body.decode("utf-8", errors="replace")
                        word_count = len(body_text.split())
                        line_count = body_text.count("\n") + 1

                    # Apply size filter.
                    if filter_size and body_size in filter_size:
                        logging.debug(f"[filter-size] {url} ({body_size}B)")
                        return None

                    # Apply word-count filter.
                    if filter_words and word_count in filter_words:
                        logging.debug(f"[filter-words] {url} ({word_count} words)")
                        return None

                    # Apply line-count filter.
                    if filter_lines and line_count in filter_lines:
                        logging.debug(f"[filter-lines] {url} ({line_count} lines)")
                        return None
                else:
                    await resp.release()

                return url, status, body_size, word_count, line_count
        except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as exc:
            logging.debug(f"Error fetching {url}: {exc}")
            return None


async def directory_fuzzing(base_urls, wordlist, max_threads, output_file,
                             output_format="txt", proxy=None, timeout=10,
                             random_ua=False, rate_limit=None,
                             filter_size=None, filter_words=None,
                             filter_lines=None, filter_codes=None,
                             auto_calibrate=False):
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

    # Announce active manual filters so the user knows what's being excluded.
    if filter_size:
        print(f"{Fore.CYAN}[ℹ] Filter — size: {sorted(filter_size)}{Style.RESET_ALL}")
    if filter_words:
        print(f"{Fore.CYAN}[ℹ] Filter — words: {sorted(filter_words)}{Style.RESET_ALL}")
    if filter_lines:
        print(f"{Fore.CYAN}[ℹ] Filter — lines: {sorted(filter_lines)}{Style.RESET_ALL}")
    if filter_codes:
        print(f"{Fore.CYAN}[ℹ] Filter — codes: {sorted(filter_codes)}{Style.RESET_ALL}")

    sem = asyncio.Semaphore(max_threads)
    # Create one ClientTimeout object and reuse it for every request.
    client_timeout = aiohttp.ClientTimeout(total=timeout)

    results = []
    found_urls = []
    filtered_count = 0
    start_time = time.monotonic()

    connector = aiohttp.TCPConnector(limit=max_threads, ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:

        # ── Phase 0: wildcard / soft-404 detection ───────────────────────────
        unique_base_urls = list({base_url.rstrip("/") for base_url in base_urls})

        # Auto-calibrate: send 3 random probes to derive filter values.
        if auto_calibrate:
            print(
                f"{Fore.CYAN}[*] Auto-calibrating filters on {len(unique_base_urls)} host(s)...{Style.RESET_ALL}"
            )
            for base in unique_base_urls:
                cal = await _auto_calibrate(
                    session, base, client_timeout, proxy=proxy, random_ua=random_ua
                )
                if cal:
                    # Merge calibrated values into the active filter sets.
                    filter_size = (filter_size or set()) | cal["sizes"]
                    filter_words = (filter_words or set()) | cal["words"]
                    filter_lines = (filter_lines or set()) | cal["lines"]
                    tqdm.write(
                        f"{Fore.YELLOW}[⚠] Auto-calibrated {base}: "
                        f"size={sorted(cal['sizes'])} "
                        f"words={sorted(cal['words'])} "
                        f"lines={sorted(cal['lines'])}{Style.RESET_ALL}"
                    )
                else:
                    tqdm.write(
                        f"{Fore.GREEN}[✔] Auto-calibrate: {base} — no consistent baseline detected.{Style.RESET_ALL}"
                    )

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

        any_filter_active = bool(
            wildcard_hosts or filter_size or filter_words or filter_lines or filter_codes
        )

        # ── Phase 1: directory fuzzing ────────────────────────────────────────
        with tqdm(total=total, desc="Fuzzing", ncols=80) as bar:
            tasks = [
                fetch_directory(
                    url, session, sem,
                    proxy=proxy, timeout=timeout, random_ua=random_ua,
                    client_timeout=client_timeout, wildcard_hosts=wildcard_hosts,
                    filter_size=filter_size, filter_words=filter_words,
                    filter_lines=filter_lines, filter_codes=filter_codes,
                )
                for url in all_urls_to_fuzz
            ]
            for coro in asyncio.as_completed(tasks):
                if stop_event.is_set():
                    break
                result = await coro
                if result:
                    url, status, body_size, word_count, line_count = result
                    if any_filter_active:
                        tqdm.write(
                            f"{Fore.GREEN}[✔] Found: {url} ({status}) "
                            f"[size:{body_size} words:{word_count} lines:{line_count}]{Style.RESET_ALL}"
                        )
                    else:
                        tqdm.write(f"{Fore.GREEN}[✔] Found: {url} ({status}){Style.RESET_ALL}")
                    results.append({"url": url, "status": status})
                    found_urls.append(url)
                else:
                    # Count filtered/suppressed responses.
                    filtered_count += 1
                bar.update(1)
                if rate_limit:
                    await asyncio.sleep(1.0 / rate_limit)

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
        f"Filtered: {filtered_count} | "
        f"Wildcard hosts: {len(wildcard_hosts)}/{len(unique_base_urls)}{Style.RESET_ALL}"
    )

    if output_file:
        with open(output_file, "a") as f:
            if output_format == "json":
                json.dump(results, f, indent=2)
            else:
                f.write("\n".join(f"{r['url']} ({r['status']})" for r in results) + "\n")

    return found_urls
