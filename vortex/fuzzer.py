import asyncio
import logging
import aiohttp
from tqdm import tqdm
from colorama import Fore, Style

from vortex.utils import stop_event, display_banner


async def fetch_directory(url, session, sem, proxy=None, timeout=10, random_ua=False):
    import random
    from vortex.user_agents import USER_AGENTS
    async with sem:
        if stop_event.is_set():
            return None
        req_kwargs = {}
        if proxy:
            req_kwargs['proxy'] = proxy
        headers = {}
        if random_ua:
            headers['User-Agent'] = random.choice(USER_AGENTS)
        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=timeout),
                                   ssl=False, headers=headers or None, **req_kwargs) as resp:
                if resp.status in [200, 301, 302, 403]:
                    return url, resp.status
        except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as e:
            logging.debug(f"Error fetching {url}: {e}")
            return None


async def directory_fuzzing(base_urls, wordlist, max_threads, output_file,
                             output_format="txt", proxy=None, timeout=10,
                             random_ua=False, rate_limit=None):
    display_banner()
    print(f"{Fore.CYAN}[*] Fuzzing directories on {len(base_urls)} target(s)...{Style.RESET_ALL}")

    with open(wordlist) as f:
        paths = [line.strip() for line in f if line.strip()]
    all_urls_to_fuzz = [f"{base_url.rstrip('/')}/{path}" for base_url in base_urls for path in paths]

    sem = asyncio.Semaphore(max_threads)
    results = []
    found_urls = []

    connector = aiohttp.TCPConnector(limit=max_threads, ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        with tqdm(total=len(all_urls_to_fuzz), desc="Fuzzing", ncols=80) as bar:
            tasks = [fetch_directory(url, session, sem, proxy=proxy, timeout=timeout, random_ua=random_ua)
                     for url in all_urls_to_fuzz]
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

    if output_file:
        import json
        with open(output_file, "a") as f:
            if output_format == "json":
                json.dump(results, f, indent=2)
            else:
                f.write("\n".join(f"{r['url']} ({r['status']})" for r in results) + "\n")

    return found_urls
