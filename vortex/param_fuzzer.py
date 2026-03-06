import asyncio
import logging
import json
import aiohttp
from tqdm import tqdm
from colorama import Fore, Style

from vortex.utils import stop_event, display_banner


async def discover_param(session, url, method, param, sem, proxy=None, timeout=10):
    async with sem:
        if stop_event.is_set():
            return None
        payload = {param: "vorteXTest"}
        req_kwargs = {}
        if proxy:
            req_kwargs['proxy'] = proxy
        try:
            if method == "GET":
                async with session.get(url, params=payload,
                                       timeout=aiohttp.ClientTimeout(total=timeout),
                                       ssl=False, **req_kwargs) as resp:
                    text = await resp.text()
                    if "vorteXTest" in text:
                        return param, resp.status
            else:
                async with session.post(url, data=payload,
                                        timeout=aiohttp.ClientTimeout(total=timeout),
                                        ssl=False, **req_kwargs) as resp:
                    text = await resp.text()
                    if "vorteXTest" in text:
                        return param, resp.status
        except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as e:
            logging.debug(f"Error fuzzing param {param}: {e}")
        return None


async def parameter_discovery(url, method, headers_dict, wordlist, output_file, output_format,
                               max_threads=20, proxy=None, timeout=10, random_ua=False,
                               rate_limit=None):
    display_banner()
    print(f"{Fore.CYAN}[*] Discovering parameters on {url}...{Style.RESET_ALL}")

    import random
    from vortex.user_agents import USER_AGENTS

    with open(wordlist) as f:
        params = [line.strip() for line in f if line.strip()]

    headers = dict(headers_dict)
    if random_ua:
        headers['User-Agent'] = random.choice(USER_AGENTS)

    found = {}
    sem = asyncio.Semaphore(max_threads)

    connector = aiohttp.TCPConnector(ssl=False)
    async with aiohttp.ClientSession(connector=connector, headers=headers) as session:
        with tqdm(total=len(params), desc="Discovering Params", ncols=80) as bar:
            tasks = [discover_param(session, url, method, param, sem, proxy=proxy, timeout=timeout)
                     for param in params]
            for coro in asyncio.as_completed(tasks):
                if stop_event.is_set():
                    break
                result = await coro
                if result:
                    param, status = result
                    found[param] = status
                    tqdm.write(f"{Fore.GREEN}[✔] {param} ({status}){Style.RESET_ALL}")
                bar.update(1)
                if rate_limit:
                    await asyncio.sleep(1.0 / rate_limit)

    if output_file:
        with open(output_file, "w") as f:
            if output_format == "json":
                json.dump(found, f, indent=2)
            else:
                for param, code in found.items():
                    f.write(f"{param}: {code}\n")

    print(f"{Fore.CYAN}\n[✔] Completed - Found {len(found)} parameters.{Style.RESET_ALL}")
