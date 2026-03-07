import asyncio
import logging
import re
import warnings
import aiohttp
from bs4 import BeautifulSoup, XMLParsedAsHTMLWarning
from urllib.parse import urlparse, urljoin
from colorama import Fore, Style

from vortex.utils import stop_event, display_banner

warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)


async def fetch_and_extract_js_links(js_url, session, proxy=None, timeout=10):
    js_links = set()
    req_kwargs = {}
    if proxy:
        req_kwargs['proxy'] = proxy
    try:
        async with session.get(js_url, timeout=aiohttp.ClientTimeout(total=timeout),
                               ssl=False, **req_kwargs) as resp:
            if resp.status == 200:
                text = await resp.text()
                found = re.findall(r'["\']((?:https?:)?//[^"\']+|/[^"\']{1,200})["\']', text)
                js_links.update(found)
    except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as e:
        logging.debug(f"Error fetching JS {js_url}: {e}")
    return js_links


async def discover_js_links(target_urls, depth, output_file=None, output_format="txt",
                             proxy=None, timeout=10, random_ua=False, rate_limit=None):
    display_banner()
    print(f"{Fore.CYAN}[*] Crawling {len(target_urls)} target(s) for JS files and endpoints (depth={depth})...{Style.RESET_ALL}")

    import random
    from vortex.user_agents import USER_AGENTS

    all_js_files = set()
    all_endpoints = set()

    connector = aiohttp.TCPConnector(ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        for target_url in target_urls:
            queue = {target_url}
            visited = set()
            base_domain = urlparse(target_url).netloc

            for _ in range(depth):
                if stop_event.is_set() or not queue:
                    break

                current_queue = list(queue)
                queue = set()

                for url in current_queue:
                    if url in visited:
                        continue
                    visited.add(url)
                    req_kwargs = {}
                    if proxy:
                        req_kwargs['proxy'] = proxy
                    headers = {}
                    if random_ua:
                        headers['User-Agent'] = random.choice(USER_AGENTS)
                    try:
                        async with session.get(url, timeout=aiohttp.ClientTimeout(total=timeout),
                                               ssl=False, headers=headers or None, **req_kwargs) as resp:
                            html = await resp.text()
                            soup = BeautifulSoup(html, "html.parser")

                            for tag in soup.find_all("script", src=True):
                                js_url = urljoin(url, tag["src"])
                                all_js_files.add(js_url)
                                endpoints = await fetch_and_extract_js_links(js_url, session, proxy=proxy, timeout=timeout)
                                all_endpoints.update(endpoints)

                            for a in soup.find_all("a", href=True):
                                full_url = urljoin(url, a["href"])
                                if urlparse(full_url).netloc == base_domain:
                                    queue.add(full_url)
                    except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as e:
                        logging.debug(f"Error in JS discovery for {url}: {e}")
                        continue

                    if rate_limit:
                        await asyncio.sleep(1.0 / rate_limit)

    print(f"\n{Fore.YELLOW}[+] JavaScript Files Found: {len(all_js_files)}{Style.RESET_ALL}")
    for js in sorted(list(all_js_files)):
        print(f"{Fore.MAGENTA}[✔] JS: {js}{Style.RESET_ALL}")

    print(f"\n{Fore.GREEN}[+] Endpoints/Paths Discovered in JS: {len(all_endpoints)}{Style.RESET_ALL}")
    for ep in sorted(list(all_endpoints)):
        print(f"{Fore.GREEN}[✔] {ep}{Style.RESET_ALL}")

    if output_file:
        import json
        with open(output_file, "a") as f:
            if output_format == "json":
                json.dump({"js_files": sorted(list(all_js_files)), "endpoints": sorted(list(all_endpoints))}, f, indent=2)
            else:
                f.write("\n# JS Files\n")
                f.writelines(f"{j}\n" for j in sorted(list(all_js_files)))
                f.write("\n# JS Endpoints\n")
                f.writelines(f"{e}\n" for e in sorted(list(all_endpoints)))
