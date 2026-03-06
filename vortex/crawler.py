import asyncio
import logging
import aiohttp
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
from colorama import Fore, Style

from vortex.utils import stop_event, display_banner


async def crawl_domain(target_urls, depth, output_file=None, output_format="txt",
                        proxy=None, timeout=10, random_ua=False, rate_limit=None):
    display_banner()
    print(f"{Fore.CYAN}[*] Crawling {len(target_urls)} target(s) for third-party links (depth={depth})...{Style.RESET_ALL}")

    import random
    from vortex.user_agents import USER_AGENTS

    all_external_links = set()
    target_results = {}

    connector = aiohttp.TCPConnector(ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        for target_url in target_urls:
            base_domain = urlparse(target_url).netloc
            queue = {target_url}
            visited = set()
            external_for_target = set()

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

                            for tag in soup.find_all("a", href=True):
                                href = tag["href"]
                                full_url = urljoin(url, href)
                                parsed = urlparse(full_url)

                                if parsed.netloc and parsed.scheme in ['http', 'https']:
                                    if parsed.netloc != base_domain:
                                        all_external_links.add(full_url)
                                        external_for_target.add(full_url)
                                    else:
                                        queue.add(full_url)
                    except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as e:
                        logging.debug(f"Error crawling {url}: {e}")
                        continue

                    if rate_limit:
                        await asyncio.sleep(1.0 / rate_limit)

            target_results[target_url] = sorted(list(external_for_target))

    print(f"\n{Fore.YELLOW}[+] Total Third-Party Links Found: {len(all_external_links)}{Style.RESET_ALL}")
    for link in sorted(list(all_external_links)):
        print(f"{Fore.MAGENTA}[✔] {link}{Style.RESET_ALL}")

    if output_file:
        import json
        with open(output_file, "a") as f:
            if output_format == "json":
                json.dump({"targets": target_results}, f, indent=2)
            else:
                f.write("\n# Crawled Links\n")
                f.write("\n".join(sorted(list(all_external_links))) + "\n")
