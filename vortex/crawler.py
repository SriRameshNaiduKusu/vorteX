import asyncio
import logging
import warnings
import aiohttp
from bs4 import BeautifulSoup, XMLParsedAsHTMLWarning
from tqdm import tqdm
from urllib.parse import urlparse, urljoin
from colorama import Fore, Style

from vortex.utils import stop_event, display_banner

warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)


async def crawl_domain(target_urls, depth, output_file=None, output_format="txt",
                        proxy=None, timeout=10, random_ua=False, rate_limit=None,
                        max_threads=20):
    display_banner()
    print(f"{Fore.CYAN}[*] Crawling {len(target_urls)} target(s) for third-party links (depth={depth})...{Style.RESET_ALL}")

    import random
    from vortex.user_agents import USER_AGENTS

    all_external_links = set()
    target_results = {}
    lock = asyncio.Lock()
    sem = asyncio.Semaphore(max_threads)

    connector = aiohttp.TCPConnector(limit=max_threads, ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        for target_url in target_urls:
            base_domain = urlparse(target_url).netloc
            queue = {target_url}
            visited = set()
            external_for_target = set()

            async def fetch_url(url, pbar):
                async with lock:
                    if url in visited:
                        pbar.update(1)
                        return
                    visited.add(url)

                if stop_event.is_set():
                    pbar.update(1)
                    return

                req_kwargs = {}
                if proxy:
                    req_kwargs['proxy'] = proxy
                headers = {}
                if random_ua:
                    headers['User-Agent'] = random.choice(USER_AGENTS)
                try:
                    async with sem:
                        async with session.get(url, timeout=aiohttp.ClientTimeout(total=timeout),
                                               ssl=False, headers=headers or None, **req_kwargs) as resp:
                            content_type = resp.headers.get('Content-Type', '')
                            if not content_type.startswith(('text/', 'application/json', 'application/javascript', 'application/xml', 'application/xhtml')):
                                pbar.update(1)
                                return
                            raw = await resp.read()
                            encoding = resp.charset or 'utf-8'
                            try:
                                html = raw.decode(encoding)
                            except (UnicodeDecodeError, LookupError):
                                html = raw.decode('utf-8', errors='replace')
                            soup = BeautifulSoup(html, "html.parser")

                            new_external = []
                            new_internal = []
                            for tag in soup.find_all("a", href=True):
                                href = tag["href"]
                                full_url = urljoin(url, href)
                                parsed = urlparse(full_url)

                                if parsed.netloc and parsed.scheme in ['http', 'https']:
                                    if parsed.netloc != base_domain:
                                        new_external.append(full_url)
                                    else:
                                        new_internal.append(full_url)

                            async with lock:
                                for link in new_external:
                                    if link not in all_external_links:
                                        tqdm.write(f"{Fore.MAGENTA}[✔] {link}{Style.RESET_ALL}")
                                    all_external_links.add(link)
                                    external_for_target.add(link)
                                queue.update(new_internal)
                except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as e:
                    logging.debug(f"Error crawling {url}: {e}")
                except Exception as e:
                    logging.warning(f"Failed to process {url}: {e}")

                if rate_limit:
                    await asyncio.sleep(1.0 / rate_limit)
                pbar.update(1)

            for d in range(depth):
                if stop_event.is_set() or not queue:
                    break

                current_queue = list(queue)
                queue = set()

                with tqdm(total=len(current_queue),
                          desc=f"Crawl depth {d + 1}/{depth}",
                          ncols=80) as pbar:
                    await asyncio.gather(*[fetch_url(u, pbar) for u in current_queue])

            target_results[target_url] = sorted(list(external_for_target))

    print(f"\n{Fore.YELLOW}[+] Total Third-Party Links Found: {len(all_external_links)}{Style.RESET_ALL}")

    if output_file:
        import json
        with open(output_file, "a") as f:
            if output_format == "json":
                json.dump({"targets": target_results}, f, indent=2)
            else:
                f.write("\n# Crawled Links\n")
                f.write("\n".join(sorted(list(all_external_links))) + "\n")
