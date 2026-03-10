import asyncio
import logging
import re
import warnings
import aiohttp
from bs4 import BeautifulSoup, XMLParsedAsHTMLWarning
from tqdm import tqdm
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
                content_type = resp.headers.get('Content-Type', '')
                if not content_type.startswith(('text/', 'application/json', 'application/javascript', 'application/xml', 'application/xhtml')):
                    return js_links
                raw = await resp.read()
                encoding = resp.charset or 'utf-8'
                try:
                    text = raw.decode(encoding)
                except (UnicodeDecodeError, LookupError):
                    text = raw.decode('utf-8', errors='replace')
                found = re.findall(r'["\']((?:https?:)?//[^"\']+|/[^"\']{1,200})["\']', text)
                js_links.update(found)
    except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as e:
        logging.debug(f"Error fetching JS {js_url}: {e}")
    except Exception as e:
        logging.warning(f"Failed to process JS {js_url}: {e}")
    return js_links


async def discover_js_links(target_urls, depth, output_file=None, output_format="txt",
                             proxy=None, timeout=10, random_ua=False, rate_limit=None,
                             max_threads=20):
    display_banner()
    print(f"{Fore.CYAN}[*] Crawling {len(target_urls)} target(s) for JS files and endpoints (depth={depth})...{Style.RESET_ALL}")

    import random
    from vortex.user_agents import USER_AGENTS

    all_js_files = set()
    all_endpoints = set()
    lock = asyncio.Lock()
    sem = asyncio.Semaphore(max_threads)

    connector = aiohttp.TCPConnector(limit=max_threads, ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        for target_url in target_urls:
            queue = {target_url}
            visited = set()
            base_domain = urlparse(target_url).netloc

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

                            new_js_files = []
                            new_internal = []
                            for tag in soup.find_all("script", src=True):
                                js_url = urljoin(url, tag["src"])
                                new_js_files.append(js_url)

                            for a in soup.find_all("a", href=True):
                                full_url = urljoin(url, a["href"])
                                if urlparse(full_url).netloc == base_domain:
                                    new_internal.append(full_url)

                    for js_url in new_js_files:
                        endpoints = await fetch_and_extract_js_links(js_url, session, proxy=proxy, timeout=timeout)
                        async with lock:
                            if js_url not in all_js_files:
                                tqdm.write(f"{Fore.MAGENTA}[✔] JS: {js_url}{Style.RESET_ALL}")
                            all_js_files.add(js_url)
                            all_endpoints.update(endpoints)

                    async with lock:
                        queue.update(new_internal)
                except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as e:
                    logging.debug(f"Error in JS discovery for {url}: {e}")
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
                          desc=f"JS depth {d + 1}/{depth}",
                          ncols=80) as pbar:
                    await asyncio.gather(*[fetch_url(u, pbar) for u in current_queue])

    print(f"\n{Fore.YELLOW}[+] JavaScript Files Found: {len(all_js_files)}{Style.RESET_ALL}")

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
