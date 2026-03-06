import asyncio
import logging
import re
import json
import aiohttp
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
from colorama import Fore, Style

from vortex.utils import stop_event, display_banner

EMAIL_PATTERN = re.compile(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}')


async def harvest_emails(target_urls, depth=2, output_file=None, output_format='txt',
                          proxy=None, timeout=10, random_ua=False, rate_limit=None):
    display_banner()
    print(f"{Fore.CYAN}[*] Harvesting emails from {len(target_urls)} target(s) (depth={depth})...{Style.RESET_ALL}")

    import random
    from vortex.user_agents import USER_AGENTS

    all_emails = set()

    connector = aiohttp.TCPConnector(ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        for target_url in target_urls:
            base_domain = urlparse(target_url).netloc
            queue = {target_url}
            visited = set()

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
                            # Find emails in raw HTML
                            found = EMAIL_PATTERN.findall(html)
                            for email in found:
                                all_emails.add(email)
                                print(f"  {Fore.GREEN}[✔] {email}{Style.RESET_ALL}")

                            # Follow internal links
                            soup = BeautifulSoup(html, 'html.parser')
                            for a in soup.find_all('a', href=True):
                                full_url = urljoin(url, a['href'])
                                if urlparse(full_url).netloc == base_domain:
                                    queue.add(full_url)
                    except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as e:
                        logging.debug(f"Error harvesting {url}: {e}")
                        continue

                    if rate_limit:
                        await asyncio.sleep(1.0 / rate_limit)

    print(f"\n{Fore.YELLOW}[+] Total Emails Found: {len(all_emails)}{Style.RESET_ALL}")

    if output_file:
        with open(output_file, 'w') as f:
            if output_format == 'json':
                json.dump({"emails": sorted(list(all_emails))}, f, indent=2)
            else:
                for email in sorted(all_emails):
                    f.write(f"{email}\n")
        print(f"{Fore.CYAN}[✔] Email harvest results saved to {output_file}{Style.RESET_ALL}")

    return sorted(list(all_emails))
