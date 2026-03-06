import socket
import asyncio
import logging
from tqdm import tqdm
from colorama import Fore, Style

from vortex.utils import stop_event, display_banner


async def resolve_subdomain(subdomain, resolver, sem):
    async with sem:
        if stop_event.is_set():
            return None
        try:
            result = await resolver.gethostbyname(subdomain, socket.AF_INET)
            return subdomain, result.addresses[0]
        except (Exception,) as e:
            logging.debug(f"Failed to resolve {subdomain}: {e}")
            return None


async def enumerate_subdomains(domain, wordlist, max_threads, output_file,
                                output_format="txt", proxy=None, timeout=10,
                                random_ua=False, rate_limit=None):
    import aiodns
    display_banner()
    print(f"{Fore.CYAN}[*] Enumerating subdomains for {domain}...{Style.RESET_ALL}")

    resolver = aiodns.DNSResolver()
    with open(wordlist) as f:
        subdomains_to_check = [f"{line.strip()}.{domain}" for line in f if line.strip()]
    sem = asyncio.Semaphore(max_threads)
    results = []
    found_urls = []

    with tqdm(total=len(subdomains_to_check), desc="Subdomains", ncols=80) as bar:
        tasks = [resolve_subdomain(sub, resolver, sem) for sub in subdomains_to_check]
        for coro in asyncio.as_completed(tasks):
            if stop_event.is_set():
                break
            result = await coro
            if result:
                sub, ip = result
                tqdm.write(f"{Fore.GREEN}[✔] Found: {sub} -> {ip}{Style.RESET_ALL}")
                results.append({"subdomain": sub, "ip": ip})
                found_urls.append(f"https://{sub}")
            bar.update(1)
            if rate_limit:
                await asyncio.sleep(1.0 / rate_limit)

    if output_file:
        import json
        with open(output_file, "a") as f:
            if output_format == "json":
                json.dump(results, f, indent=2)
            else:
                f.write("\n".join(f"{r['subdomain']} -> {r['ip']}" for r in results) + "\n")

    return found_urls
