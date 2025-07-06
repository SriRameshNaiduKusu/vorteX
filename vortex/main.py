__all__ = []

import json
import requests
import socket
import argparse
import signal
import threading
import time
import sys
import asyncio
import aiohttp
import aiodns
from tqdm import tqdm
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
from pyfiglet import figlet_format
from colorama import Fore, Style, init
import re
from vortex.tech_fingerprinting import fingerprint_technologies

init(autoreset=True)

if sys.platform.startswith('win'):
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

stop_event = threading.Event()


def signal_handler(sig, frame):
    if not stop_event.is_set():
        print("\n[!] Scan interrupted. Exiting...\n")
        stop_event.set()
        time.sleep(0.5)
        sys.exit(0)


signal.signal(signal.SIGINT, signal_handler)


def display_banner():
    print(Fore.RED + figlet_format("vorteX", font="slant") + Style.RESET_ALL)
    print(f"{Fore.MAGENTA}[✔] vorteX - The Advanced Recon Tool{Style.RESET_ALL}\n")


# ===== Subdomain Enumeration =====
async def resolve_subdomain(subdomain, resolver, sem):
    async with sem:
        if stop_event.is_set():
            return None
        try:
            # Use HTTPS by default as it's more common
            result = await resolver.gethostbyname(subdomain, socket.AF_INET)
            return subdomain, result.addresses[0]
        except:
            return None


async def enumerate_subdomains(domain, wordlist, max_threads, output_file):
    display_banner()
    print(f"{Fore.CYAN}[*] Enumerating subdomains for {domain}...{Style.RESET_ALL}")

    resolver = aiodns.DNSResolver()
    subdomains_to_check = [f"{line.strip()}.{domain}" for line in open(wordlist) if line.strip()]
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
                results.append(f"{sub} -> {ip}")
                found_urls.append(f"https://{sub}")  # Assume HTTPS for fingerprinting
            bar.update(1)

    if output_file:
        with open(output_file, "a") as f:
            f.write("\n".join(results) + "\n")

    return found_urls


# ===== Directory Fuzzing =====
async def fetch_directory(url, session, sem):
    async with sem:
        if stop_event.is_set():
            return None
        try:
            async with session.get(url, timeout=5, ssl=False) as resp:
                if resp.status in [200, 301, 302, 403]:
                    return url, resp.status
        except:
            return None


async def directory_fuzzing(base_urls, wordlist, max_threads, output_file):
    display_banner()
    print(f"{Fore.CYAN}[*] Fuzzing directories on {len(base_urls)} target(s)...{Style.RESET_ALL}")

    paths = [line.strip() for line in open(wordlist) if line.strip()]
    all_urls_to_fuzz = [f"{base_url.rstrip('/')}/{path}" for base_url in base_urls for path in paths]

    sem = asyncio.Semaphore(max_threads)
    results = []
    found_urls = []

    connector = aiohttp.TCPConnector(limit=max_threads, ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        with tqdm(total=len(all_urls_to_fuzz), desc="Fuzzing", ncols=80) as bar:
            tasks = [fetch_directory(url, session, sem) for url in all_urls_to_fuzz]
            for coro in asyncio.as_completed(tasks):
                if stop_event.is_set():
                    break
                result = await coro
                if result:
                    url, status = result
                    tqdm.write(f"{Fore.GREEN}[✔] Found: {url} ({status}){Style.RESET_ALL}")
                    results.append(f"{url} ({status})")
                    found_urls.append(url)
                bar.update(1)

    if output_file:
        with open(output_file, "a") as f:
            f.write("\n".join(results) + "\n")

    return found_urls


# ===== Third-Party Link Crawler =====
async def crawl_domain(target_urls, depth, output_file=None):
    display_banner()
    print(
        f"{Fore.CYAN}[*] Crawling {len(target_urls)} target(s) for third-party links (depth={depth})...{Style.RESET_ALL}")

    all_external_links = set()
    async with aiohttp.ClientSession() as session:
        for target_url in target_urls:
            base_domain = urlparse(target_url).netloc
            queue = {target_url}
            visited = set()

            for _ in range(depth):
                if stop_event.is_set() or not queue:
                    break

                tasks = []
                current_queue = list(queue)
                queue = set()

                for url in current_queue:
                    if url in visited:
                        continue
                    visited.add(url)
                    try:
                        async with session.get(url, timeout=5, ssl=False) as resp:
                            html = await resp.text()
                            soup = BeautifulSoup(html, "html.parser")

                            for tag in soup.find_all("a", href=True):
                                href = tag["href"]
                                full_url = urljoin(url, href)
                                parsed_full_url = urlparse(full_url)

                                if parsed_full_url.netloc and parsed_full_url.scheme in ['http', 'https']:
                                    if parsed_full_url.netloc != base_domain:
                                        all_external_links.add(full_url)
                                    else:
                                        queue.add(full_url)
                    except:
                        continue

    print(f"\n{Fore.YELLOW}[+] Total Third-Party Links Found: {len(all_external_links)}{Style.RESET_ALL}")
    for link in sorted(list(all_external_links)):
        print(f"{Fore.MAGENTA}[✔] {link}{Style.RESET_ALL}")

    if output_file:
        with open(output_file, "a") as f:
            f.write("\n# Crawled Links\n")
            f.write("\n".join(sorted(list(all_external_links))) + "\n")


# ===== JavaScript Link Discovery =====
async def discover_js_links(target_urls, depth, output_file=None):
    display_banner()
    print(
        f"{Fore.CYAN}[*] Crawling {len(target_urls)} target(s) for JS files and endpoints (depth={depth})...{Style.RESET_ALL}")

    all_js_files = set()
    all_endpoints = set()

    async with aiohttp.ClientSession() as session:
        for target_url in target_urls:
            queue = {target_url}
            visited = set()
            base_domain = urlparse(target_url).netloc

            for _ in range(depth):
                if stop_event.is_set() or not queue:
                    break

                tasks = []
                current_queue = list(queue)
                queue = set()

                for url in current_queue:
                    if url in visited:
                        continue
                    visited.add(url)
                    try:
                        async with session.get(url, timeout=5, ssl=False) as resp:
                            html = await resp.text()
                            soup = BeautifulSoup(html, "html.parser")

                            for tag in soup.find_all("script", src=True):
                                js_url = urljoin(url, tag["src"])
                                all_js_files.add(js_url)
                                endpoints = await fetch_and_extract_js_links(js_url, session)
                                all_endpoints.update(endpoints)

                            for a in soup.find_all("a", href=True):
                                full_url = urljoin(url, a["href"])
                                if urlparse(full_url).netloc == base_domain:
                                    queue.add(full_url)
                    except:
                        continue

    print(f"\n{Fore.YELLOW}[+] JavaScript Files Found: {len(all_js_files)}{Style.RESET_ALL}")
    for js in sorted(list(all_js_files)):
        print(f"{Fore.MAGENTA}[✔] JS: {js}{Style.RESET_ALL}")

    print(f"\n{Fore.GREEN}[+] Endpoints/Paths Discovered in JS: {len(all_endpoints)}{Style.RESET_ALL}")
    for ep in sorted(list(all_endpoints)):
        print(f"{Fore.GREEN}[✔] {ep}{Style.RESET_ALL}")

    if output_file:
        with open(output_file, "a") as f:
            f.write("\n# JS Files\n")
            f.writelines(f"{j}\n" for j in sorted(list(all_js_files)))
            f.write("\n# JS Endpoints\n")
            f.writelines(f"{e}\n" for e in sorted(list(all_endpoints)))


async def fetch_and_extract_js_links(js_url, session):
    js_links = set()
    try:
        async with session.get(js_url, timeout=5, ssl=False) as resp:
            if resp.status == 200:
                text = await resp.text()
                # Improved regex to find paths and URLs
                found = re.findall(r'["\']((?:https?:)?//[^"\']+|/[^"\']{1,200})["\']', text)
                js_links.update(found)
    except:
        pass
    return js_links


# ===== Parameter Discovery =====
def parameter_discovery(url, method, headers_list, wordlist, output_file, output_format):
    display_banner()
    print(f"{Fore.CYAN}[*] Discovering parameters on {url}...{Style.RESET_ALL}")

    headers = {k.strip(): v.strip() for h in headers_list if ":" in h for k, v in [h.split(":", 1)]}
    params = [line.strip() for line in open(wordlist) if line.strip()]
    found = {}

    with tqdm(total=len(params), desc="Discovering Params", ncols=80) as bar:
        for param in params:
            if stop_event.is_set():
                break
            payload = {param: "vorteXTest"}
            try:
                # Using synchronous requests for this module as it's simpler for its logic
                response = requests.request(method, url, params=payload, headers=headers, timeout=5)
                if "vorteXTest" in response.text:
                    found[param] = response.status_code
                    tqdm.write(f"{Fore.GREEN}[✔] {param} ({response.status_code}){Style.RESET_ALL}")
            except requests.exceptions.RequestException:
                pass
            bar.update(1)

    if output_file:
        with open(output_file, "w") as f:
            if output_format == "json":
                json.dump(found, f, indent=2)
            else:
                for param, code in found.items():
                    f.write(f"{param}: {code}\n")

    print(f"{Fore.CYAN}\n[✔] Completed - Found {len(found)} parameters.{Style.RESET_ALL}")


# ===== CLI Parser =====
def main():
    parser = argparse.ArgumentParser(description="vorteX - Advanced Async Recon Tool. Use '-' as a target to read from stdin.")

    # Modes
    parser.add_argument("-d", "--domain", help="Target domain for subdomain enumeration")
    parser.add_argument("-fuzz", "--fuzzing", action="store_true", help="Enable directory fuzzing on target URLs")
    parser.add_argument("-crawl", "--crawling", action="store_true", help="Crawl target URLs for third-party links")
    parser.add_argument("-js", "--discover-js", action="store_true", help="Discover JS files and endpoints on target URLs")
    parser.add_argument("-paramfuzz", "--parameter-fuzzing", action="store_true", help="Enable parameter discovery on a single target URL")
    parser.add_argument("-tech", "--fingerprint", action="store_true", help="Enable technology fingerprinting on target URLs")
    parser.add_argument("-url", "--target", help="Target URL (required for some modes if not using stdin)")

    # Options
    parser.add_argument("-w", "--wordlist", help="Wordlist for enumeration, fuzzing, or paramfuzz")
    parser.add_argument("-T", "--threads", type=int, default=20, help="Number of concurrent threads/tasks")
    parser.add_argument("-o", "--output", help="Save primary results to a file (e.g., subdomains, fuzz results)")
    parser.add_argument("--depth", type=int, default=2, help="Crawling depth for -js and -crawl")
    parser.add_argument("--method", choices=["GET", "POST"], default="GET", help="HTTP method for -paramfuzz")
    parser.add_argument("--headers", nargs='*', default=[], help='Custom headers (e.g., "User-Agent: UA")')
    parser.add_argument("--format", choices=["json", "txt"], default="txt", help="Output format for -paramfuzz")

    args = parser.parse_args()

    targets = []
    # Check if data is being piped to stdin
    if not sys.stdin.isatty():
        print(f"{Fore.CYAN}[*] Reading targets from stdin...{Style.RESET_ALL}")
        targets = [line.strip() for line in sys.stdin if line.strip()]
    elif args.target:
        targets = [args.target]

    # --- Mode Logic ---
    if args.domain:
        if not args.wordlist:
            print(f"{Fore.RED}[!] Wordlist required for subdomain enumeration. Use -w.{Style.RESET_ALL}")
            sys.exit(1)
        found_urls = asyncio.run(enumerate_subdomains(args.domain, args.wordlist, args.threads, args.output))
        if args.fingerprint and found_urls:
            print(f"{Fore.CYAN}[*] Running technology fingerprinting on discovered subdomains...{Style.RESET_ALL}")
            asyncio.run(fingerprint_technologies(found_urls))

    elif args.fuzzing:
        if not args.wordlist:
            print(f"{Fore.RED}[!] Wordlist required for fuzzing. Use -w.{Style.RESET_ALL}")
            sys.exit(1)
        if not targets:
            print(f"{Fore.RED}[!] No targets specified. Use -url or pipe targets via stdin.{Style.RESET_ALL}")
            sys.exit(1)

        found_urls = asyncio.run(directory_fuzzing(targets, args.wordlist, args.threads, args.output))
        if args.fingerprint and found_urls:
            print(f"{Fore.CYAN}[*] Running technology fingerprinting on fuzzed URLs...{Style.RESET_ALL}")
            asyncio.run(fingerprint_technologies(found_urls))

    elif args.crawling:
        if not targets:
            print(f"{Fore.RED}[!] No targets specified. Use -url or pipe targets via stdin.{Style.RESET_ALL}")
            sys.exit(1)
        asyncio.run(crawl_domain(targets, args.depth, args.output))

    elif args.discover_js:
        if not targets:
            print(f"{Fore.RED}[!] No targets specified. Use -url or pipe targets via stdin.{Style.RESET_ALL}")
            sys.exit(1)
        asyncio.run(discover_js_links(targets, args.depth, args.output))

    elif args.parameter_fuzzing:
        if not args.wordlist or not targets:
            print(
                f"{Fore.RED}[!] Target URL (-url) and wordlist (-w) are required for parameter fuzzing.{Style.RESET_ALL}")
            sys.exit(1)
        parameter_discovery(targets[0], args.method, args.headers, args.wordlist, args.output, args.format)

    elif args.fingerprint and targets:
        asyncio.run(fingerprint_technologies(targets))

    else:
        print(f"{Fore.RED}[!] No valid mode or target specified. Use -h for help.{Style.RESET_ALL}")


if __name__ == "__main__":
    main()