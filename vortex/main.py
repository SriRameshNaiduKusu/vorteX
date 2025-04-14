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
            result = await resolver.gethostbyname(subdomain, socket.AF_INET)
            return subdomain, result.addresses[0]
        except:
            return None

async def enumerate_subdomains(domain, wordlist, max_threads, output_file):
    display_banner()
    print(f"{Fore.CYAN}[*] Enumerating subdomains for {domain}...{Style.RESET_ALL}")

    resolver = aiodns.DNSResolver()
    subdomains = [f"{line.strip()}.{domain}" for line in open(wordlist) if line.strip()]
    sem = asyncio.Semaphore(max_threads)
    results = []

    with tqdm(total=len(subdomains), desc="Subdomains", ncols=80) as bar:
        tasks = [resolve_subdomain(sub, resolver, sem) for sub in subdomains]
        for coro in asyncio.as_completed(tasks):
            if stop_event.is_set():
                break
            result = await coro
            if result:
                sub, ip = result
                tqdm.write(f"{Fore.GREEN}[✔] Found: {sub} -> {ip}{Style.RESET_ALL}")
                results.append(f"{sub} -> {ip}")
            bar.update(1)

    if output_file:
        with open(output_file, "a") as f:
            f.write("\n".join(results) + "\n")

# ===== Directory Fuzzing =====
async def fetch_directory(url, session, sem):
    async with sem:
        if stop_event.is_set():
            return None
        try:
            async with session.get(url, timeout=5) as resp:
                if resp.status in [200, 301, 302, 403]:
                    return url, resp.status
        except:
            return None

async def directory_fuzzing(base_url, wordlist, max_threads, output_file):
    display_banner()
    print(f"{Fore.CYAN}[*] Fuzzing directories on {base_url}...{Style.RESET_ALL}")

    paths = [line.strip() for line in open(wordlist) if line.strip()]
    urls = [f"{base_url.rstrip('/')}/{path}" for path in paths]
    sem = asyncio.Semaphore(max_threads)
    results = []

    connector = aiohttp.TCPConnector(limit=max_threads)
    async with aiohttp.ClientSession(connector=connector) as session:
        with tqdm(total=len(urls), desc="Fuzzing", ncols=80) as bar:
            tasks = [fetch_directory(url, session, sem) for url in urls]
            for coro in asyncio.as_completed(tasks):
                if stop_event.is_set():
                    break
                result = await coro
                if result:
                    url, status = result
                    tqdm.write(f"{Fore.GREEN}[✔] Found: {url} ({status}){Style.RESET_ALL}")
                    results.append(f"{url} ({status})")
                bar.update(1)

    if output_file:
        with open(output_file, "a") as f:
            f.write("\n".join(results) + "\n")

# ===== Third-Party Link Crawler =====
async def crawl_domain(target_url, depth, output_file=None):
    display_banner()
    print(f"{Fore.CYAN}[*] Crawling {target_url} for third-party links (depth={depth})...{Style.RESET_ALL}")

    base_domain = urlparse(target_url).netloc
    queue = {target_url}
    visited = set()
    external_links = set()

    async with aiohttp.ClientSession() as session:
        for _ in range(depth):
            next_queue = set()
            for url in queue:
                if stop_event.is_set():
                    break
                if url in visited:
                    continue
                visited.add(url)

                try:
                    async with session.get(url, timeout=5) as resp:
                        html = await resp.text()
                        soup = BeautifulSoup(html, "html.parser")

                        for tag in soup.find_all("a", href=True):
                            href = tag["href"]
                            full_url = urljoin(url, href)
                            if urlparse(full_url).netloc != base_domain:
                                external_links.add(full_url)
                            else:
                                next_queue.add(full_url)
                except:
                    continue
            queue = next_queue

    print(f"\n{Fore.YELLOW}[+] Total Third-Party Links Found: {len(external_links)}{Style.RESET_ALL}")
    for link in external_links:
        print(f"{Fore.MAGENTA}[✔] {link}{Style.RESET_ALL}")

    if output_file:
        with open(output_file, "a") as f:
            f.write("\n# Crawled Links\n")
            f.write("\n".join(external_links) + "\n")

# ===== JavaScript Link Discovery =====
async def fetch_and_extract_js_links(js_url, session):
    js_links = set()
    try:
        async with session.get(js_url, timeout=5) as resp:
            if resp.status == 200:
                text = await resp.text()
                found = re.findall(r'["\']((?:https?:)?//[^"\']+|/[^"\']+)["\']', text)
                js_links.update(found)
    except:
        pass
    return js_links

async def discover_js_links(target_url, depth, output_file=None):
    display_banner()
    print(f"{Fore.CYAN}[*] Crawling {target_url} for JavaScript files and endpoints (depth={depth})...{Style.RESET_ALL}")

    queue = {target_url}
    visited = set()
    js_files = set()
    endpoints = set()

    async with aiohttp.ClientSession() as session:
        for _ in range(depth):
            next_queue = set()
            for url in queue:
                if stop_event.is_set():
                    break
                if url in visited:
                    continue
                visited.add(url)

                try:
                    async with session.get(url, timeout=5) as resp:
                        html = await resp.text()
                        soup = BeautifulSoup(html, "html.parser")

                        for tag in soup.find_all("script", src=True):
                            js_url = urljoin(url, tag["src"])
                            js_files.add(js_url)
                            endpoints.update(await fetch_and_extract_js_links(js_url, session))

                        for a in soup.find_all("a", href=True):
                            href = a["href"]
                            full_url = urljoin(url, href)
                            if urlparse(full_url).netloc == urlparse(target_url).netloc:
                                next_queue.add(full_url)
                except:
                    continue
            queue = next_queue

    print(f"\n{Fore.YELLOW}[+] JavaScript Files Found: {len(js_files)}{Style.RESET_ALL}")
    for js in js_files:
        print(f"{Fore.MAGENTA}[✔] JS: {js}{Style.RESET_ALL}")

    print(f"\n{Fore.GREEN}[+] Endpoints/Paths Discovered in JS: {len(endpoints)}{Style.RESET_ALL}")
    for ep in endpoints:
        print(f"{Fore.GREEN}[✔] {ep}{Style.RESET_ALL}")

    if output_file:
        with open(output_file, "a") as f:
            f.write("\n# JS Files\n")
            f.writelines(f"{j}\n" for j in js_files)
            f.write("\n# JS Endpoints\n")
            f.writelines(f"{e}\n" for e in endpoints)

# ===== Parameter Discovery =====
def parse_headers(header_list):
    headers = {}
    for h in header_list:
        if ":" in h:
            k, v = h.split(":", 1)
            headers[k.strip()] = v.strip()
    return headers

def parameter_discovery(url, method, headers_list, wordlist, output_file, output_format):
    display_banner()
    print(f"{Fore.CYAN}[*] Discovering parameters on {url}...{Style.RESET_ALL}")

    headers = parse_headers(headers_list)
    params = [line.strip() for line in open(wordlist) if line.strip()]
    found = {}

    with tqdm(total=len(params), desc="Discovering Params", ncols=80) as bar:
        for param in params:
            if stop_event.is_set():
                break
            payload = {param: "vorteXTest"}
            try:
                response = requests.request(method, url, params=payload, headers=headers, timeout=5)
                if "vorteXTest" in response.text:
                    found[param] = response.status_code
                    tqdm.write(f"{Fore.GREEN}[✔] {param} ({response.status_code}){Style.RESET_ALL}")
            except:
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
    parser = argparse.ArgumentParser(description="vorteX - Advanced Async Recon Tool")

    parser.add_argument("-d", "--domain", help="Target domain for subdomain enumeration")
    parser.add_argument("-url", "--target", help="Target URL for directory fuzzing")
    parser.add_argument("-fuzz", "--fuzzing", action="store_true", help="Enable directory fuzzing")
    parser.add_argument("-crawl", help="Target URL to crawl for third-party links")
    parser.add_argument("-js", help="Target URL to discover JavaScript files and endpoints")
    parser.add_argument("-paramfuzz", action="store_true", help="Enable parameter discovery")

    parser.add_argument("--method", choices=["GET", "POST"], default="GET")
    parser.add_argument("--headers", nargs='*', default=[])
    parser.add_argument("--format", choices=["json", "txt"], default="txt")
    parser.add_argument("--depth", type=int, default=2, help="Crawling depth (default: 2)")
    parser.add_argument("-w", "--wordlist", help="Wordlist")
    parser.add_argument("-T", "--threads", type=int, default=10)
    parser.add_argument("-o", "--output", help="Save results to file")

    args = parser.parse_args()

    if args.domain and args.wordlist:
        asyncio.run(enumerate_subdomains(args.domain, args.wordlist, args.threads, args.output))

    elif args.target and args.fuzzing and args.wordlist:
        asyncio.run(directory_fuzzing(args.target, args.wordlist, args.threads, args.output))

    elif args.crawl:
        asyncio.run(crawl_domain(args.crawl, args.depth, args.output))

    elif args.js:
        asyncio.run(discover_js_links(args.js, args.depth, args.output))

    elif args.paramfuzz and args.target and args.wordlist:
        parameter_discovery(args.target, args.method, args.headers, args.wordlist, args.output, args.format)

    else:
        print(f"{Fore.RED}[!] Invalid argument combination. Use -h for help.{Style.RESET_ALL}")



if __name__ == "__main__":
    main()
