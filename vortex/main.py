import sys
import asyncio
import argparse
from colorama import Fore, Style, init
from urllib.parse import urlparse

from vortex.utils import display_banner, setup_logging, VERSION
from vortex.wordlists import DEFAULT_SUBDOMAINS, DEFAULT_DIRECTORIES, DEFAULT_PARAMETERS


def _count_lines(path):
    """Return the number of non-empty lines in a file."""
    with open(path) as fh:
        return sum(1 for line in fh if line.strip())

init(autoreset=True)

if sys.platform.startswith('win'):
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())


def main():
    parser = argparse.ArgumentParser(
        description="vorteX - Advanced Async Recon Tool. Use '-' as a target to read from stdin."
    )

    # Modes
    parser.add_argument("-d", "--domain", help="Target domain for subdomain enumeration")
    parser.add_argument("-fuzz", "--fuzzing", action="store_true", help="Enable directory fuzzing on target URLs")
    parser.add_argument("-crawl", "--crawling", action="store_true", help="Crawl target URLs for third-party links")
    parser.add_argument("-js", "--discover-js", action="store_true", help="Discover JS files and endpoints on target URLs")
    parser.add_argument("-paramfuzz", "--parameter-fuzzing", action="store_true", help="Enable parameter discovery on a single target URL")
    parser.add_argument("-tech", "--fingerprint", action="store_true", help="Enable technology fingerprinting on target URLs")
    parser.add_argument("-dns", "--dns-enum", action="store_true", help="DNS record enumeration for a domain")
    parser.add_argument("-ssl", "--ssl-check", action="store_true", help="SSL/TLS certificate analysis")
    parser.add_argument("-ports", "--port-scan", action="store_true", help="Lightweight async port scanner")
    parser.add_argument("-emails", "--harvest-emails", action="store_true", help="Harvest emails from target URLs")
    parser.add_argument("-all", "--all", action="store_true",
                        help="Run all recon modules automatically in sequence")
    parser.add_argument("-url", "--target", help="Target URL (required for some modes if not using stdin)")

    # Options
    parser.add_argument("-w", "--wordlist", help="Wordlist for enumeration, fuzzing, or paramfuzz")
    parser.add_argument("-T", "--threads", type=int, default=20, help="Number of concurrent threads/tasks")
    parser.add_argument("-o", "--output", help="Save primary results to a file")
    parser.add_argument("--depth", type=int, default=2, help="Crawling depth for -js, -crawl, and -emails")
    parser.add_argument("--method", choices=["GET", "POST"], default="GET", help="HTTP method for -paramfuzz")
    parser.add_argument("--headers", nargs='*', default=[], help='Custom headers (e.g., "User-Agent: UA")')
    parser.add_argument("--format", choices=["json", "txt"], default="txt", help="Output format (global)")
    parser.add_argument("--proxy", help="HTTP/SOCKS proxy URL (e.g., http://127.0.0.1:8080)")
    parser.add_argument("--rate-limit", type=float, help="Max requests per second")
    parser.add_argument("--random-ua", action="store_true", help="Rotate User-Agent strings randomly")
    parser.add_argument("--timeout", type=float, default=10, help="Request timeout in seconds")
    parser.add_argument("--port-range", help="Custom port range for port scan (e.g., 1-1000)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose/debug logging")
    parser.add_argument("--version", action="version", version=f"vorteX v{VERSION}")

    args = parser.parse_args()

    setup_logging(args.verbose)

    targets = []
    if not sys.stdin.isatty():
        print(f"{Fore.CYAN}[*] Reading targets from stdin...{Style.RESET_ALL}")
        targets = [line.strip() for line in sys.stdin if line.strip()]
    elif args.target:
        targets = [args.target]

    # Parse custom headers
    headers_dict = {}
    for h in args.headers:
        if ":" in h:
            k, v = h.split(":", 1)
            headers_dict[k.strip()] = v.strip()

    # Common kwargs for modules
    common_kwargs = dict(
        proxy=args.proxy,
        timeout=args.timeout,
        random_ua=args.random_ua,
        rate_limit=args.rate_limit,
    )

    # --- Mode Logic ---
    if args.all:
        from vortex.full_recon import run_full_recon
        if not targets and not args.domain:
            print(f"{Fore.RED}[!] No targets specified. Use -url, -d, or pipe targets via stdin.{Style.RESET_ALL}")
            sys.exit(1)
        asyncio.run(run_full_recon(
            targets=targets,
            domain=args.domain,
            wordlist=args.wordlist,
            threads=args.threads,
            output=args.output,
            depth=args.depth,
            method=args.method,
            headers=headers_dict,
            output_format=args.format,
            proxy=args.proxy,
            rate_limit=args.rate_limit,
            random_ua=args.random_ua,
            timeout=args.timeout,
            verbose=args.verbose,
        ))

    elif args.domain and not any([args.dns_enum, args.ssl_check, args.port_scan]):
        from vortex.subdomain import enumerate_subdomains
        wordlist = args.wordlist or DEFAULT_SUBDOMAINS
        if not args.wordlist:
            print(f"{Fore.CYAN}[*] No wordlist specified. Using built-in default: subdomains.txt ({_count_lines(wordlist)} entries){Style.RESET_ALL}")
        found_urls = asyncio.run(enumerate_subdomains(
            args.domain, wordlist, args.threads, args.output,
            output_format=args.format, **common_kwargs
        ))
        if args.fingerprint and found_urls:
            from vortex.tech_fingerprinting import fingerprint_technologies
            print(f"{Fore.CYAN}[*] Running technology fingerprinting on discovered subdomains...{Style.RESET_ALL}")
            asyncio.run(fingerprint_technologies(found_urls, output_format=args.format, **common_kwargs))

    elif args.fuzzing:
        from vortex.fuzzer import directory_fuzzing
        wordlist = args.wordlist or DEFAULT_DIRECTORIES
        if not args.wordlist:
            print(f"{Fore.CYAN}[*] No wordlist specified. Using built-in default: directories.txt ({_count_lines(wordlist)} entries){Style.RESET_ALL}")
        if not targets:
            print(f"{Fore.RED}[!] No targets specified. Use -url or pipe targets via stdin.{Style.RESET_ALL}")
            sys.exit(1)
        found_urls = asyncio.run(directory_fuzzing(
            targets, wordlist, args.threads, args.output,
            output_format=args.format, **common_kwargs
        ))
        if args.fingerprint and found_urls:
            from vortex.tech_fingerprinting import fingerprint_technologies
            print(f"{Fore.CYAN}[*] Running technology fingerprinting on fuzzed URLs...{Style.RESET_ALL}")
            asyncio.run(fingerprint_technologies(found_urls, output_format=args.format, **common_kwargs))

    elif args.crawling:
        from vortex.crawler import crawl_domain
        if not targets:
            print(f"{Fore.RED}[!] No targets specified. Use -url or pipe targets via stdin.{Style.RESET_ALL}")
            sys.exit(1)
        asyncio.run(crawl_domain(targets, args.depth, args.output, output_format=args.format, **common_kwargs))

    elif args.discover_js:
        from vortex.js_discovery import discover_js_links
        if not targets:
            print(f"{Fore.RED}[!] No targets specified. Use -url or pipe targets via stdin.{Style.RESET_ALL}")
            sys.exit(1)
        asyncio.run(discover_js_links(targets, args.depth, args.output, output_format=args.format, **common_kwargs))

    elif args.parameter_fuzzing:
        from vortex.param_fuzzer import parameter_discovery
        if not targets:
            print(f"{Fore.RED}[!] Target URL (-url) is required for parameter fuzzing.{Style.RESET_ALL}")
            sys.exit(1)
        wordlist = args.wordlist or DEFAULT_PARAMETERS
        if not args.wordlist:
            print(f"{Fore.CYAN}[*] No wordlist specified. Using built-in default: parameters.txt ({_count_lines(wordlist)} entries){Style.RESET_ALL}")
        asyncio.run(parameter_discovery(
            targets[0], args.method, headers_dict, wordlist, args.output, args.format,
            max_threads=args.threads, **common_kwargs
        ))

    elif args.fingerprint and targets:
        from vortex.tech_fingerprinting import fingerprint_technologies
        asyncio.run(fingerprint_technologies(
            targets, output_file=args.output, output_format=args.format,
            max_threads=args.threads, **common_kwargs
        ))

    elif args.dns_enum:
        from vortex.dns_records import dns_enum
        domain = args.domain or (urlparse(targets[0]).netloc if targets else None)
        if not domain:
            print(f"{Fore.RED}[!] Domain required for DNS enumeration. Use -d or -url.{Style.RESET_ALL}")
            sys.exit(1)
        asyncio.run(dns_enum(domain, output_file=args.output, output_format=args.format))

    elif args.ssl_check:
        from vortex.ssl_analysis import ssl_check
        target = targets[0] if targets else (args.domain if args.domain else None)
        if not target:
            print(f"{Fore.RED}[!] Target required for SSL check. Use -url or -d.{Style.RESET_ALL}")
            sys.exit(1)
        host = urlparse(target).netloc or target
        port = 443
        # Handle IPv6 addresses like [::1]:443
        if host.startswith('['):
            bracket_end = host.find(']')
            if bracket_end != -1 and bracket_end + 1 < len(host) and host[bracket_end + 1] == ':':
                port = int(host[bracket_end + 2:])
                host = host[1:bracket_end]
        elif ':' in host:
            try:
                host, port_str = host.rsplit(':', 1)
                port = int(port_str)
            except ValueError:
                pass
        asyncio.run(ssl_check(host, port=port, output_file=args.output, output_format=args.format))

    elif args.port_scan:
        from vortex.port_scanner import port_scan
        target = targets[0] if targets else (args.domain if args.domain else None)
        if not target:
            print(f"{Fore.RED}[!] Target required for port scan. Use -url or -d.{Style.RESET_ALL}")
            sys.exit(1)
        host = urlparse(target).netloc or target
        # Strip port from host if present, handling IPv6 addresses
        if host.startswith('['):
            bracket_end = host.find(']')
            if bracket_end != -1:
                host = host[1:bracket_end]
        elif ':' in host:
            host = host.rsplit(':', 1)[0]
        asyncio.run(port_scan(
            host, port_range=args.port_range,
            max_threads=args.threads, output_file=args.output,
            output_format=args.format, timeout=args.timeout
        ))

    elif args.harvest_emails:
        from vortex.email_harvester import harvest_emails
        if not targets:
            print(f"{Fore.RED}[!] No targets specified. Use -url or pipe targets via stdin.{Style.RESET_ALL}")
            sys.exit(1)
        asyncio.run(harvest_emails(
            targets, depth=args.depth, output_file=args.output,
            output_format=args.format, **common_kwargs
        ))

    else:
        display_banner()
        print(f"{Fore.RED}[!] Please Specify Target. No valid mode or target specified. Use -h for help.{Style.RESET_ALL}")


if __name__ == "__main__":
    main()
