import sys
import asyncio
import argparse
from colorama import Fore, Style, init
from urllib.parse import urlparse

from vortex.utils import display_banner, setup_logging, VERSION, _count_lines
from vortex.wordlists import (
    get_wordlist_for_size,
    _SECLISTS_FILES,
)


def _resolve_wordlist(module, size, explicit_wordlist):
    """Return (wordlist_path, already_printed_message) for *module*.

    If the user supplied an explicit ``-w`` path, that takes priority.
    Otherwise tries SecLists, then falls back to bundled wordlists, printing
    an informative status message either way.
    """
    if explicit_wordlist:
        return explicit_wordlist

    path, from_seclists = get_wordlist_for_size(module, size)
    count = _count_lines(path)

    if from_seclists:
        relative = _SECLISTS_FILES.get(module, {}).get(size, path)
        print(
            f"{Fore.CYAN}[*] Using SecLists ({size}): {relative} ({count} entries){Style.RESET_ALL}"
        )
    else:
        bundled_name = {
            'subdomains': 'subdomains.txt',
            'directories': 'directories.txt',
            'parameters': 'parameters.txt',
        }.get(module, 'wordlist.txt')
        print(
            f"{Fore.CYAN}[*] SecLists not found. Using built-in wordlist: {bundled_name} ({count} entries). "
            f"Install SecLists for better results: apt install seclists  "
            f"or: git clone https://github.com/danielmiessler/SecLists ~/SecLists{Style.RESET_ALL}"
        )

    return path

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
    parser.add_argument("-takeover", "--takeover", action="store_true",
                        help="Check subdomains for takeover vulnerabilities")
    parser.add_argument("-ct", "--ct-enum", action="store_true",
                        help="Mine Certificate Transparency logs for subdomains (crt.sh)")
    parser.add_argument("-wayback", "--wayback", action="store_true",
                        help="Mine Wayback Machine for historical URLs")
    parser.add_argument("-cors", "--cors-scan", action="store_true",
                        help="Scan for CORS misconfigurations")
    parser.add_argument("-sensitive", "--sensitive-files", action="store_true",
                        help="Check for exposed sensitive files and paths")
    parser.add_argument("-header-audit", "--header-audit", action="store_true",
                        help="Audit HTTP security headers and provide a grade (A-F)")
    parser.add_argument("-redirect", "--open-redirect", action="store_true",
                        help="Test for open redirect vulnerabilities")
    parser.add_argument("-api", "--api-discovery", action="store_true",
                        help="Discover API endpoints, GraphQL, and OpenAPI specs")

    # New vulnerability scanning modes
    parser.add_argument("-xss", "--xss-scan", action="store_true",
                        help="Scan for reflected XSS vulnerabilities")
    parser.add_argument("-sqli", "--sqli-scan", action="store_true",
                        help="Scan for SQL injection vulnerabilities")
    parser.add_argument("-ssrf", "--ssrf-scan", action="store_true",
                        help="Scan for SSRF vulnerabilities")
    parser.add_argument("-lfi", "--lfi-scan", action="store_true",
                        help="Scan for Local File Inclusion vulnerabilities")
    parser.add_argument("-bypass403", "--bypass-403", action="store_true",
                        help="Attempt 403 Forbidden bypass techniques")
    parser.add_argument("-waf", "--waf-detect", action="store_true",
                        help="Detect Web Application Firewalls")

    # Options
    parser.add_argument("-w", "--wordlist", help="Wordlist for enumeration, fuzzing, or paramfuzz")
    parser.add_argument("--wordlist-size", choices=["small", "medium", "large"], default="small",
                        help="SecLists wordlist size tier: small (default), medium, or large")
    parser.add_argument("-T", "--threads", type=int, default=20, help="Number of concurrent threads/tasks")
    parser.add_argument("-o", "--output", help="Save primary results to a file")
    parser.add_argument("--depth", type=int, default=2, help="Crawling depth for -js, -crawl, and -emails")
    parser.add_argument("--method", choices=["GET", "POST"], default="GET", help="HTTP method for -paramfuzz")
    parser.add_argument("--headers", nargs='*', default=[], help='Custom headers (e.g., "User-Agent: UA")')
    parser.add_argument("--format", choices=["json", "txt"], default="txt", help="Output format (global)")
    parser.add_argument("--proxy", help="HTTP/SOCKS proxy URL (e.g., http://127.0.0.1:8080)")
    parser.add_argument("--proxy-file", help="File with proxy URLs for rotation (one per line)")
    parser.add_argument("--rate-limit", type=float, help="Max requests per second")
    parser.add_argument("--random-ua", action="store_true", help="Rotate User-Agent strings randomly")
    parser.add_argument("--timeout", type=float, default=10, help="Request timeout in seconds")
    parser.add_argument("--port-range", help="Custom port range for port scan (e.g., 1-1000)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose/debug logging")
    parser.add_argument("--version", action="version", version=f"vorteX v{VERSION}")
    parser.add_argument("--fast", action="store_true",
                        help="Enable fast mode — reduced payloads and checks for quicker scans")
    parser.add_argument("--skip", default="",
                        help="Comma-separated list of modules to skip during -all mode "
                             "(e.g., dns,ssl,ports,subdomains,fuzzing,tech,crawl,js,emails,params,"
                             "ct,wayback,redirect,cors,takeover,waf,xss,sqli,ssrf,lfi)")

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
    proxy = args.proxy
    if not proxy and args.proxy_file:
        from vortex.proxy_manager import ProxyManager
        try:
            pm = ProxyManager(args.proxy_file)
            proxy = pm.next()
            print(f"{Fore.CYAN}[*] Proxy rotation enabled — {len(pm)} proxies loaded.{Style.RESET_ALL}")
        except (ValueError, OSError) as exc:
            print(f"{Fore.YELLOW}[!] Could not load proxy file: {exc}{Style.RESET_ALL}")

    common_kwargs = dict(
        proxy=proxy,
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
            wordlist_size=args.wordlist_size,
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
            fast=args.fast,
            skip=args.skip,
        ))

    elif args.domain and not any([args.dns_enum, args.ssl_check, args.port_scan]):
        from vortex.subdomain import enumerate_subdomains
        wordlist = _resolve_wordlist('subdomains', args.wordlist_size, args.wordlist)
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
        wordlist = _resolve_wordlist('directories', args.wordlist_size, args.wordlist)
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
        wordlist = _resolve_wordlist('parameters', args.wordlist_size, args.wordlist)
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

    elif args.takeover:
        from vortex.takeover import check_takeover
        subdomains = targets[:]
        if args.domain:
            # Run subdomain enum first, then check takeover
            from vortex.subdomain import enumerate_subdomains
            wordlist = _resolve_wordlist('subdomains', args.wordlist_size, args.wordlist)
            found = asyncio.run(enumerate_subdomains(
                args.domain, wordlist, args.threads, None,
                output_format=args.format, **common_kwargs
            ))
            subdomains.extend(found)
        if not subdomains:
            print(f"{Fore.RED}[!] No subdomains to check. Use -d or -url.{Style.RESET_ALL}")
            sys.exit(1)
        asyncio.run(check_takeover(
            subdomains, output_file=args.output, output_format=args.format,
            max_threads=args.threads, **common_kwargs
        ))

    elif args.ct_enum:
        from vortex.ct_enum import ct_search
        domain = args.domain or (urlparse(targets[0]).netloc if targets else None)
        if not domain:
            print(f"{Fore.RED}[!] Domain required for CT log mining. Use -d or -url.{Style.RESET_ALL}")
            sys.exit(1)
        asyncio.run(ct_search(domain, output_file=args.output, output_format=args.format, **common_kwargs))

    elif args.wayback:
        from vortex.wayback import wayback_enum
        domain = args.domain or (urlparse(targets[0]).netloc if targets else None)
        if not domain:
            print(f"{Fore.RED}[!] Domain required for Wayback mining. Use -d or -url.{Style.RESET_ALL}")
            sys.exit(1)
        asyncio.run(wayback_enum(domain, output_file=args.output, output_format=args.format, **common_kwargs))

    elif args.cors_scan:
        from vortex.cors_scanner import check_cors
        if not targets:
            print(f"{Fore.RED}[!] No targets specified. Use -url or pipe targets via stdin.{Style.RESET_ALL}")
            sys.exit(1)
        asyncio.run(check_cors(
            targets, output_file=args.output, output_format=args.format,
            max_threads=args.threads, fast=args.fast, **common_kwargs
        ))

    elif args.sensitive_files:
        from vortex.sensitive_files import scan_sensitive_files
        if not targets:
            print(f"{Fore.RED}[!] No targets specified. Use -url or pipe targets via stdin.{Style.RESET_ALL}")
            sys.exit(1)
        asyncio.run(scan_sensitive_files(
            targets, output_file=args.output, output_format=args.format,
            max_threads=args.threads, fast=args.fast, **common_kwargs
        ))

    elif args.header_audit:
        from vortex.header_audit import audit_headers
        if not targets:
            print(f"{Fore.RED}[!] No targets specified. Use -url or pipe targets via stdin.{Style.RESET_ALL}")
            sys.exit(1)
        asyncio.run(audit_headers(
            targets, output_file=args.output, output_format=args.format,
            max_threads=args.threads, **common_kwargs
        ))

    elif args.open_redirect:
        from vortex.open_redirect import check_open_redirect
        if not targets:
            print(f"{Fore.RED}[!] No targets specified. Use -url or pipe targets via stdin.{Style.RESET_ALL}")
            sys.exit(1)
        asyncio.run(check_open_redirect(
            targets, output_file=args.output, output_format=args.format,
            max_threads=args.threads, fast=args.fast, **common_kwargs
        ))

    elif args.api_discovery:
        from vortex.api_discovery import discover_api_endpoints
        if not targets:
            print(f"{Fore.RED}[!] No targets specified. Use -url or pipe targets via stdin.{Style.RESET_ALL}")
            sys.exit(1)
        asyncio.run(discover_api_endpoints(
            targets, output_file=args.output, output_format=args.format,
            max_threads=args.threads, **common_kwargs
        ))

    elif args.xss_scan:
        from vortex.xss_scanner import scan_xss
        if not targets:
            print(f"{Fore.RED}[!] No targets specified. Use -url or pipe targets via stdin.{Style.RESET_ALL}")
            sys.exit(1)
        asyncio.run(scan_xss(
            targets, output_file=args.output, output_format=args.format,
            max_threads=args.threads, fast=args.fast, **common_kwargs
        ))

    elif args.sqli_scan:
        from vortex.sqli_scanner import scan_sqli
        if not targets:
            print(f"{Fore.RED}[!] No targets specified. Use -url or pipe targets via stdin.{Style.RESET_ALL}")
            sys.exit(1)
        asyncio.run(scan_sqli(
            targets, output_file=args.output, output_format=args.format,
            max_threads=args.threads, fast=args.fast, **common_kwargs
        ))

    elif args.ssrf_scan:
        from vortex.ssrf_scanner import scan_ssrf
        if not targets:
            print(f"{Fore.RED}[!] No targets specified. Use -url or pipe targets via stdin.{Style.RESET_ALL}")
            sys.exit(1)
        asyncio.run(scan_ssrf(
            targets, output_file=args.output, output_format=args.format,
            max_threads=args.threads, fast=args.fast, **common_kwargs
        ))

    elif args.lfi_scan:
        from vortex.lfi_scanner import scan_lfi
        if not targets:
            print(f"{Fore.RED}[!] No targets specified. Use -url or pipe targets via stdin.{Style.RESET_ALL}")
            sys.exit(1)
        asyncio.run(scan_lfi(
            targets, output_file=args.output, output_format=args.format,
            max_threads=args.threads, fast=args.fast, **common_kwargs
        ))

    elif args.bypass_403:
        from vortex.bypass403 import bypass_403
        if not targets:
            print(f"{Fore.RED}[!] No targets specified. Use -url or pipe targets via stdin.{Style.RESET_ALL}")
            sys.exit(1)
        asyncio.run(bypass_403(
            targets, output_file=args.output, output_format=args.format,
            max_threads=args.threads, **common_kwargs
        ))

    elif args.waf_detect:
        from vortex.waf_detector import detect_waf
        if not targets:
            print(f"{Fore.RED}[!] No targets specified. Use -url or pipe targets via stdin.{Style.RESET_ALL}")
            sys.exit(1)
        asyncio.run(detect_waf(
            targets, output_file=args.output, output_format=args.format,
            max_threads=args.threads, **common_kwargs
        ))

    else:
        display_banner()
        print(f"{Fore.RED}[!] Please Specify Target. No valid mode or target specified. Use -h for help.{Style.RESET_ALL}")


if __name__ == "__main__":
    main()
