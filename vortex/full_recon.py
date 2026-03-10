import json
import logging
import time
from datetime import datetime, timezone
from urllib.parse import urlparse

from colorama import Fore, Style

from vortex.utils import _count_lines


def _print_phase_banner(title: str) -> None:
    line = "═" * 63
    print(f"\n{Fore.CYAN}{line}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  ⚡ {title}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{line}{Style.RESET_ALL}\n")


def _print_phase_summary(label: str, count: int, elapsed: float) -> None:
    print(
        f"{Fore.YELLOW}[✔] {label}: {count} result(s) "
        f"(elapsed: {elapsed:.1f}s){Style.RESET_ALL}"
    )


def _extract_host(target: str) -> str:
    parsed = urlparse(target)
    host = parsed.netloc or target
    if host.startswith("["):
        bracket_end = host.find("]")
        if bracket_end != -1:
            host = host[1:bracket_end]
    elif ":" in host:
        host = host.rsplit(":", 1)[0]
    return host


def _format_duration(seconds: float) -> str:
    m, s = divmod(int(seconds), 60)
    if m:
        return f"{m}m {s}s"
    return f"{s}s"


async def run_full_recon(
    targets,
    domain,
    wordlist,
    threads,
    output,
    depth,
    method,
    headers,
    output_format,
    proxy,
    rate_limit,
    random_ua,
    timeout,
    verbose,
    wordlist_size='small',
    fast=False,
    skip='',
    max_probe_targets=5000,
):
    """Run all recon modules sequentially, feeding results forward."""
    scan_start = time.monotonic()
    all_discovered_urls: set[str] = set(targets)
    all_results: dict = {}
    failed_modules: list[str] = []

    # Parse skip list
    skip_modules: set[str] = {s.strip().lower() for s in skip.split(",") if s.strip()}

    common_kwargs = dict(
        proxy=proxy,
        timeout=timeout,
        random_ua=random_ua,
        rate_limit=rate_limit,
    )

    # ── Phase 1: Reconnaissance & Discovery ──────────────────────────────────
    _print_phase_banner("Phase 1: Reconnaissance & Discovery")

    # DNS Records
    if domain:
        if "dns" in skip_modules:
            print(f"{Fore.CYAN}[ℹ] Skipping DNS enumeration (--skip){Style.RESET_ALL}")
        else:
            t0 = time.monotonic()
            try:
                from vortex.dns_records import dns_enum

                dns_results = await dns_enum(domain, output_file=None, output_format=output_format)
                all_results["dns"] = dns_results
                total_dns = sum(len(v) for v in dns_results.values())
                _print_phase_summary("DNS records", total_dns, time.monotonic() - t0)
            except Exception as exc:
                logging.warning(f"DNS enumeration failed: {exc}")
                print(f"{Fore.YELLOW}[⚠] DNS enumeration failed: {exc}. Continuing...{Style.RESET_ALL}")
                failed_modules.append("dns")

    # SSL/TLS
    if "ssl" in skip_modules:
        print(f"{Fore.CYAN}[ℹ] Skipping SSL/TLS check (--skip){Style.RESET_ALL}")
    else:
        for target in targets:
            t0 = time.monotonic()
            host = _extract_host(target)
            port = 443
            raw_netloc = urlparse(target).netloc or target
            if raw_netloc.startswith("["):
                bracket_end = raw_netloc.find("]")
                if bracket_end != -1 and bracket_end + 1 < len(raw_netloc) and raw_netloc[bracket_end + 1] == ":":
                    port = int(raw_netloc[bracket_end + 2:])
                    host = raw_netloc[1:bracket_end]
            elif ":" in raw_netloc:
                try:
                    host, port_str = raw_netloc.rsplit(":", 1)
                    port = int(port_str)
                except ValueError:
                    pass
            try:
                from vortex.ssl_analysis import ssl_check

                ssl_results = await ssl_check(host, port=port, output_file=None, output_format=output_format)
                all_results["ssl"] = ssl_results
                _print_phase_summary("SSL/TLS check", 1, time.monotonic() - t0)
            except Exception as exc:
                logging.warning(f"SSL check failed for {host}: {exc}")
                print(f"{Fore.YELLOW}[⚠] SSL check failed: {exc}. Continuing...{Style.RESET_ALL}")
                failed_modules.append("ssl")

    # Port Scanning
    if "ports" in skip_modules:
        print(f"{Fore.CYAN}[ℹ] Skipping port scanning (--skip){Style.RESET_ALL}")
    else:
        for target in targets:
            t0 = time.monotonic()
            host = _extract_host(target)
            try:
                from vortex.port_scanner import port_scan

                port_results = await port_scan(
                    host,
                    max_threads=threads,
                    output_file=None,
                    output_format=output_format,
                    timeout=timeout,
                )
                all_results["ports"] = port_results
                open_count = len(port_results.get("open_ports", []))
                _print_phase_summary("Open ports", open_count, time.monotonic() - t0)
            except Exception as exc:
                logging.warning(f"Port scan failed for {host}: {exc}")
                print(f"{Fore.YELLOW}[⚠] Port scan failed: {exc}. Continuing...{Style.RESET_ALL}")
                failed_modules.append("ports")

    # ── Phase 2: Subdomain & Surface Expansion ────────────────────────────────
    _print_phase_banner("Phase 2: Subdomain & Surface Expansion")

    from vortex.wordlists import get_wordlist_for_size, _SECLISTS_FILES

    found_subdomains: list[str] = []
    if domain:
        if "subdomains" in skip_modules:
            print(f"{Fore.CYAN}[ℹ] Skipping subdomain enumeration (--skip){Style.RESET_ALL}")
        else:
            if wordlist:
                subdomain_wordlist = wordlist
            else:
                subdomain_wordlist, from_seclists = get_wordlist_for_size('subdomains', wordlist_size)
                count = _count_lines(subdomain_wordlist)
                if from_seclists:
                    relative = _SECLISTS_FILES['subdomains'][wordlist_size]
                    print(f"{Fore.CYAN}[*] Using SecLists ({wordlist_size}): {relative} ({count} entries){Style.RESET_ALL}")
                else:
                    print(f"{Fore.CYAN}[*] SecLists not found. Using built-in wordlist: subdomains.txt ({count} entries){Style.RESET_ALL}")
            t0 = time.monotonic()
            try:
                from vortex.subdomain import enumerate_subdomains

                found_subdomains = await enumerate_subdomains(
                    domain,
                    subdomain_wordlist,
                    threads,
                    output_file=None,
                    output_format=output_format,
                    **common_kwargs,
                )
                all_discovered_urls.update(found_subdomains)
                all_results["subdomains"] = found_subdomains
                _print_phase_summary("Subdomains found", len(found_subdomains), time.monotonic() - t0)
            except Exception as exc:
                logging.warning(f"Subdomain enumeration failed: {exc}")
                print(f"{Fore.YELLOW}[⚠] Subdomain enumeration failed: {exc}. Continuing...{Style.RESET_ALL}")
                failed_modules.append("subdomains")
    else:
        print(f"{Fore.YELLOW}[ℹ] No domain provided — skipping subdomain enumeration.{Style.RESET_ALL}")

    # ── Phase 2.5: HTTP Probing (Liveness Check) ──────────────────────────────
    _print_phase_banner("Phase 2.5: HTTP Probing (Liveness Check)")

    if found_subdomains:
        if "probe" in skip_modules:
            print(f"{Fore.CYAN}[ℹ] Skipping HTTP probing (--skip){Style.RESET_ALL}")
        else:
            t0 = time.monotonic()
            try:
                from vortex.http_probe import probe_alive

                live_targets = await probe_alive(
                    found_subdomains,
                    max_threads=threads,
                    timeout=min(timeout, 5.0),
                    proxy=proxy,
                    random_ua=random_ua,
                    max_targets=max_probe_targets,
                )
                # Replace discovered URLs with only live targets + original targets
                all_discovered_urls = set(targets) | set(live_targets)
                all_results["probe"] = {
                    "total_probed": len(found_subdomains),
                    "alive": len(live_targets),
                    "filtered": len(found_subdomains) - len(live_targets),
                }
                _print_phase_summary("Live hosts", len(live_targets), time.monotonic() - t0)
            except Exception as exc:
                logging.warning(f"HTTP probing failed: {exc}")
                print(f"{Fore.YELLOW}[⚠] HTTP probing failed: {exc}. Using all subdomains...{Style.RESET_ALL}")
                failed_modules.append("probe")
    else:
        print(f"{Fore.YELLOW}[ℹ] No subdomains found — skipping HTTP probing.{Style.RESET_ALL}")

    # ── Phase 3: Active Scanning ──────────────────────────────────────────────
    _print_phase_banner("Phase 3: Active Scanning")

    fuzzed_urls: list[str] = []
    if all_discovered_urls:
        if "fuzzing" in skip_modules:
            print(f"{Fore.CYAN}[ℹ] Skipping directory fuzzing (--skip){Style.RESET_ALL}")
        else:
            if wordlist:
                dir_wordlist = wordlist
            else:
                dir_wordlist, from_seclists = get_wordlist_for_size('directories', wordlist_size)
                count = _count_lines(dir_wordlist)
                if from_seclists:
                    relative = _SECLISTS_FILES['directories'][wordlist_size]
                    print(f"{Fore.CYAN}[*] Using SecLists ({wordlist_size}): {relative} ({count} entries){Style.RESET_ALL}")
                else:
                    print(f"{Fore.CYAN}[*] SecLists not found. Using built-in wordlist: directories.txt ({count} entries){Style.RESET_ALL}")
            t0 = time.monotonic()
            try:
                from vortex.fuzzer import directory_fuzzing

                fuzzed_urls = await directory_fuzzing(
                    list(all_discovered_urls),
                    dir_wordlist,
                    threads,
                    output_file=None,
                    output_format=output_format,
                    **common_kwargs,
                )
                all_discovered_urls.update(fuzzed_urls)
                all_results["fuzzing"] = fuzzed_urls
                _print_phase_summary("Fuzzed URLs found", len(fuzzed_urls), time.monotonic() - t0)
            except Exception as exc:
                logging.warning(f"Directory fuzzing failed: {exc}")
                print(f"{Fore.YELLOW}[⚠] Directory fuzzing failed: {exc}. Continuing...{Style.RESET_ALL}")
                failed_modules.append("fuzzing")

    # Technology Fingerprinting
    tech_count = 0
    if "tech" in skip_modules:
        print(f"{Fore.CYAN}[ℹ] Skipping technology fingerprinting (--skip){Style.RESET_ALL}")
    else:
        t0 = time.monotonic()
        try:
            from vortex.tech_fingerprinting import fingerprint_technologies

            tech_results = await fingerprint_technologies(
                list(all_discovered_urls),
                output_file=None,
                output_format=output_format,
                max_threads=threads,
                **common_kwargs,
            )
            all_results["tech"] = tech_results
            tech_count = sum(
                1 for v in tech_results.values() if v and v != ["No identifiable technologies detected"]
            )
            _print_phase_summary("URLs fingerprinted", len(tech_results), time.monotonic() - t0)
        except Exception as exc:
            logging.warning(f"Technology fingerprinting failed: {exc}")
            print(f"{Fore.YELLOW}[⚠] Technology fingerprinting failed: {exc}. Continuing...{Style.RESET_ALL}")
            failed_modules.append("tech")

    # ── Phase 4: Deep Analysis ────────────────────────────────────────────────
    _print_phase_banner("Phase 4: Deep Analysis")

    url_list = list(all_discovered_urls)

    # Crawling
    if "crawl" in skip_modules:
        print(f"{Fore.CYAN}[ℹ] Skipping web crawling (--skip){Style.RESET_ALL}")
    else:
        t0 = time.monotonic()
        try:
            from vortex.crawler import crawl_domain

            await crawl_domain(url_list, depth, output_file=None, output_format=output_format, max_threads=threads, **common_kwargs)
            all_results["crawl"] = {}
            _print_phase_summary("Crawl targets processed", len(url_list), time.monotonic() - t0)
        except Exception as exc:
            logging.warning(f"Crawling failed: {exc}")
            print(f"{Fore.YELLOW}[⚠] Crawling failed: {exc}. Continuing...{Style.RESET_ALL}")
            failed_modules.append("crawl")

    # JS Discovery
    if "js" in skip_modules:
        print(f"{Fore.CYAN}[ℹ] Skipping JS discovery (--skip){Style.RESET_ALL}")
    else:
        t0 = time.monotonic()
        try:
            from vortex.js_discovery import discover_js_links

            await discover_js_links(url_list, depth, output_file=None, output_format=output_format, max_threads=threads, **common_kwargs)
            all_results["js"] = {}
            _print_phase_summary("JS discovery targets", len(url_list), time.monotonic() - t0)
        except Exception as exc:
            logging.warning(f"JS discovery failed: {exc}")
            print(f"{Fore.YELLOW}[⚠] JS discovery failed: {exc}. Continuing...{Style.RESET_ALL}")
            failed_modules.append("js")

    # Email Harvesting
    email_results: list = []
    if "emails" in skip_modules:
        print(f"{Fore.CYAN}[ℹ] Skipping email harvesting (--skip){Style.RESET_ALL}")
    else:
        t0 = time.monotonic()
        try:
            from vortex.email_harvester import harvest_emails

            email_results = await harvest_emails(
                url_list, depth=depth, output_file=None, output_format=output_format, **common_kwargs
            )
            all_results["emails"] = email_results
            _print_phase_summary("Emails harvested", len(email_results), time.monotonic() - t0)
        except Exception as exc:
            logging.warning(f"Email harvesting failed: {exc}")
            print(f"{Fore.YELLOW}[⚠] Email harvesting failed: {exc}. Continuing...{Style.RESET_ALL}")
            failed_modules.append("emails")

    # ── Phase 5: Parameter Analysis ───────────────────────────────────────────
    _print_phase_banner("Phase 5: Parameter Analysis")

    if url_list:
        if "params" in skip_modules:
            print(f"{Fore.CYAN}[ℹ] Skipping parameter fuzzing (--skip){Style.RESET_ALL}")
        else:
            if wordlist:
                param_wordlist = wordlist
            else:
                param_wordlist, from_seclists = get_wordlist_for_size('parameters', wordlist_size)
                count = _count_lines(param_wordlist)
                if from_seclists:
                    relative = _SECLISTS_FILES['parameters'][wordlist_size]
                    print(f"{Fore.CYAN}[*] Using SecLists ({wordlist_size}): {relative} ({count} entries){Style.RESET_ALL}")
                else:
                    print(f"{Fore.CYAN}[*] SecLists not found. Using built-in wordlist: parameters.txt ({count} entries){Style.RESET_ALL}")
            t0 = time.monotonic()
            try:
                from vortex.param_fuzzer import parameter_discovery

                param_results: dict = await parameter_discovery(
                    url_list[0],
                    method,
                    headers,
                    param_wordlist,
                    output_file=None,
                    output_format=output_format,
                    max_threads=threads,
                    **common_kwargs,
                ) or {}
                all_results["params"] = param_results
                _print_phase_summary("Parameters discovered", len(param_results), time.monotonic() - t0)
            except Exception as exc:
                logging.warning(f"Parameter fuzzing failed: {exc}")
                print(f"{Fore.YELLOW}[⚠] Parameter fuzzing failed: {exc}. Continuing...{Style.RESET_ALL}")
                failed_modules.append("params")
    else:
        print(f"{Fore.YELLOW}[ℹ] No targets available — skipping parameter fuzzing.{Style.RESET_ALL}")

    # ── Phase 6: Passive Recon (CT Logs & Wayback) ────────────────────────────
    _print_phase_banner("Phase 6: Passive Recon (CT Logs & Wayback)")

    if domain:
        # Certificate Transparency log mining
        if "ct" in skip_modules:
            print(f"{Fore.CYAN}[ℹ] Skipping CT log mining (--skip){Style.RESET_ALL}")
        else:
            t0 = time.monotonic()
            try:
                from vortex.ct_enum import ct_search

                ct_subdomains = await ct_search(
                    domain,
                    output_file=None,
                    output_format=output_format,
                    **common_kwargs,
                )
                all_results["ct_subdomains"] = ct_subdomains
                if ct_subdomains and "probe" not in skip_modules:
                    try:
                        from vortex.http_probe import probe_alive

                        ct_live = await probe_alive(
                            ct_subdomains,
                            max_threads=threads,
                            timeout=min(timeout, 5.0),
                            proxy=proxy,
                            random_ua=random_ua,
                            max_targets=max_probe_targets,
                        )
                        all_discovered_urls.update(ct_live)
                    except Exception as exc:
                        logging.warning(f"CT log HTTP probing failed: {exc}")
                        all_discovered_urls.update(f"https://{s}" for s in ct_subdomains)
                else:
                    all_discovered_urls.update(f"https://{s}" for s in ct_subdomains)
                _print_phase_summary("CT log subdomains", len(ct_subdomains), time.monotonic() - t0)
            except Exception as exc:
                logging.warning(f"CT log mining failed: {exc}")
                print(f"{Fore.YELLOW}[⚠] CT log mining failed: {exc}. Continuing...{Style.RESET_ALL}")
                failed_modules.append("ct")

        # Wayback Machine URL mining
        if "wayback" in skip_modules:
            print(f"{Fore.CYAN}[ℹ] Skipping Wayback Machine mining (--skip){Style.RESET_ALL}")
        else:
            t0 = time.monotonic()
            try:
                from vortex.wayback import wayback_enum

                wayback_urls = await wayback_enum(
                    domain,
                    output_file=None,
                    output_format=output_format,
                    **common_kwargs,
                )
                all_results["wayback_urls"] = wayback_urls
                _print_phase_summary("Wayback URLs", len(wayback_urls), time.monotonic() - t0)
            except Exception as exc:
                logging.warning(f"Wayback mining failed: {exc}")
                print(f"{Fore.YELLOW}[⚠] Wayback mining failed: {exc}. Continuing...{Style.RESET_ALL}")
                failed_modules.append("wayback")
    else:
        print(f"{Fore.YELLOW}[ℹ] No domain provided — skipping CT log and Wayback mining.{Style.RESET_ALL}")

    # ── Phase 7: Vulnerability Scanning ──────────────────────────────────────
    _print_phase_banner("Phase 7: Vulnerability Scanning")

    active_url_list = list(all_discovered_urls)

    # Emit a scale warning for large URL sets before running slow modules
    _LARGE_SCAN_THRESHOLD = 500
    if len(active_url_list) >= _LARGE_SCAN_THRESHOLD:
        from vortex.open_redirect import REDIRECT_PARAMS, REDIRECT_PAYLOADS, REDIRECT_PARAMS_FAST, REDIRECT_PAYLOADS_FAST
        if fast:
            estimated_redirect = len(active_url_list) * len(REDIRECT_PARAMS_FAST) * len(REDIRECT_PAYLOADS_FAST)
        else:
            estimated_redirect = len(active_url_list) * len(REDIRECT_PARAMS) * len(REDIRECT_PAYLOADS)
        print(
            f"{Fore.CYAN}[ℹ] Large scan detected: {len(active_url_list)} URLs discovered. "
            f"Estimated open redirect checks: ~{estimated_redirect:,} requests.{Style.RESET_ALL}"
        )
        print(
            f"{Fore.CYAN}[ℹ] Tip: Use --fast for quicker scans, or --skip redirect to skip slow modules.{Style.RESET_ALL}"
        )

    # Subdomain takeover
    if found_subdomains:
        if "takeover" in skip_modules:
            print(f"{Fore.CYAN}[ℹ] Skipping subdomain takeover detection (--skip){Style.RESET_ALL}")
        else:
            t0 = time.monotonic()
            try:
                from vortex.takeover import check_takeover

                takeover_findings = await check_takeover(
                    found_subdomains,
                    output_file=None,
                    output_format=output_format,
                    **common_kwargs,
                )
                all_results["takeover"] = takeover_findings
                _print_phase_summary("Takeover findings", len(takeover_findings), time.monotonic() - t0)
            except Exception as exc:
                logging.warning(f"Takeover scan failed: {exc}")
                print(f"{Fore.YELLOW}[⚠] Takeover scan failed: {exc}. Continuing...{Style.RESET_ALL}")
                failed_modules.append("takeover")

    # CORS scan
    if active_url_list:
        if "cors" in skip_modules:
            print(f"{Fore.CYAN}[ℹ] Skipping CORS scan (--skip){Style.RESET_ALL}")
        else:
            t0 = time.monotonic()
            try:
                from vortex.cors_scanner import check_cors

                cors_findings = await check_cors(
                    active_url_list,
                    output_file=None,
                    output_format=output_format,
                    fast=fast,
                    **common_kwargs,
                )
                all_results["cors"] = cors_findings
                _print_phase_summary("CORS findings", len(cors_findings), time.monotonic() - t0)
            except Exception as exc:
                logging.warning(f"CORS scan failed: {exc}")
                print(f"{Fore.YELLOW}[⚠] CORS scan failed: {exc}. Continuing...{Style.RESET_ALL}")
                failed_modules.append("cors")

    # Sensitive file detection
    if active_url_list:
        if "sensitive" in skip_modules:
            print(f"{Fore.CYAN}[ℹ] Skipping sensitive file detection (--skip){Style.RESET_ALL}")
        else:
            t0 = time.monotonic()
            try:
                from vortex.sensitive_files import scan_sensitive_files

                sensitive_findings = await scan_sensitive_files(
                    active_url_list,
                    output_file=None,
                    output_format=output_format,
                    fast=fast,
                    **common_kwargs,
                )
                all_results["sensitive"] = sensitive_findings
                _print_phase_summary("Sensitive files", len(sensitive_findings), time.monotonic() - t0)
            except Exception as exc:
                logging.warning(f"Sensitive file scan failed: {exc}")
                print(f"{Fore.YELLOW}[⚠] Sensitive file scan failed: {exc}. Continuing...{Style.RESET_ALL}")
                failed_modules.append("sensitive")

    # Security header audit
    if active_url_list:
        if "headers" in skip_modules:
            print(f"{Fore.CYAN}[ℹ] Skipping security header audit (--skip){Style.RESET_ALL}")
        else:
            t0 = time.monotonic()
            try:
                from vortex.header_audit import audit_headers

                header_results = await audit_headers(
                    active_url_list,
                    output_file=None,
                    output_format=output_format,
                    **common_kwargs,
                )
                all_results["headers"] = header_results
                _print_phase_summary("Header audits", len(header_results), time.monotonic() - t0)
            except Exception as exc:
                logging.warning(f"Header audit failed: {exc}")
                print(f"{Fore.YELLOW}[⚠] Header audit failed: {exc}. Continuing...{Style.RESET_ALL}")
                failed_modules.append("headers")

    # Open redirect detection
    if active_url_list:
        if "redirect" in skip_modules:
            print(f"{Fore.CYAN}[ℹ] Skipping open redirect detection (--skip){Style.RESET_ALL}")
        else:
            t0 = time.monotonic()
            try:
                from vortex.open_redirect import check_open_redirect

                redirect_findings = await check_open_redirect(
                    active_url_list,
                    output_file=None,
                    output_format=output_format,
                    fast=fast,
                    **common_kwargs,
                )
                all_results["redirects"] = redirect_findings
                _print_phase_summary("Open redirect findings", len(redirect_findings), time.monotonic() - t0)
            except Exception as exc:
                logging.warning(f"Open redirect scan failed: {exc}")
                print(f"{Fore.YELLOW}[⚠] Open redirect scan failed: {exc}. Continuing...{Style.RESET_ALL}")
                failed_modules.append("redirects")

    # API endpoint discovery
    if active_url_list:
        if "api" in skip_modules:
            print(f"{Fore.CYAN}[ℹ] Skipping API endpoint discovery (--skip){Style.RESET_ALL}")
        else:
            t0 = time.monotonic()
            try:
                from vortex.api_discovery import discover_api_endpoints

                api_results = await discover_api_endpoints(
                    active_url_list,
                    output_file=None,
                    output_format=output_format,
                    **common_kwargs,
                )
                all_results["api"] = api_results
                api_count = len(api_results.get("found_endpoints", []))
                _print_phase_summary("API endpoints found", api_count, time.monotonic() - t0)
            except Exception as exc:
                logging.warning(f"API discovery failed: {exc}")
                print(f"{Fore.YELLOW}[⚠] API discovery failed: {exc}. Continuing...{Style.RESET_ALL}")
                failed_modules.append("api")

    # ── Phase 8: Advanced Vulnerability Scanning ──────────────────────────────
    _print_phase_banner("Phase 8: Advanced Vulnerability Scanning")

    # WAF detection (run first so results can inform other modules)
    if active_url_list:
        if "waf" in skip_modules:
            print(f"{Fore.CYAN}[ℹ] Skipping WAF detection (--skip){Style.RESET_ALL}")
        else:
            t0 = time.monotonic()
            try:
                from vortex.waf_detector import detect_waf

                waf_results = await detect_waf(
                    active_url_list,
                    output_file=None,
                    output_format=output_format,
                    **common_kwargs,
                )
                all_results["waf"] = waf_results
                waf_count = sum(1 for r in waf_results if r.get("waf_detected"))
                _print_phase_summary("WAFs detected", waf_count, time.monotonic() - t0)
            except Exception as exc:
                logging.warning(f"WAF detection failed: {exc}")
                print(f"{Fore.YELLOW}[⚠] WAF detection failed: {exc}. Continuing...{Style.RESET_ALL}")
                failed_modules.append("waf")

    # XSS scanning
    if active_url_list:
        if "xss" in skip_modules:
            print(f"{Fore.CYAN}[ℹ] Skipping XSS scan (--skip){Style.RESET_ALL}")
        else:
            t0 = time.monotonic()
            try:
                from vortex.xss_scanner import scan_xss

                xss_findings = await scan_xss(
                    active_url_list,
                    output_file=None,
                    output_format=output_format,
                    fast=fast,
                    **common_kwargs,
                )
                all_results["xss"] = xss_findings
                _print_phase_summary("XSS findings", len(xss_findings), time.monotonic() - t0)
            except Exception as exc:
                logging.warning(f"XSS scan failed: {exc}")
                print(f"{Fore.YELLOW}[⚠] XSS scan failed: {exc}. Continuing...{Style.RESET_ALL}")
                failed_modules.append("xss")

    # SQL injection scanning
    if active_url_list:
        if "sqli" in skip_modules:
            print(f"{Fore.CYAN}[ℹ] Skipping SQLi scan (--skip){Style.RESET_ALL}")
        else:
            t0 = time.monotonic()
            try:
                from vortex.sqli_scanner import scan_sqli

                sqli_findings = await scan_sqli(
                    active_url_list,
                    output_file=None,
                    output_format=output_format,
                    fast=fast,
                    **common_kwargs,
                )
                all_results["sqli"] = sqli_findings
                _print_phase_summary("SQLi findings", len(sqli_findings), time.monotonic() - t0)
            except Exception as exc:
                logging.warning(f"SQLi scan failed: {exc}")
                print(f"{Fore.YELLOW}[⚠] SQLi scan failed: {exc}. Continuing...{Style.RESET_ALL}")
                failed_modules.append("sqli")

    # SSRF scanning
    if active_url_list:
        if "ssrf" in skip_modules:
            print(f"{Fore.CYAN}[ℹ] Skipping SSRF scan (--skip){Style.RESET_ALL}")
        else:
            t0 = time.monotonic()
            try:
                from vortex.ssrf_scanner import scan_ssrf

                ssrf_findings = await scan_ssrf(
                    active_url_list,
                    output_file=None,
                    output_format=output_format,
                    fast=fast,
                    **common_kwargs,
                )
                all_results["ssrf"] = ssrf_findings
                _print_phase_summary("SSRF findings", len(ssrf_findings), time.monotonic() - t0)
            except Exception as exc:
                logging.warning(f"SSRF scan failed: {exc}")
                print(f"{Fore.YELLOW}[⚠] SSRF scan failed: {exc}. Continuing...{Style.RESET_ALL}")
                failed_modules.append("ssrf")

    # LFI scanning
    if active_url_list:
        if "lfi" in skip_modules:
            print(f"{Fore.CYAN}[ℹ] Skipping LFI scan (--skip){Style.RESET_ALL}")
        else:
            t0 = time.monotonic()
            try:
                from vortex.lfi_scanner import scan_lfi

                lfi_findings = await scan_lfi(
                    active_url_list,
                    output_file=None,
                    output_format=output_format,
                    fast=fast,
                    **common_kwargs,
                )
                all_results["lfi"] = lfi_findings
                _print_phase_summary("LFI findings", len(lfi_findings), time.monotonic() - t0)
            except Exception as exc:
                logging.warning(f"LFI scan failed: {exc}")
                print(f"{Fore.YELLOW}[⚠] LFI scan failed: {exc}. Continuing...{Style.RESET_ALL}")
                failed_modules.append("lfi")

    # ── Scan Summary ──────────────────────────────────────────────────────────
    scan_duration = time.monotonic() - scan_start
    _print_phase_banner("Scan Summary")

    summary = {
        "total_subdomains": len(all_results.get("subdomains", [])),
        "probed_alive": all_results.get("probe", {}).get("alive", 0),
        "probed_filtered": all_results.get("probe", {}).get("filtered", 0),
        "total_directories": len(all_results.get("fuzzing", [])),
        "total_emails": len(all_results.get("emails", [])),
        "total_technologies": tech_count,
        "ct_subdomains": len(all_results.get("ct_subdomains", [])),
        "wayback_urls": len(all_results.get("wayback_urls", [])),
        "takeover_findings": len(all_results.get("takeover", [])),
        "cors_findings": len(all_results.get("cors", [])),
        "sensitive_findings": len(all_results.get("sensitive", [])),
        "header_audits": len(all_results.get("headers", [])),
        "redirect_findings": len(all_results.get("redirects", [])),
        "api_endpoints": len((all_results.get("api") or {}).get("found_endpoints", [])),
        "waf_detections": sum(1 for r in all_results.get("waf", []) if r.get("waf_detected")),
        "xss_findings": len(all_results.get("xss", [])),
        "sqli_findings": len(all_results.get("sqli", [])),
        "ssrf_findings": len(all_results.get("ssrf", [])),
        "lfi_findings": len(all_results.get("lfi", [])),
        "scan_duration": _format_duration(scan_duration),
        "failed_modules": failed_modules,
    }

    print(f"{Fore.CYAN}  Subdomains found   : {summary['total_subdomains']}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  Live hosts (probed): {summary['probed_alive']}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  CT log subdomains  : {summary['ct_subdomains']}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  Wayback URLs       : {summary['wayback_urls']}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  Directories found  : {summary['total_directories']}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  Emails found       : {summary['total_emails']}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  Technologies ID'd  : {summary['total_technologies']}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  Takeover findings  : {summary['takeover_findings']}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  CORS findings      : {summary['cors_findings']}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  Sensitive files    : {summary['sensitive_findings']}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  Header audits      : {summary['header_audits']}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  Open redirects     : {summary['redirect_findings']}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  API endpoints      : {summary['api_endpoints']}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  WAFs detected      : {summary['waf_detections']}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  XSS findings       : {summary['xss_findings']}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  SQLi findings      : {summary['sqli_findings']}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  SSRF findings      : {summary['ssrf_findings']}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  LFI findings       : {summary['lfi_findings']}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  Scan duration      : {summary['scan_duration']}{Style.RESET_ALL}")
    if failed_modules:
        print(f"{Fore.YELLOW}  Failed modules     : {', '.join(failed_modules)}{Style.RESET_ALL}")
    else:
        print(f"{Fore.GREEN}  All modules completed successfully.{Style.RESET_ALL}")

    # ── Consolidated Report ───────────────────────────────────────────────────
    if output:
        report = {
            "target": domain or (targets[0] if targets else ""),
            "scan_date": datetime.now(timezone.utc).isoformat(),
            "phases": {
                "dns": all_results.get("dns", {}),
                "ssl": all_results.get("ssl", {}),
                "ports": all_results.get("ports", {}),
                "subdomains": all_results.get("subdomains", []),
                "probe": all_results.get("probe", {}),
                "ct_subdomains": all_results.get("ct_subdomains", []),
                "wayback_urls": all_results.get("wayback_urls", []),
                "fuzzing": all_results.get("fuzzing", []),
                "tech_fingerprint": {
                    url: techs
                    for url, techs in (all_results.get("tech") or {}).items()
                },
                "crawled_links": list(all_results.get("crawl", {}).values()),
                "js_files": list((all_results.get("js") or {}).get("js_files", [])),
                "js_endpoints": list((all_results.get("js") or {}).get("endpoints", [])),
                "emails": all_results.get("emails", []),
                "parameters": all_results.get("params", {}),
                "takeover": all_results.get("takeover", []),
                "cors": all_results.get("cors", []),
                "sensitive": all_results.get("sensitive", []),
                "headers": all_results.get("headers", []),
                "redirects": all_results.get("redirects", []),
                "api": all_results.get("api", {}),
                "waf": all_results.get("waf", []),
                "xss": all_results.get("xss", []),
                "sqli": all_results.get("sqli", []),
                "ssrf": all_results.get("ssrf", []),
                "lfi": all_results.get("lfi", []),
            },
            "summary": summary,
        }

        with open(output, "w", encoding="utf-8") as fh:
            if output_format == "json":
                json.dump(report, fh, indent=2, default=str)
            else:
                fh.write("vorteX Full Recon Report\n")
                fh.write(f"Target : {report['target']}\n")
                fh.write(f"Date   : {report['scan_date']}\n\n")
                for section, data in report["phases"].items():
                    fh.write(f"[{section.upper()}]\n")
                    fh.write(f"{data}\n\n")
                fh.write("[SUMMARY]\n")
                for k, v in summary.items():
                    fh.write(f"  {k}: {v}\n")
        print(f"\n{Fore.CYAN}[✔] Full recon report saved to {output}{Style.RESET_ALL}")

    return all_results
