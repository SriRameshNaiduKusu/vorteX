import json
import logging
import time
from datetime import datetime, timezone
from urllib.parse import urlparse

from colorama import Fore, Style


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
):
    """Run all recon modules sequentially, feeding results forward."""
    scan_start = time.monotonic()
    all_discovered_urls: set[str] = set(targets)
    all_results: dict = {}
    failed_modules: list[str] = []

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
        if wordlist:
            subdomain_wordlist = wordlist
        else:
            subdomain_wordlist, from_seclists = get_wordlist_for_size('subdomains', wordlist_size)
            if from_seclists:
                relative = _SECLISTS_FILES['subdomains'][wordlist_size]
                print(f"{Fore.CYAN}[*] Using SecLists ({wordlist_size}): {relative}{Style.RESET_ALL}")
            else:
                print(f"{Fore.CYAN}[*] No wordlist provided — using built-in default: subdomains.txt{Style.RESET_ALL}")
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

    # ── Phase 3: Active Scanning ──────────────────────────────────────────────
    _print_phase_banner("Phase 3: Active Scanning")

    fuzzed_urls: list[str] = []
    if all_discovered_urls:
        if wordlist:
            dir_wordlist = wordlist
        else:
            dir_wordlist, from_seclists = get_wordlist_for_size('directories', wordlist_size)
            if from_seclists:
                relative = _SECLISTS_FILES['directories'][wordlist_size]
                print(f"{Fore.CYAN}[*] Using SecLists ({wordlist_size}): {relative}{Style.RESET_ALL}")
            else:
                print(f"{Fore.CYAN}[*] No wordlist provided — using built-in default: directories.txt{Style.RESET_ALL}")
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
    t0 = time.monotonic()
    try:
        from vortex.crawler import crawl_domain

        await crawl_domain(url_list, depth, output_file=None, output_format=output_format, **common_kwargs)
        all_results["crawl"] = {}
        _print_phase_summary("Crawl targets processed", len(url_list), time.monotonic() - t0)
    except Exception as exc:
        logging.warning(f"Crawling failed: {exc}")
        print(f"{Fore.YELLOW}[⚠] Crawling failed: {exc}. Continuing...{Style.RESET_ALL}")
        failed_modules.append("crawl")

    # JS Discovery
    t0 = time.monotonic()
    try:
        from vortex.js_discovery import discover_js_links

        await discover_js_links(url_list, depth, output_file=None, output_format=output_format, **common_kwargs)
        all_results["js"] = {}
        _print_phase_summary("JS discovery targets", len(url_list), time.monotonic() - t0)
    except Exception as exc:
        logging.warning(f"JS discovery failed: {exc}")
        print(f"{Fore.YELLOW}[⚠] JS discovery failed: {exc}. Continuing...{Style.RESET_ALL}")
        failed_modules.append("js")

    # Email Harvesting
    email_results: list = []
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
        if wordlist:
            param_wordlist = wordlist
        else:
            param_wordlist, from_seclists = get_wordlist_for_size('parameters', wordlist_size)
            if from_seclists:
                relative = _SECLISTS_FILES['parameters'][wordlist_size]
                print(f"{Fore.CYAN}[*] Using SecLists ({wordlist_size}): {relative}{Style.RESET_ALL}")
            else:
                print(f"{Fore.CYAN}[*] No wordlist provided — using built-in default: parameters.txt{Style.RESET_ALL}")
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

    # ── Scan Summary ──────────────────────────────────────────────────────────
    scan_duration = time.monotonic() - scan_start
    _print_phase_banner("Scan Summary")

    summary = {
        "total_subdomains": len(all_results.get("subdomains", [])),
        "total_directories": len(all_results.get("fuzzing", [])),
        "total_emails": len(all_results.get("emails", [])),
        "total_technologies": tech_count,
        "scan_duration": _format_duration(scan_duration),
        "failed_modules": failed_modules,
    }

    print(f"{Fore.CYAN}  Subdomains found   : {summary['total_subdomains']}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  Directories found  : {summary['total_directories']}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  Emails found       : {summary['total_emails']}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  Technologies ID'd  : {summary['total_technologies']}{Style.RESET_ALL}")
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
