import asyncio
import logging
import json
import aiodns
from colorama import Fore, Style

from vortex.utils import display_banner


RECORD_TYPES = ['A', 'AAAA', 'MX', 'TXT', 'CNAME', 'NS', 'SOA']


def _parse_txt_record(r):
    if isinstance(r.text, list):
        parts = [t if isinstance(t, bytes) else t.encode('utf-8') for t in r.text]
        return b''.join(parts).decode('utf-8', errors='replace')
    if isinstance(r.text, bytes):
        return r.text.decode('utf-8', errors='replace')
    return str(r.text)


async def query_record(resolver, domain, record_type):
    try:
        result = await resolver.query(domain, record_type)
        records = []
        if record_type in ('A', 'AAAA'):
            records = [r.host for r in result]
        elif record_type == 'MX':
            records = [f"{r.host} (priority {r.priority})" for r in result]
        elif record_type == 'TXT':
            records = [_parse_txt_record(r) for r in result]
        elif record_type == 'CNAME':
            records = [result.cname]
        elif record_type == 'NS':
            records = [r.host for r in result]
        elif record_type == 'SOA':
            records = [f"mname={result.mname}, rname={result.rname}, serial={result.serial}"]
        return record_type, records
    except aiodns.error.DNSError as e:
        logging.debug(f"DNS query {record_type} for {domain} failed: {e}")
        return record_type, []
    except Exception as e:
        logging.debug(f"Unexpected error querying {record_type} for {domain}: {e}")
        return record_type, []


async def dns_enum(domain, output_file=None, output_format='txt'):
    display_banner()
    print(f"{Fore.CYAN}[*] DNS Record Enumeration for {domain}...{Style.RESET_ALL}\n")

    resolver = aiodns.DNSResolver()
    tasks = [query_record(resolver, domain, rt) for rt in RECORD_TYPES]
    results = await asyncio.gather(*tasks)

    all_results = {}
    for record_type, records in results:
        all_results[record_type] = records
        if records:
            print(f"{Fore.YELLOW}[{record_type}]{Style.RESET_ALL}")
            for r in records:
                print(f"  {Fore.GREEN}[✔] {r}{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}[{record_type}]{Style.RESET_ALL} {Fore.RED}No records found{Style.RESET_ALL}")

    if output_file:
        with open(output_file, 'w') as f:
            if output_format == 'json':
                json.dump({"domain": domain, "records": all_results}, f, indent=2)
            else:
                for rt, records in all_results.items():
                    f.write(f"[{rt}]\n")
                    for r in records:
                        f.write(f"  {r}\n")
                    f.write("\n")
        print(f"\n{Fore.CYAN}[✔] DNS results saved to {output_file}{Style.RESET_ALL}")

    return all_results
