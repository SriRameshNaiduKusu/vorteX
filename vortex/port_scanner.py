import asyncio
import logging
import json
from colorama import Fore, Style

from vortex.utils import display_banner

COMMON_PORTS = [21, 22, 25, 53, 80, 110, 143, 443, 993, 995, 3306, 3389, 5432, 8080, 8443]


async def scan_port(host, port, sem, timeout=3):
    async with sem:
        try:
            conn = asyncio.open_connection(host, port)
            reader, writer = await asyncio.wait_for(conn, timeout=timeout)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return port, True
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError) as e:
            logging.debug(f"Port {port} on {host}: {e}")
            return port, False


async def port_scan(host, ports=None, port_range=None, max_threads=100,
                     output_file=None, output_format='txt', timeout=3):
    display_banner()

    if port_range:
        start, end = map(int, port_range.split('-'))
        ports = list(range(start, end + 1))
    elif ports is None:
        ports = COMMON_PORTS

    print(f"{Fore.CYAN}[*] Port scanning {host} ({len(ports)} ports)...{Style.RESET_ALL}\n")

    sem = asyncio.Semaphore(max_threads)
    tasks = [scan_port(host, port, sem, timeout=timeout) for port in ports]
    results = await asyncio.gather(*tasks)

    open_ports = [(port, open_) for port, open_ in results if open_]

    print(f"{Fore.YELLOW}[+] Open Ports:{Style.RESET_ALL}")
    if open_ports:
        for port, _ in sorted(open_ports):
            print(f"  {Fore.GREEN}[✔] {port}/tcp OPEN{Style.RESET_ALL}")
    else:
        print(f"  {Fore.RED}No open ports found.{Style.RESET_ALL}")

    scan_result = {
        "host": host,
        "open_ports": [p for p, _ in sorted(open_ports)],
        "total_scanned": len(ports),
    }

    if output_file:
        with open(output_file, 'w') as f:
            if output_format == 'json':
                json.dump(scan_result, f, indent=2)
            else:
                f.write(f"Host: {host}\n")
                f.write(f"Open ports: {', '.join(str(p) for p in scan_result['open_ports'])}\n")
        print(f"\n{Fore.CYAN}[✔] Port scan results saved to {output_file}{Style.RESET_ALL}")

    return scan_result
