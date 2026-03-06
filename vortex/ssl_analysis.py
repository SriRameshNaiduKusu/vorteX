import ssl
import socket
import json
import asyncio
import logging
from datetime import datetime, timezone
from colorama import Fore, Style

from vortex.utils import display_banner


async def ssl_check(host, port=443, output_file=None, output_format='txt'):
    display_banner()
    print(f"{Fore.CYAN}[*] SSL/TLS Analysis for {host}:{port}...{Style.RESET_ALL}\n")

    result = {
        "host": host,
        "port": port,
        "error": None,
        "subject": None,
        "issuer": None,
        "not_before": None,
        "not_after": None,
        "days_until_expiry": None,
        "tls_version": None,
        "expired": False,
        "expiry_warning": False,
    }

    try:
        ctx = ssl.create_default_context()
        loop = asyncio.get_event_loop()

        def _do_ssl():
            with socket.create_connection((host, port), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    tls_version = ssock.version()
                    return cert, tls_version

        cert, tls_version = await loop.run_in_executor(None, _do_ssl)

        subject = dict(x[0] for x in cert.get('subject', []))
        issuer = dict(x[0] for x in cert.get('issuer', []))
        not_before = cert.get('notBefore')
        not_after = cert.get('notAfter')

        result['subject'] = subject
        result['issuer'] = issuer
        result['not_before'] = not_before
        result['not_after'] = not_after
        result['tls_version'] = tls_version

        if not_after:
            expiry_dt = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z').replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)
            days_left = (expiry_dt - now).days
            result['days_until_expiry'] = days_left
            if days_left < 0:
                result['expired'] = True
            elif days_left < 30:
                result['expiry_warning'] = True

        # Print results
        print(f"  {Fore.GREEN}Subject:{Style.RESET_ALL} {subject.get('commonName', 'N/A')}")
        print(f"  {Fore.GREEN}Issuer:{Style.RESET_ALL} {issuer.get('organizationName', 'N/A')}")
        print(f"  {Fore.GREEN}Valid From:{Style.RESET_ALL} {not_before}")
        print(f"  {Fore.GREEN}Valid Until:{Style.RESET_ALL} {not_after}")
        print(f"  {Fore.GREEN}TLS Version:{Style.RESET_ALL} {tls_version}")

        if result['expired']:
            print(f"  {Fore.RED}[!] Certificate is EXPIRED!{Style.RESET_ALL}")
        elif result['expiry_warning']:
            print(f"  {Fore.YELLOW}[!] Certificate expires in {result['days_until_expiry']} days!{Style.RESET_ALL}")
        else:
            print(f"  {Fore.GREEN}[✔] Certificate valid for {result['days_until_expiry']} more days{Style.RESET_ALL}")

    except ssl.SSLError as e:
        result['error'] = f"SSL Error: {e}"
        print(f"  {Fore.RED}[!] SSL Error: {e}{Style.RESET_ALL}")
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        result['error'] = f"Connection error: {e}"
        print(f"  {Fore.RED}[!] Connection error: {e}{Style.RESET_ALL}")
    except Exception as e:
        logging.debug(f"Unexpected error in ssl_check: {e}")
        result['error'] = str(e)
        print(f"  {Fore.RED}[!] Error: {e}{Style.RESET_ALL}")

    if output_file:
        with open(output_file, 'w') as f:
            if output_format == 'json':
                json.dump(result, f, indent=2)
            else:
                for k, v in result.items():
                    f.write(f"{k}: {v}\n")
        print(f"\n{Fore.CYAN}[✔] SSL results saved to {output_file}{Style.RESET_ALL}")

    return result
