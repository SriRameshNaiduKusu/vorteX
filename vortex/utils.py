import threading
import time
import sys
import signal
from pyfiglet import figlet_format
from colorama import Fore, Style, init
import logging

init(autoreset=True)

stop_event = threading.Event()

VERSION = "2.0.0"


def signal_handler(sig, frame):
    if not stop_event.is_set():
        print("\n[!] Scan interrupted. Exiting...\n")
        stop_event.set()
        time.sleep(0.5)
        sys.exit(0)


signal.signal(signal.SIGINT, signal_handler)


def display_banner():
    print(Fore.RED + figlet_format("vorteX", font="slant") + Style.RESET_ALL)
    print(f"{Fore.MAGENTA}[✔] vorteX v{VERSION} - The Advanced Recon Tool{Style.RESET_ALL}\n")


def setup_logging(verbose: bool = False):
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(level=level, format="%(asctime)s [%(levelname)s] %(message)s")


def build_session_kwargs(proxy=None, timeout=10, random_ua=False, headers=None):
    """Return kwargs for aiohttp.ClientSession requests."""
    import random
    from vortex.user_agents import USER_AGENTS
    kwargs = {}
    if proxy:
        kwargs['proxy'] = proxy
    if random_ua:
        kwargs['headers'] = {'User-Agent': random.choice(USER_AGENTS)}
    if headers:
        kwargs.setdefault('headers', {}).update(headers)
    return kwargs
