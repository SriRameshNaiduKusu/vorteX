"""Proxy rotation manager.

Loads a list of proxy URLs from a file and provides round-robin rotation
across requests. Integrates with any module that accepts a ``proxy`` kwarg.
"""

import itertools
import logging


class ProxyManager:
    """Round-robin proxy rotator loaded from a file.

    Parameters
    ----------
    proxy_file : str
        Path to a file containing proxy URLs, one per line.
        Lines starting with ``#`` and blank lines are ignored.

    Example
    -------
    ::

        pm = ProxyManager("proxies.txt")
        proxy = pm.next()   # returns the next proxy URL in rotation
    """

    def __init__(self, proxy_file: str) -> None:
        self._proxies = self._load(proxy_file)
        if not self._proxies:
            raise ValueError(f"No valid proxies found in {proxy_file!r}")
        self._cycle = itertools.cycle(self._proxies)

    @staticmethod
    def _load(path: str) -> list[str]:
        proxies = []
        try:
            with open(path, encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    proxies.append(line)
        except OSError as exc:
            logging.warning(f"Could not load proxy file {path!r}: {exc}")
        return proxies

    def next(self) -> str:
        """Return the next proxy URL in rotation."""
        return next(self._cycle)

    def __len__(self) -> int:
        return len(self._proxies)

    def __repr__(self) -> str:
        return f"ProxyManager({len(self._proxies)} proxies)"
