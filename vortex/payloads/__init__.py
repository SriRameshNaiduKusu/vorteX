"""Helper utilities for loading bundled payload files."""

import os

_PAYLOADS_DIR = os.path.dirname(__file__)


def load_payloads(name: str) -> list[str]:
    """Load payloads from a bundled text file.

    Parameters
    ----------
    name : str
        Payload file name, e.g. ``'xss.txt'``.

    Returns
    -------
    list[str]
        Non-empty, stripped lines from the payload file.
    """
    path = os.path.join(_PAYLOADS_DIR, name)
    with open(path, encoding="utf-8") as fh:
        return [line.strip() for line in fh if line.strip()]
