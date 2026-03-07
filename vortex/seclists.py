"""SecLists auto-detection helpers.

This module provides a lightweight public interface for finding a local
SecLists installation and resolving per-module wordlist paths.  It
delegates to the richer ``vortex.wordlists`` implementation so that
detection logic is kept in a single place.
"""

from vortex.wordlists import SecListsProvider, _SECLISTS_FILES, get_wordlist_for_size

# Re-export the singleton provider for convenience
_provider = SecListsProvider()


def find_seclists():
    """Return the SecLists base directory path, or ``None`` if not found.

    Searches (in order):
    1. The ``SECLISTS_PATH`` environment variable.
    2. ``/usr/share/seclists/``
    3. ``/usr/share/SecLists/``
    4. ``/opt/seclists/``
    5. ``~/SecLists/``
    """
    return _provider.base_path


def get_seclists_wordlist(category, size="small"):
    """Return the absolute path to a SecLists wordlist for *category*.

    Parameters
    ----------
    category : str
        One of ``'subdomains'``, ``'directories'``, or ``'parameters'``.
    size : str
        One of ``'small'`` (default), ``'medium'``, or ``'large'``.

    Returns
    -------
    str or None
        Absolute path to the wordlist file, or ``None`` when SecLists is
        not installed or the specific file is missing.
    """
    return _provider.get_path(category, size)


__all__ = [
    "find_seclists",
    "get_seclists_wordlist",
    "get_wordlist_for_size",
    "_SECLISTS_FILES",
]
