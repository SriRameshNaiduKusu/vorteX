import os

WORDLIST_DIR = os.path.dirname(os.path.abspath(__file__))

_BUNDLED_SUBDOMAINS = os.path.join(WORDLIST_DIR, 'subdomains.txt')
_BUNDLED_DIRECTORIES = os.path.join(WORDLIST_DIR, 'directories.txt')
_BUNDLED_PARAMETERS = os.path.join(WORDLIST_DIR, 'parameters.txt')

# SecLists relative paths for each size tier
_SECLISTS_FILES = {
    'subdomains': {
        'small':  'Discovery/DNS/subdomains-top1million-5000.txt',
        'medium': 'Discovery/DNS/subdomains-top1million-20000.txt',
        'large':  'Discovery/DNS/subdomains-top1million-110000.txt',
    },
    'directories': {
        'small':  'Discovery/Web-Content/common.txt',
        'medium': 'Discovery/Web-Content/raft-medium-directories.txt',
        'large':  'Discovery/Web-Content/directory-list-2.3-medium.txt',
    },
    'parameters': {
        'small':  'Discovery/Web-Content/burp-parameter-names.txt',
        'medium': 'Discovery/Web-Content/burp-parameter-names.txt',
        'large':  'Discovery/Web-Content/burp-parameter-names.txt',
    },
}

# Search order for SecLists installation paths.
# Both lowercase and capitalised variants are intentional for case-sensitive Linux filesystems.
_SECLISTS_SEARCH_PATHS = [
    '/usr/share/seclists',
    '/usr/share/SecLists',
    '/opt/seclists',
    os.path.expanduser('~/SecLists'),
]


class SecListsProvider:
    """Detects a local SecLists installation and resolves wordlist paths."""

    def __init__(self):
        self._base = self._detect()

    def _detect(self):
        """Return the SecLists base directory, or None if not found."""
        # Environment variable override takes highest priority
        env_path = os.environ.get('SECLISTS_PATH', '').strip()
        if env_path and os.path.isdir(env_path):
            return env_path

        for candidate in _SECLISTS_SEARCH_PATHS:
            if os.path.isdir(candidate):
                return candidate

        return None

    @property
    def available(self):
        """True when a SecLists installation was found."""
        return self._base is not None

    @property
    def base_path(self):
        """The detected SecLists base directory (may be None)."""
        return self._base

    def get_path(self, module, size='small'):
        """Return the absolute path to a SecLists wordlist, or None.

        Parameters
        ----------
        module : str
            One of ``'subdomains'``, ``'directories'``, ``'parameters'``.
        size : str
            One of ``'small'``, ``'medium'``, ``'large'``.
        """
        if not self.available:
            return None
        relative = _SECLISTS_FILES.get(module, {}).get(size)
        if not relative:
            return None
        full = os.path.join(self._base, relative)
        return full if os.path.isfile(full) else None


# Module-level singleton — evaluated once at import time
_provider = SecListsProvider()


def get_wordlist_for_size(module, size='small'):
    """Return the best wordlist path for *module* at the requested *size*.

    Tries SecLists first; falls back to the bundled wordlist when SecLists is
    not available or the specific file is missing.

    Parameters
    ----------
    module : str
        ``'subdomains'``, ``'directories'``, or ``'parameters'``.
    size : str
        ``'small'`` (default), ``'medium'``, or ``'large'``.

    Returns
    -------
    tuple[str, bool]
        ``(path, from_seclists)`` where *from_seclists* is True when the
        returned path comes from a SecLists installation.
    """
    seclists_path = _provider.get_path(module, size)
    if seclists_path:
        return seclists_path, True

    bundled = {
        'subdomains': _BUNDLED_SUBDOMAINS,
        'directories': _BUNDLED_DIRECTORIES,
        'parameters': _BUNDLED_PARAMETERS,
    }
    return bundled.get(module, _BUNDLED_SUBDOMAINS), False


# Public defaults — point to SecLists (small) when available, else bundled
DEFAULT_SUBDOMAINS, _ = get_wordlist_for_size('subdomains', 'small')
DEFAULT_DIRECTORIES, _ = get_wordlist_for_size('directories', 'small')
DEFAULT_PARAMETERS, _ = get_wordlist_for_size('parameters', 'small')


def get_wordlist(name):
    """Get path to a wordlist by name (uses SecLists when available)."""
    mapping = {
        'subdomains': DEFAULT_SUBDOMAINS,
        'directories': DEFAULT_DIRECTORIES,
        'parameters': DEFAULT_PARAMETERS,
    }
    return mapping.get(name)
