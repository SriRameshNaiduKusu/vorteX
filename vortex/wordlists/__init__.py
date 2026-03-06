import os

WORDLIST_DIR = os.path.dirname(os.path.abspath(__file__))

DEFAULT_SUBDOMAINS = os.path.join(WORDLIST_DIR, 'subdomains.txt')
DEFAULT_DIRECTORIES = os.path.join(WORDLIST_DIR, 'directories.txt')
DEFAULT_PARAMETERS = os.path.join(WORDLIST_DIR, 'parameters.txt')


def get_wordlist(name):
    """Get path to a built-in wordlist by name."""
    wordlists = {
        'subdomains': DEFAULT_SUBDOMAINS,
        'directories': DEFAULT_DIRECTORIES,
        'parameters': DEFAULT_PARAMETERS,
    }
    return wordlists.get(name)
