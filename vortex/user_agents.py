import os

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Android 14; Mobile; rv:121.0) Gecko/121.0 Firefox/121.0",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "curl/7.88.1",
]


def _load_seclists_user_agents():
    """Extend USER_AGENTS with entries from SecLists if available."""
    from vortex.wordlists import _provider as _seclists_provider  # local import to avoid circular deps

    if not _seclists_provider.available:
        return

    ua_dir = os.path.join(_seclists_provider.base_path, 'Fuzzing', 'User-Agents')
    if not os.path.isdir(ua_dir):
        return

    _MAX_EXTRA_UA = 500  # avoid loading an unbounded number of entries
    seen = set(USER_AGENTS)
    for fname in sorted(os.listdir(ua_dir)):
        if len(USER_AGENTS) - 10 >= _MAX_EXTRA_UA:
            break
        fpath = os.path.join(ua_dir, fname)
        if not os.path.isfile(fpath):
            continue
        try:
            with open(fpath, encoding='utf-8', errors='replace') as fh:
                for line in fh:
                    if len(USER_AGENTS) - 10 >= _MAX_EXTRA_UA:
                        break
                    ua = line.strip()
                    if ua and ua not in seen:
                        USER_AGENTS.append(ua)
                        seen.add(ua)
        except OSError:
            pass


_load_seclists_user_agents()
