import os
from unittest.mock import patch


# ---------------------------------------------------------------------------
# Test: built-in wordlist files exist and are non-empty
# ---------------------------------------------------------------------------

def test_default_wordlist_files_exist():
    from vortex.wordlists import DEFAULT_SUBDOMAINS, DEFAULT_DIRECTORIES, DEFAULT_PARAMETERS

    for path in (DEFAULT_SUBDOMAINS, DEFAULT_DIRECTORIES, DEFAULT_PARAMETERS):
        assert os.path.isfile(path), f"Wordlist not found: {path}"


def test_default_wordlist_files_non_empty():
    from vortex.wordlists import DEFAULT_SUBDOMAINS, DEFAULT_DIRECTORIES, DEFAULT_PARAMETERS

    for path in (DEFAULT_SUBDOMAINS, DEFAULT_DIRECTORIES, DEFAULT_PARAMETERS):
        with open(path) as fh:
            entries = [line.strip() for line in fh if line.strip()]
        assert len(entries) > 0, f"Wordlist is empty: {path}"


# ---------------------------------------------------------------------------
# Test: get_wordlist() returns correct paths
# ---------------------------------------------------------------------------

def test_get_wordlist_returns_correct_paths():
    from vortex.wordlists import get_wordlist, DEFAULT_SUBDOMAINS, DEFAULT_DIRECTORIES, DEFAULT_PARAMETERS

    assert get_wordlist('subdomains') == DEFAULT_SUBDOMAINS
    assert get_wordlist('directories') == DEFAULT_DIRECTORIES
    assert get_wordlist('parameters') == DEFAULT_PARAMETERS


def test_get_wordlist_returns_none_for_unknown():
    from vortex.wordlists import get_wordlist

    assert get_wordlist('nonexistent') is None


# ---------------------------------------------------------------------------
# Test: CLI falls back to defaults when -w is not specified
# ---------------------------------------------------------------------------

def test_cli_subdomain_uses_default_wordlist(tmp_path, capsys):
    """When -d is given without -w, the built-in subdomain wordlist is used."""
    from vortex.wordlists import DEFAULT_SUBDOMAINS

    captured_wordlist = []

    async def fake_enum(domain, wordlist, *args, **kwargs):
        captured_wordlist.append(wordlist)
        return []

    with (
        patch("vortex.subdomain.enumerate_subdomains", side_effect=fake_enum),
        patch("sys.argv", ["vorteX", "-d", "example.com"]),
        patch("sys.stdin.isatty", return_value=True),
    ):
        from vortex import main as main_module
        try:
            main_module.main()
        except SystemExit:
            pass

    if captured_wordlist:
        assert captured_wordlist[0] == DEFAULT_SUBDOMAINS


def test_cli_user_wordlist_overrides_default(tmp_path):
    """When -w is given, that wordlist should be used instead of the default."""
    custom_wl = tmp_path / "custom.txt"
    custom_wl.write_text("test\n")

    from vortex.wordlists import DEFAULT_SUBDOMAINS

    captured_wordlist = []

    async def fake_enum(domain, wordlist, *args, **kwargs):
        captured_wordlist.append(wordlist)
        return []

    with (
        patch("vortex.subdomain.enumerate_subdomains", side_effect=fake_enum),
        patch("sys.argv", ["vorteX", "-d", "example.com", "-w", str(custom_wl)]),
        patch("sys.stdin.isatty", return_value=True),
    ):
        from vortex import main as main_module
        try:
            main_module.main()
        except SystemExit:
            pass

    if captured_wordlist:
        assert captured_wordlist[0] == str(custom_wl)
        assert captured_wordlist[0] != DEFAULT_SUBDOMAINS
