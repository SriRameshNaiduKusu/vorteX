"""Tests for vortex/seclists.py."""

import os
from unittest.mock import patch


def test_find_seclists_returns_none_when_absent():
    """find_seclists() returns None when no SecLists installation is present."""
    import vortex.seclists as sl_mod

    with patch.dict(os.environ, {"SECLISTS_PATH": ""}, clear=False):
        with patch("vortex.wordlists._SECLISTS_SEARCH_PATHS", ["/nonexistent/seclists"]):
            from vortex.wordlists import SecListsProvider
            provider = SecListsProvider()
            with patch.object(sl_mod, "_provider", provider):
                assert sl_mod.find_seclists() is None


def test_find_seclists_returns_path_when_present(tmp_path):
    """find_seclists() returns the detected SecLists base directory."""
    import vortex.seclists as sl_mod

    with patch.dict(os.environ, {"SECLISTS_PATH": str(tmp_path)}):
        from vortex.wordlists import SecListsProvider
        provider = SecListsProvider()
        with patch.object(sl_mod, "_provider", provider):
            assert sl_mod.find_seclists() == str(tmp_path)


def test_get_seclists_wordlist_returns_none_when_absent():
    """get_seclists_wordlist() returns None when SecLists is not installed."""
    import vortex.seclists as sl_mod

    with patch.dict(os.environ, {"SECLISTS_PATH": ""}, clear=False):
        with patch("vortex.wordlists._SECLISTS_SEARCH_PATHS", ["/nonexistent"]):
            from vortex.wordlists import SecListsProvider
            provider = SecListsProvider()
            with patch.object(sl_mod, "_provider", provider):
                assert sl_mod.get_seclists_wordlist("subdomains") is None


def test_get_seclists_wordlist_returns_path_when_file_exists(tmp_path):
    """get_seclists_wordlist() returns the correct path when the file exists."""
    import vortex.seclists as sl_mod

    sl_dns = tmp_path / "Discovery" / "DNS"
    sl_dns.mkdir(parents=True)
    wordlist_file = sl_dns / "subdomains-top1million-5000.txt"
    wordlist_file.write_text("example\n")

    with patch.dict(os.environ, {"SECLISTS_PATH": str(tmp_path)}):
        from vortex.wordlists import SecListsProvider
        provider = SecListsProvider()
        with patch.object(sl_mod, "_provider", provider):
            path = sl_mod.get_seclists_wordlist("subdomains", "small")
            assert path is not None
            assert os.path.isfile(path)
            assert "subdomains-top1million-5000.txt" in path


def test_seclists_module_exports():
    """seclists module exposes expected public API."""
    from vortex import seclists
    assert callable(seclists.find_seclists)
    assert callable(seclists.get_seclists_wordlist)
    assert callable(seclists.get_wordlist_for_size)
