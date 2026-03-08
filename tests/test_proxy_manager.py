"""Tests for vortex/proxy_manager.py."""

import pytest
from vortex.proxy_manager import ProxyManager


def test_proxy_manager_loads_proxies(tmp_path):
    proxy_file = tmp_path / "proxies.txt"
    proxy_file.write_text(
        "http://127.0.0.1:8080\n"
        "http://127.0.0.1:8081\n"
        "# This is a comment\n"
        "\n"
        "http://127.0.0.1:8082\n"
    )
    pm = ProxyManager(str(proxy_file))
    assert len(pm) == 3


def test_proxy_manager_round_robin(tmp_path):
    proxy_file = tmp_path / "proxies.txt"
    proxy_file.write_text("http://proxy1:8080\nhttp://proxy2:8080\n")
    pm = ProxyManager(str(proxy_file))
    p1 = pm.next()
    p2 = pm.next()
    p3 = pm.next()
    assert p1 == "http://proxy1:8080"
    assert p2 == "http://proxy2:8080"
    assert p3 == "http://proxy1:8080"  # wraps around


def test_proxy_manager_raises_on_empty_file(tmp_path):
    proxy_file = tmp_path / "proxies.txt"
    proxy_file.write_text("# only comments\n\n")
    with pytest.raises(ValueError, match="No valid proxies"):
        ProxyManager(str(proxy_file))


def test_proxy_manager_raises_on_missing_file():
    with pytest.raises(ValueError, match="No valid proxies"):
        ProxyManager("/nonexistent/path/proxies.txt")


def test_proxy_manager_repr(tmp_path):
    proxy_file = tmp_path / "proxies.txt"
    proxy_file.write_text("http://proxy1:8080\n")
    pm = ProxyManager(str(proxy_file))
    assert "1 proxies" in repr(pm)


def test_proxy_manager_ignores_blank_lines(tmp_path):
    proxy_file = tmp_path / "proxies.txt"
    proxy_file.write_text("\n\nhttp://proxy1:8080\n\nhttp://proxy2:8080\n\n")
    pm = ProxyManager(str(proxy_file))
    assert len(pm) == 2
