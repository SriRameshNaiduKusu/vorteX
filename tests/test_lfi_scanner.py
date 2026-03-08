"""Tests for vortex/lfi_scanner.py."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

from vortex.lfi_scanner import scan_lfi, _detect_lfi


# ── _detect_lfi ──────────────────────────────────────────────────────────────

def test_detect_lfi_linux_passwd():
    body = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/bin/sh"
    found, file_type = _detect_lfi(body)
    assert found is True
    assert "passwd" in file_type.lower() or "Linux" in file_type


def test_detect_lfi_windows_ini():
    body = "[extensions]\n[fonts]\n\n[mci extensions]\n"
    found, file_type = _detect_lfi(body)
    assert found is True
    assert "win" in file_type.lower() or "Windows" in file_type


def test_detect_lfi_no_match():
    body = "<html><p>Normal page content here</p></html>"
    found, file_type = _detect_lfi(body)
    assert found is False
    assert file_type == ""


def test_detect_lfi_etc_hosts():
    body = "127.0.0.1 localhost\n127.0.1.1 myhost"
    found, file_type = _detect_lfi(body)
    assert found is True


# ── scan_lfi ─────────────────────────────────────────────────────────────────

def _make_mock_response(body: str, status: int = 200):
    resp = AsyncMock()
    resp.status = status
    resp.text = AsyncMock(return_value=body)
    resp.__aenter__ = AsyncMock(return_value=resp)
    resp.__aexit__ = AsyncMock(return_value=False)
    return resp


def test_scan_lfi_empty_urls():
    results = asyncio.run(scan_lfi([]))
    assert results == []


def test_scan_lfi_no_params():
    results = asyncio.run(scan_lfi(["http://example.com/page"]))
    assert results == []


def test_scan_lfi_detects_lfi():
    lfi_body = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1"
    mock_resp = _make_mock_response(lfi_body)

    mock_session = MagicMock()
    mock_session.get = MagicMock(return_value=mock_resp)
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=False)

    with patch("vortex.lfi_scanner.aiohttp.ClientSession", return_value=mock_session):
        results = asyncio.run(scan_lfi(
            ["http://example.com/page?file=about.txt"],
            fast=True,
        ))

    assert any(f["parameter"] == "file" for f in results)


def test_scan_lfi_no_findings_on_clean_body():
    mock_resp = _make_mock_response("<html>Welcome!</html>")

    mock_session = MagicMock()
    mock_session.get = MagicMock(return_value=mock_resp)
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=False)

    with patch("vortex.lfi_scanner.aiohttp.ClientSession", return_value=mock_session):
        results = asyncio.run(scan_lfi(
            ["http://example.com/page?file=about.txt"],
            fast=True,
        ))

    assert results == []
