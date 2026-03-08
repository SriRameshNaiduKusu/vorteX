"""Tests for vortex/ssrf_scanner.py."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

from vortex.ssrf_scanner import scan_ssrf, _looks_like_ssrf


# ── _looks_like_ssrf ─────────────────────────────────────────────────────────

def test_looks_like_ssrf_aws_metadata():
    body = "ami-id: ami-12345678\ninstance-id: i-abcdef"
    found, indicator = _looks_like_ssrf(body)
    assert found is True
    assert "ami-id" in indicator or "instance-id" in indicator


def test_looks_like_ssrf_linux_passwd():
    body = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1"
    found, indicator = _looks_like_ssrf(body)
    assert found is True


def test_looks_like_ssrf_gcp_metadata():
    body = '{"computeMetadata": {"instance": {"id": 12345}}}'
    found, indicator = _looks_like_ssrf(body)
    assert found is True


def test_looks_like_ssrf_clean_body():
    body = "<html><p>Welcome to our site!</p></html>"
    found, indicator = _looks_like_ssrf(body)
    assert found is False
    assert indicator == ""


# ── scan_ssrf ────────────────────────────────────────────────────────────────

def _make_mock_response(body: str, status: int = 200):
    resp = AsyncMock()
    resp.status = status
    resp.text = AsyncMock(return_value=body)
    resp.__aenter__ = AsyncMock(return_value=resp)
    resp.__aexit__ = AsyncMock(return_value=False)
    return resp


def test_scan_ssrf_empty_urls():
    results = asyncio.run(scan_ssrf([]))
    assert results == []


def test_scan_ssrf_no_params():
    results = asyncio.run(scan_ssrf(["http://example.com/page"]))
    assert results == []


def test_scan_ssrf_detects_ssrf():
    ssrf_body = "root:x:0:0:root:/root:/bin/bash"
    mock_resp = _make_mock_response(ssrf_body)

    mock_session = MagicMock()
    mock_session.get = MagicMock(return_value=mock_resp)
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=False)

    with patch("vortex.ssrf_scanner.aiohttp.ClientSession", return_value=mock_session):
        results = asyncio.run(scan_ssrf(
            ["http://example.com/fetch?url=test"],
            fast=True,
        ))

    assert any(f["parameter"] == "url" for f in results)


def test_scan_ssrf_no_findings_on_clean_body():
    mock_resp = _make_mock_response("<html>Hello World</html>")

    mock_session = MagicMock()
    mock_session.get = MagicMock(return_value=mock_resp)
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=False)

    with patch("vortex.ssrf_scanner.aiohttp.ClientSession", return_value=mock_session):
        results = asyncio.run(scan_ssrf(
            ["http://example.com/fetch?url=test"],
            fast=True,
        ))

    assert results == []
