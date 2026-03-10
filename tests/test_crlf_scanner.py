"""Tests for vortex/crlf_scanner.py."""

import asyncio
import os
from unittest.mock import AsyncMock, MagicMock, patch

from vortex.crlf_scanner import scan_crlf, _check_crlf


# ── _check_crlf ───────────────────────────────────────────────────────────────

def test_check_crlf_cookie_injection():
    """crlftest=vortex in Set-Cookie header → detected."""
    resp_headers = {"Set-Cookie": "crlftest=vortex; Path=/"}
    found, evidence = _check_crlf(resp_headers, "")
    assert found is True
    assert "Set-Cookie" in evidence


def test_check_crlf_header_injection():
    """vortex-crlf-test in custom header → detected."""
    resp_headers = {"X-Injected": "vortex-crlf-test"}
    found, evidence = _check_crlf(resp_headers, "")
    assert found is True
    assert "Header injection" in evidence


def test_check_crlf_location_injection():
    """evil.com in Location header → detected."""
    resp_headers = {"Location": "https://evil.com/redirect"}
    found, evidence = _check_crlf(resp_headers, "")
    assert found is True
    assert "Location" in evidence


def test_check_crlf_no_injection():
    """Clean headers and body → no finding."""
    resp_headers = {"Content-Type": "text/html", "Server": "nginx"}
    found, evidence = _check_crlf(resp_headers, "<html><p>Hello</p></html>")
    assert found is False
    assert evidence == ""


def test_check_crlf_response_splitting_in_body():
    """<script>alert(1)</script> in body → HTTP response splitting detected."""
    resp_headers = {"Content-Type": "text/html"}
    found, evidence = _check_crlf(resp_headers, "<script>alert(1)</script>")
    assert found is True
    assert "splitting" in evidence.lower()


# ── scan_crlf ─────────────────────────────────────────────────────────────────

def _make_mock_response(body: str, status: int = 200, extra_headers: dict | None = None):
    resp = AsyncMock()
    resp.status = status
    resp.text = AsyncMock(return_value=body)
    headers = {"Content-Type": "text/html"}
    if extra_headers:
        headers.update(extra_headers)
    resp.headers = headers
    resp.__aenter__ = AsyncMock(return_value=resp)
    resp.__aexit__ = AsyncMock(return_value=False)
    return resp


def test_scan_crlf_empty_urls():
    """Empty URL list returns empty."""
    results = asyncio.run(scan_crlf([]))
    assert results == []


def test_scan_crlf_no_params():
    """URLs without query parameters yield no findings."""
    results = asyncio.run(scan_crlf(["http://example.com/page"]))
    assert results == []


def test_scan_crlf_detects_injection():
    """Integration test: injected Set-Cookie header in response → HIGH finding."""
    mock_resp = _make_mock_response(
        "<html>OK</html>",
        extra_headers={"Set-Cookie": "crlftest=vortex; Path=/"},
    )

    mock_session = MagicMock()
    mock_session.get = MagicMock(return_value=mock_resp)
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=False)

    with patch("vortex.crlf_scanner.aiohttp.ClientSession", return_value=mock_session):
        results = asyncio.run(scan_crlf(
            ["http://example.com/page?redirect=test"],
            fast=True,
        ))

    assert len(results) >= 1
    assert results[0]["severity"] == "HIGH"
    assert results[0]["parameter"] == "redirect"


def test_scan_crlf_no_findings_on_clean_response():
    """Clean response → no findings."""
    mock_resp = _make_mock_response("<html><p>Hello World</p></html>")

    mock_session = MagicMock()
    mock_session.get = MagicMock(return_value=mock_resp)
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=False)

    with patch("vortex.crlf_scanner.aiohttp.ClientSession", return_value=mock_session):
        results = asyncio.run(scan_crlf(
            ["http://example.com/page?q=test"],
            fast=True,
        ))

    assert results == []


def test_scan_crlf_output_file(tmp_path):
    """Output file is written when findings exist."""
    mock_resp = _make_mock_response(
        "<html>OK</html>",
        extra_headers={"Set-Cookie": "crlftest=vortex; Path=/"},
    )

    mock_session = MagicMock()
    mock_session.get = MagicMock(return_value=mock_resp)
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=False)

    out_file = str(tmp_path / "crlf_results.txt")
    with patch("vortex.crlf_scanner.aiohttp.ClientSession", return_value=mock_session):
        results = asyncio.run(scan_crlf(
            ["http://example.com/page?redirect=test"],
            output_file=out_file,
            fast=True,
        ))

    if results:
        assert os.path.isfile(out_file)
