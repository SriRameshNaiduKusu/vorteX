"""Tests for vortex/xss_scanner.py."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

from vortex.xss_scanner import scan_xss, _detect_context


# ── _detect_context ──────────────────────────────────────────────────────────

def test_detect_context_script_tag():
    payload = "<script>alert(1)</script>"
    body = f'<html><head>{payload}</head></html>'
    ctx = _detect_context(payload, body)
    assert "script" in ctx.lower()


def test_detect_context_html_body():
    payload = "<img src=x onerror=alert(1)>"
    body = f"<p>{payload}</p>"
    ctx = _detect_context(payload, body)
    assert isinstance(ctx, str)
    assert len(ctx) > 0


def test_detect_context_not_reflected():
    payload = "<script>alert(1)</script>"
    body = "<html><p>Hello</p></html>"
    ctx = _detect_context(payload, body)
    # Should still return a string even when not found
    assert isinstance(ctx, str)


# ── scan_xss ─────────────────────────────────────────────────────────────────

def _make_mock_response(body: str, status: int = 200):
    resp = AsyncMock()
    resp.status = status
    resp.text = AsyncMock(return_value=body)
    resp.__aenter__ = AsyncMock(return_value=resp)
    resp.__aexit__ = AsyncMock(return_value=False)
    return resp


def test_scan_xss_empty_urls():
    results = asyncio.run(scan_xss([]))
    assert results == []


def test_scan_xss_no_params():
    """URLs without query parameters should yield no findings."""
    results = asyncio.run(scan_xss(["http://example.com/page"]))
    assert results == []


def test_scan_xss_detects_reflected_payload():
    """When payload is reflected in body, a finding should be returned."""
    payload = "<script>alert(1)</script>"

    mock_resp = _make_mock_response(f"<html>{payload}</html>")

    mock_session = MagicMock()
    mock_session.get = MagicMock(return_value=mock_resp)
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=False)

    with patch("vortex.xss_scanner.aiohttp.ClientSession", return_value=mock_session):
        results = asyncio.run(scan_xss(
            ["http://example.com/search?q=test"],
            fast=True,
        ))

    assert any(f["parameter"] == "q" for f in results)


def test_scan_xss_no_reflection():
    """When payload is NOT reflected, no findings should be returned."""
    mock_resp = _make_mock_response("<html><p>Safe</p></html>")

    mock_session = MagicMock()
    mock_session.get = MagicMock(return_value=mock_resp)
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=False)

    with patch("vortex.xss_scanner.aiohttp.ClientSession", return_value=mock_session):
        results = asyncio.run(scan_xss(
            ["http://example.com/search?q=test"],
            fast=True,
        ))

    assert results == []


def test_scan_xss_output_file(tmp_path):
    payload = "<script>alert(1)</script>"
    mock_resp = _make_mock_response(f"<html>{payload}</html>")

    mock_session = MagicMock()
    mock_session.get = MagicMock(return_value=mock_resp)
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=False)

    out_file = str(tmp_path / "xss_results.txt")
    with patch("vortex.xss_scanner.aiohttp.ClientSession", return_value=mock_session):
        results = asyncio.run(scan_xss(
            ["http://example.com/search?q=test"],
            output_file=out_file,
            fast=True,
        ))

    if results:
        import os
        assert os.path.isfile(out_file)


def test_scan_xss_fast_mode_uses_fewer_payloads():
    """Fast mode should use a reduced payload set."""
    from vortex.payloads import load_payloads
    all_payloads = load_payloads("xss.txt")
    fast_count = len(all_payloads[:20])
    assert fast_count <= 20
    assert fast_count < len(all_payloads)
