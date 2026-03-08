"""Tests for vortex/waf_detector.py."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

from vortex.waf_detector import detect_waf, _WAF_SIGNATURES


# ── Signature tests ──────────────────────────────────────────────────────────

def test_waf_signatures_not_empty():
    assert len(_WAF_SIGNATURES) > 0


def test_cloudflare_signature():
    """Cloudflare should be detected via the cf-ray header."""
    for name, check_fn in _WAF_SIGNATURES:
        if name == "Cloudflare":
            assert check_fn({"cf-ray": "abc123"}, {}, "") is True
            assert check_fn({}, {}, "") is False
            break


def test_imperva_signature_via_cookie():
    """Imperva/Incapsula detected via incap_ses cookie."""
    for name, check_fn in _WAF_SIGNATURES:
        if name == "Imperva / Incapsula":
            assert check_fn({}, {"incap_ses_123": "xyz"}, "") is True
            break


def test_sucuri_signature_via_header():
    """Sucuri detected via x-sucuri-id header."""
    for name, check_fn in _WAF_SIGNATURES:
        if name == "Sucuri":
            assert check_fn({"x-sucuri-id": "12345"}, {}, "") is True
            break


# ── detect_waf ───────────────────────────────────────────────────────────────

def _make_mock_response(status: int, headers: dict, body: str = ""):
    resp = AsyncMock()
    resp.status = status
    resp.headers = headers
    resp.cookies = {}
    resp.text = AsyncMock(return_value=body)
    resp.read = AsyncMock(return_value=body.encode())
    resp.__aenter__ = AsyncMock(return_value=resp)
    resp.__aexit__ = AsyncMock(return_value=False)
    return resp


def test_detect_waf_empty_urls():
    results = asyncio.run(detect_waf([]))
    assert results == []


def test_detect_waf_cloudflare():
    mock_resp = _make_mock_response(
        403,
        {"cf-ray": "abc-DEF", "server": "cloudflare"},
        "Attention Required! | Cloudflare",
    )
    mock_session = MagicMock()
    mock_session.get = MagicMock(return_value=mock_resp)
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=False)

    with patch("vortex.waf_detector.aiohttp.ClientSession", return_value=mock_session):
        results = asyncio.run(detect_waf(["http://example.com/"]))

    assert len(results) == 1
    assert results[0]["waf_detected"] is True
    waf = results[0]["waf"]
    waf_str = ", ".join(waf) if isinstance(waf, list) else waf
    assert "Cloudflare" in waf_str


def test_detect_waf_no_waf():
    mock_resp = _make_mock_response(200, {"server": "nginx"}, "<html>Hello</html>")
    mock_session = MagicMock()
    mock_session.get = MagicMock(return_value=mock_resp)
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=False)

    with patch("vortex.waf_detector.aiohttp.ClientSession", return_value=mock_session):
        results = asyncio.run(detect_waf(["http://example.com/"]))

    assert len(results) == 1
    assert results[0]["waf_detected"] is False
