"""Tests for vortex/bypass403.py."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

from vortex.bypass403 import bypass_403, _BYPASS_HEADERS, _PATH_BYPASSES, _BYPASS_METHODS


# ── Constants ─────────────────────────────────────────────────────────────────

def test_bypass_headers_not_empty():
    assert len(_BYPASS_HEADERS) > 0


def test_path_bypasses_not_empty():
    assert len(_PATH_BYPASSES) > 0


def test_bypass_methods_not_empty():
    assert len(_BYPASS_METHODS) > 0


def test_bypass_methods_include_common_verbs():
    assert "POST" in _BYPASS_METHODS
    assert "OPTIONS" in _BYPASS_METHODS


# ── bypass_403 ────────────────────────────────────────────────────────────────

def _make_mock_response(status: int):
    resp = AsyncMock()
    resp.status = status
    resp.__aenter__ = AsyncMock(return_value=resp)
    resp.__aexit__ = AsyncMock(return_value=False)
    return resp


def test_bypass_403_empty_urls():
    results = asyncio.run(bypass_403([]))
    assert results == []


def test_bypass_403_detects_bypass():
    """A 200 response to a modified request should be reported as a bypass."""
    mock_resp_200 = _make_mock_response(200)

    mock_session = MagicMock()
    mock_session.get = MagicMock(return_value=mock_resp_200)
    mock_session.request = MagicMock(return_value=mock_resp_200)
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=False)

    with patch("vortex.bypass403.aiohttp.ClientSession", return_value=mock_session):
        results = asyncio.run(bypass_403(["http://example.com/admin"]))

    assert len(results) > 0
    assert all(f["status"] == 200 for f in results)


def test_bypass_403_no_bypass_on_403():
    """If all responses return 403, no bypasses should be reported."""
    mock_resp_403 = _make_mock_response(403)

    mock_session = MagicMock()
    mock_session.get = MagicMock(return_value=mock_resp_403)
    mock_session.request = MagicMock(return_value=mock_resp_403)
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=False)

    with patch("vortex.bypass403.aiohttp.ClientSession", return_value=mock_session):
        results = asyncio.run(bypass_403(["http://example.com/admin"]))

    assert results == []


def test_bypass_403_output_file(tmp_path):
    mock_resp_200 = _make_mock_response(200)

    mock_session = MagicMock()
    mock_session.get = MagicMock(return_value=mock_resp_200)
    mock_session.request = MagicMock(return_value=mock_resp_200)
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=False)

    out_file = str(tmp_path / "bypass_results.txt")
    with patch("vortex.bypass403.aiohttp.ClientSession", return_value=mock_session):
        results = asyncio.run(bypass_403(
            ["http://example.com/admin"],
            output_file=out_file,
        ))

    if results:
        import os
        assert os.path.isfile(out_file)
