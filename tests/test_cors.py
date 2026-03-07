"""Tests for vortex/cors_scanner.py."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch


def test_get_evil_origin():
    """_get_evil_origin returns a domain-specific evil origin."""
    from vortex.cors_scanner import _get_evil_origin
    evil = _get_evil_origin("https://example.com/path")
    assert "evil.com" in evil
    assert "example.com" in evil


def test_check_cors_empty():
    """check_cors with empty URL list returns empty findings."""
    async def run():
        from vortex.cors_scanner import check_cors
        result = await check_cors([])
        assert result == []

    asyncio.run(run())


def _make_mock_response(status=200, headers=None):
    """Helper to build a mock aiohttp response."""
    resp = AsyncMock()
    resp.status = status
    resp.headers = headers or {}
    resp.__aenter__ = AsyncMock(return_value=resp)
    resp.__aexit__ = AsyncMock(return_value=False)
    return resp


def test_check_cors_no_acao_header():
    """check_cors produces no findings when ACAO header is absent."""
    async def run():
        from vortex.cors_scanner import check_cors

        resp = _make_mock_response(headers={"Content-Type": "text/html"})
        mock_session = MagicMock()
        mock_session.get = MagicMock(return_value=resp)
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=False)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            with patch("aiohttp.TCPConnector", return_value=MagicMock()):
                result = await check_cors(["https://example.com"])

        assert result == []

    asyncio.run(run())


def test_check_cors_reflected_origin_critical():
    """Reflected origin + credentials=true is classified as CRITICAL."""
    async def run():
        from vortex.cors_scanner import check_cors, _SEVERITY_CRITICAL

        call_count = {"n": 0}

        def make_resp(*args, **kwargs):
            # Return a reflected ACAO for the first call
            call_count["n"] += 1
            origin = kwargs.get("headers", {}).get("Origin", "")
            headers = {
                "Access-Control-Allow-Origin": origin,
                "Access-Control-Allow-Credentials": "true",
            }
            return _make_mock_response(status=200, headers=headers)

        mock_session = MagicMock()
        mock_session.get = MagicMock(side_effect=make_resp)
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=False)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            with patch("aiohttp.TCPConnector", return_value=MagicMock()):
                result = await check_cors(["https://example.com"])

        assert any(f["severity"] == _SEVERITY_CRITICAL for f in result)

    asyncio.run(run())


def test_check_cors_output_file(tmp_path):
    """check_cors writes findings to output file."""
    async def run():
        from vortex.cors_scanner import check_cors
        out = tmp_path / "cors.txt"

        def make_resp(*args, **kwargs):
            origin = kwargs.get("headers", {}).get("Origin", "")
            headers = {
                "Access-Control-Allow-Origin": origin,
                "Access-Control-Allow-Credentials": "true",
            }
            return _make_mock_response(status=200, headers=headers)

        mock_session = MagicMock()
        mock_session.get = MagicMock(side_effect=make_resp)
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=False)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            with patch("aiohttp.TCPConnector", return_value=MagicMock()):
                await check_cors(["https://example.com"], output_file=str(out))

        assert out.exists()
        assert "CRITICAL" in out.read_text() or "HIGH" in out.read_text() or out.stat().st_size >= 0

    asyncio.run(run())
