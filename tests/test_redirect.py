"""Tests for vortex/open_redirect.py."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch


def test_redirect_params_not_empty():
    """REDIRECT_PARAMS list should contain common parameter names."""
    from vortex.open_redirect import REDIRECT_PARAMS
    assert "url" in REDIRECT_PARAMS
    assert "redirect" in REDIRECT_PARAMS
    assert "next" in REDIRECT_PARAMS


def test_redirect_payloads_not_empty():
    """REDIRECT_PAYLOADS list should contain test payloads."""
    from vortex.open_redirect import REDIRECT_PAYLOADS
    assert len(REDIRECT_PAYLOADS) > 0
    assert any("evil.com" in p for p in REDIRECT_PAYLOADS)


def test_location_points_to_evil():
    """_location_points_to_evil correctly identifies evil.com redirects."""
    from vortex.open_redirect import _location_points_to_evil
    assert _location_points_to_evil("https://evil.com/path")
    assert _location_points_to_evil("//evil.com")
    assert not _location_points_to_evil("https://example.com")
    assert not _location_points_to_evil("")
    assert not _location_points_to_evil(None)


def test_check_open_redirect_empty():
    """check_open_redirect with empty URL list returns empty findings."""
    async def run():
        from vortex.open_redirect import check_open_redirect
        result = await check_open_redirect([])
        assert result == []

    asyncio.run(run())


def _make_redirect_response(status=302, location="https://evil.com"):
    resp = AsyncMock()
    resp.status = status
    resp.headers = {"Location": location} if location else {}
    resp.__aenter__ = AsyncMock(return_value=resp)
    resp.__aexit__ = AsyncMock(return_value=False)
    return resp


def test_check_open_redirect_detects_redirect():
    """check_open_redirect detects a 302 redirect to evil.com."""
    async def run():
        from vortex.open_redirect import check_open_redirect

        resp = _make_redirect_response(status=302, location="https://evil.com")
        mock_session = MagicMock()
        mock_session.get = MagicMock(return_value=resp)
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=False)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            with patch("aiohttp.TCPConnector", return_value=MagicMock()):
                result = await check_open_redirect(
                    ["https://example.com/page"],
                    params=["url"],
                    payloads=["https://evil.com"],
                )

        assert len(result) >= 1
        assert result[0]["severity"] == "HIGH"
        assert result[0]["location"] == "https://evil.com"

    asyncio.run(run())


def test_check_open_redirect_ignores_200():
    """check_open_redirect does not flag non-redirect responses."""
    async def run():
        from vortex.open_redirect import check_open_redirect

        resp = AsyncMock()
        resp.status = 200
        resp.headers = {}
        resp.__aenter__ = AsyncMock(return_value=resp)
        resp.__aexit__ = AsyncMock(return_value=False)

        mock_session = MagicMock()
        mock_session.get = MagicMock(return_value=resp)
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=False)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            with patch("aiohttp.TCPConnector", return_value=MagicMock()):
                result = await check_open_redirect(
                    ["https://example.com/page"],
                    params=["url"],
                    payloads=["https://evil.com"],
                )

        assert result == []

    asyncio.run(run())


def test_check_open_redirect_output_file(tmp_path):
    """Findings are written to an output file."""
    async def run():
        from vortex.open_redirect import check_open_redirect
        out = tmp_path / "redirect.txt"

        resp = _make_redirect_response(status=302, location="https://evil.com")
        mock_session = MagicMock()
        mock_session.get = MagicMock(return_value=resp)
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=False)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            with patch("aiohttp.TCPConnector", return_value=MagicMock()):
                await check_open_redirect(
                    ["https://example.com/page"],
                    params=["url"],
                    payloads=["https://evil.com"],
                    output_file=str(out),
                )

        assert out.exists()
        assert "evil.com" in out.read_text()

    asyncio.run(run())
