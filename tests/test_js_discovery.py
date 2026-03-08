import asyncio
from unittest.mock import AsyncMock, MagicMock


def test_fetch_and_extract_js_links_finds_paths():
    async def run():
        from vortex.js_discovery import fetch_and_extract_js_links

        js_content = b'var api = "/api/v1/users"; var base = "https://cdn.example.com/lib.js";'

        mock_resp = AsyncMock()
        mock_resp.status = 200
        mock_resp.charset = 'utf-8'
        mock_resp.headers = {'Content-Type': 'application/javascript'}
        mock_resp.read = AsyncMock(return_value=js_content)
        mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_resp.__aexit__ = AsyncMock(return_value=False)

        mock_session = MagicMock()
        mock_session.get = MagicMock(return_value=mock_resp)

        result = await fetch_and_extract_js_links('http://example.com/app.js', mock_session)
        assert '/api/v1/users' in result or 'https://cdn.example.com/lib.js' in result

    asyncio.run(run())


def test_fetch_and_extract_js_links_error():
    async def run():
        import aiohttp
        from vortex.js_discovery import fetch_and_extract_js_links

        mock_resp = AsyncMock()
        mock_resp.__aenter__ = AsyncMock(side_effect=aiohttp.ClientError("error"))
        mock_resp.__aexit__ = AsyncMock(return_value=False)

        mock_session = MagicMock()
        mock_session.get = MagicMock(return_value=mock_resp)

        result = await fetch_and_extract_js_links('http://example.com/app.js', mock_session)
        assert result == set()

    asyncio.run(run())


def test_fetch_and_extract_js_links_binary_content_type():
    """Binary Content-Type responses should be skipped (return empty set)."""
    async def run():
        from vortex.js_discovery import fetch_and_extract_js_links

        mock_resp = AsyncMock()
        mock_resp.status = 200
        mock_resp.charset = None
        mock_resp.headers = {'Content-Type': 'application/octet-stream'}
        mock_resp.read = AsyncMock(return_value=b'\x89PNG\r\n\x1a\n')
        mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_resp.__aexit__ = AsyncMock(return_value=False)

        mock_session = MagicMock()
        mock_session.get = MagicMock(return_value=mock_resp)

        result = await fetch_and_extract_js_links('http://example.com/image.png', mock_session)
        assert result == set()

    asyncio.run(run())


def test_fetch_and_extract_js_links_invalid_encoding():
    """Non-UTF-8 bytes should be decoded with replacement rather than raising."""
    async def run():
        from vortex.js_discovery import fetch_and_extract_js_links

        # 0x9e is invalid in UTF-8
        raw = b'var path = "/api/data"; \x9e garbage'

        mock_resp = AsyncMock()
        mock_resp.status = 200
        mock_resp.charset = 'utf-8'
        mock_resp.headers = {'Content-Type': 'application/javascript'}
        mock_resp.read = AsyncMock(return_value=raw)
        mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_resp.__aexit__ = AsyncMock(return_value=False)

        mock_session = MagicMock()
        mock_session.get = MagicMock(return_value=mock_resp)

        result = await fetch_and_extract_js_links('http://example.com/app.js', mock_session)
        assert '/api/data' in result

    asyncio.run(run())
