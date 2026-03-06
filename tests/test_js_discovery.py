import asyncio
from unittest.mock import AsyncMock, MagicMock


def test_fetch_and_extract_js_links_finds_paths():
    async def run():
        from vortex.js_discovery import fetch_and_extract_js_links

        js_content = b'var api = "/api/v1/users"; var base = "https://cdn.example.com/lib.js";'

        mock_resp = AsyncMock()
        mock_resp.status = 200
        mock_resp.text = AsyncMock(return_value=js_content.decode())
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
