import asyncio
from unittest.mock import AsyncMock, MagicMock
import aiohttp


def test_fetch_directory_found():
    async def run():
        from vortex.fuzzer import fetch_directory

        mock_resp = AsyncMock()
        mock_resp.status = 200
        mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_resp.__aexit__ = AsyncMock(return_value=False)

        mock_session = MagicMock()
        mock_session.get = MagicMock(return_value=mock_resp)

        sem = asyncio.Semaphore(1)
        result = await fetch_directory('http://example.com/admin', mock_session, sem)
        assert result == ('http://example.com/admin', 200)

    asyncio.run(run())


def test_fetch_directory_error():
    async def run():
        from vortex.fuzzer import fetch_directory

        mock_resp = AsyncMock()
        mock_resp.__aenter__ = AsyncMock(side_effect=aiohttp.ClientError("error"))
        mock_resp.__aexit__ = AsyncMock(return_value=False)

        mock_session = MagicMock()
        mock_session.get = MagicMock(return_value=mock_resp)

        sem = asyncio.Semaphore(1)
        result = await fetch_directory('http://example.com/admin', mock_session, sem)
        assert result is None

    asyncio.run(run())
