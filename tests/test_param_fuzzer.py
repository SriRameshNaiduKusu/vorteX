import asyncio
from unittest.mock import AsyncMock, MagicMock


def test_discover_param_found():
    async def run():
        from vortex.param_fuzzer import discover_param

        mock_resp = AsyncMock()
        mock_resp.status = 200
        mock_resp.text = AsyncMock(return_value='vorteXTest found in response')
        mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_resp.__aexit__ = AsyncMock(return_value=False)

        mock_session = MagicMock()
        mock_session.get = MagicMock(return_value=mock_resp)

        sem = asyncio.Semaphore(1)
        result = await discover_param(mock_session, 'http://example.com', 'GET', 'id', sem)
        assert result == ('id', 200)

    asyncio.run(run())


def test_discover_param_not_found():
    async def run():
        from vortex.param_fuzzer import discover_param

        mock_resp = AsyncMock()
        mock_resp.status = 200
        mock_resp.text = AsyncMock(return_value='no match here')
        mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_resp.__aexit__ = AsyncMock(return_value=False)

        mock_session = MagicMock()
        mock_session.get = MagicMock(return_value=mock_resp)

        sem = asyncio.Semaphore(1)
        result = await discover_param(mock_session, 'http://example.com', 'GET', 'id', sem)
        assert result is None

    asyncio.run(run())
