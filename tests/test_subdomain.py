import asyncio
from unittest.mock import AsyncMock, MagicMock


def test_resolve_subdomain_success():
    async def run():
        from vortex.subdomain import resolve_subdomain

        mock_resolver = AsyncMock()
        mock_result = MagicMock()
        mock_result.addresses = ['1.2.3.4']
        mock_resolver.gethostbyname = AsyncMock(return_value=mock_result)

        sem = asyncio.Semaphore(1)
        result = await resolve_subdomain('www.example.com', mock_resolver, sem)
        assert result == ('www.example.com', '1.2.3.4')

    asyncio.run(run())


def test_resolve_subdomain_failure():
    async def run():
        from vortex.subdomain import resolve_subdomain

        mock_resolver = AsyncMock()
        mock_resolver.gethostbyname = AsyncMock(side_effect=Exception("DNS error"))

        sem = asyncio.Semaphore(1)
        result = await resolve_subdomain('nonexistent.example.com', mock_resolver, sem)
        assert result is None

    asyncio.run(run())
