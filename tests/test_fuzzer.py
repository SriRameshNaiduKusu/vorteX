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


# ── New tests for wildcard / soft-404 filtering ───────────────────────────────

def _make_get_mock(status: int, body: bytes = b"") -> MagicMock:
    """Build a mock session whose .get() returns *status* and *body*."""
    mock_resp = AsyncMock()
    mock_resp.status = status
    mock_resp.read = AsyncMock(return_value=body)
    mock_resp.release = AsyncMock()
    mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
    mock_resp.__aexit__ = AsyncMock(return_value=False)
    mock_session = MagicMock()
    mock_session.get = MagicMock(return_value=mock_resp)
    return mock_session


def test_fetch_directory_wildcard_filtered():
    """A 200 whose body length matches the wildcard baseline should be suppressed."""
    async def run():
        from vortex.fuzzer import fetch_directory
        import aiohttp

        baseline_body = b"x" * 5000
        mock_session = _make_get_mock(200, baseline_body)

        sem = asyncio.Semaphore(1)
        timeout_obj = aiohttp.ClientTimeout(total=5)
        # Body within ±50 bytes of baseline → soft-404 → None
        result = await fetch_directory(
            'http://example.com/anything',
            mock_session,
            sem,
            client_timeout=timeout_obj,
            wildcard_hosts={'http://example.com': (200, len(baseline_body))},
        )
        assert result is None

    asyncio.run(run())


def test_fetch_directory_wildcard_genuine_hit():
    """A 200 whose body length differs significantly from baseline should pass through."""
    async def run():
        from vortex.fuzzer import fetch_directory
        import aiohttp

        real_body = b"x" * 200  # very different from 5000-byte baseline
        mock_session = _make_get_mock(200, real_body)

        sem = asyncio.Semaphore(1)
        timeout_obj = aiohttp.ClientTimeout(total=5)
        result = await fetch_directory(
            'http://example.com/admin',
            mock_session,
            sem,
            client_timeout=timeout_obj,
            wildcard_hosts={'http://example.com': (200, 5000)},
        )
        assert result == ('http://example.com/admin', 200)

    asyncio.run(run())


def test_fetch_directory_reused_timeout():
    """Passing a pre-built ClientTimeout should be used without creating a new one."""
    async def run():
        from vortex.fuzzer import fetch_directory
        import aiohttp

        mock_session = _make_get_mock(200)
        sem = asyncio.Semaphore(1)
        timeout_obj = aiohttp.ClientTimeout(total=99)
        result = await fetch_directory(
            'http://example.com/page',
            mock_session,
            sem,
            client_timeout=timeout_obj,
        )
        assert result == ('http://example.com/page', 200)

    asyncio.run(run())


def test_detect_wildcard_positive():
    """Two gibberish-path 200s with similar body lengths → wildcard host."""
    async def run():
        from vortex.fuzzer import _detect_wildcard
        import aiohttp

        body = b"catch-all page content " * 100

        # Each call to session.get() returns the same mock response.
        mock_resp = AsyncMock()
        mock_resp.status = 200
        mock_resp.read = AsyncMock(return_value=body)
        mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_resp.__aexit__ = AsyncMock(return_value=False)

        mock_session = MagicMock()
        mock_session.get = MagicMock(return_value=mock_resp)

        timeout_obj = aiohttp.ClientTimeout(total=5)
        is_wc, status, baseline_len = await _detect_wildcard(
            mock_session, 'http://wildcard.example.com', timeout_obj
        )
        assert is_wc is True
        assert status == 200
        assert baseline_len == len(body)  # average of two identical lengths is exact


    asyncio.run(run())


def test_detect_wildcard_negative_404():
    """404 probes → not a wildcard host."""
    async def run():
        from vortex.fuzzer import _detect_wildcard
        import aiohttp

        mock_resp = AsyncMock()
        mock_resp.status = 404
        mock_resp.read = AsyncMock(return_value=b"Not Found")
        mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_resp.__aexit__ = AsyncMock(return_value=False)

        mock_session = MagicMock()
        mock_session.get = MagicMock(return_value=mock_resp)

        timeout_obj = aiohttp.ClientTimeout(total=5)
        is_wc, status, length = await _detect_wildcard(
            mock_session, 'http://normal.example.com', timeout_obj
        )
        assert is_wc is False
        assert status == 0
        assert length == 0

    asyncio.run(run())

