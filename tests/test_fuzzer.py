import asyncio
from unittest.mock import AsyncMock, MagicMock
import aiohttp


def test_fetch_directory_found():
    async def run():
        from vortex.fuzzer import fetch_directory

        mock_resp = AsyncMock()
        mock_resp.status = 200
        mock_resp.read = AsyncMock(return_value=b"")
        mock_resp.release = AsyncMock()
        mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_resp.__aexit__ = AsyncMock(return_value=False)

        mock_session = MagicMock()
        mock_session.get = MagicMock(return_value=mock_resp)

        sem = asyncio.Semaphore(1)
        result = await fetch_directory('http://example.com/admin', mock_session, sem)
        assert result is not None
        url, status, body_size, word_count, line_count = result
        assert url == 'http://example.com/admin'
        assert status == 200

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
        assert result is not None
        url, status, body_size, word_count, line_count = result
        assert url == 'http://example.com/admin'
        assert status == 200

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
        assert result is not None
        url, status, body_size, word_count, line_count = result
        assert url == 'http://example.com/page'
        assert status == 200

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


# ── Tests for new response-filtering flags ────────────────────────────────────

def test_filter_size_filters_matching_response():
    """A response whose body size is in filter_size should be suppressed."""
    async def run():
        from vortex.fuzzer import fetch_directory
        import aiohttp

        body = b"x" * 12438
        mock_session = _make_get_mock(200, body)
        sem = asyncio.Semaphore(1)
        timeout_obj = aiohttp.ClientTimeout(total=5)
        result = await fetch_directory(
            'http://example.com/path',
            mock_session,
            sem,
            client_timeout=timeout_obj,
            filter_size={12438},
        )
        assert result is None

    asyncio.run(run())


def test_filter_size_passes_non_matching_response():
    """A response whose body size is NOT in filter_size should pass through."""
    async def run():
        from vortex.fuzzer import fetch_directory
        import aiohttp

        body = b"x" * 500
        mock_session = _make_get_mock(200, body)
        sem = asyncio.Semaphore(1)
        timeout_obj = aiohttp.ClientTimeout(total=5)
        result = await fetch_directory(
            'http://example.com/path',
            mock_session,
            sem,
            client_timeout=timeout_obj,
            filter_size={12438},
        )
        assert result is not None
        url, status, body_size, word_count, line_count = result
        assert url == 'http://example.com/path'
        assert body_size == 500

    asyncio.run(run())


def test_word_line_counts_computed_with_only_filter_size():
    """word_count and line_count should be non-zero when only filter_size is active."""
    async def run():
        from vortex.fuzzer import fetch_directory
        import aiohttp

        # Body has 4 words and 2 lines; size (17 bytes) does NOT match filter_size.
        body = b"hello world\nfoo bar"
        mock_session = _make_get_mock(200, body)
        sem = asyncio.Semaphore(1)
        timeout_obj = aiohttp.ClientTimeout(total=5)
        result = await fetch_directory(
            'http://example.com/path',
            mock_session,
            sem,
            client_timeout=timeout_obj,
            filter_size={99999},  # does not match → response should pass through
        )
        assert result is not None
        url, status, body_size, word_count, line_count = result
        assert body_size == len(body)
        assert word_count == 4
        assert line_count == 2

    asyncio.run(run())


def test_filter_words_filters_matching_response():
    """A response whose word count is in filter_words should be suppressed."""
    async def run():
        from vortex.fuzzer import fetch_directory
        import aiohttp

        # Body with exactly 5 words.
        body = b"one two three four five"
        mock_session = _make_get_mock(200, body)
        sem = asyncio.Semaphore(1)
        timeout_obj = aiohttp.ClientTimeout(total=5)
        result = await fetch_directory(
            'http://example.com/path',
            mock_session,
            sem,
            client_timeout=timeout_obj,
            filter_words={5},
        )
        assert result is None

    asyncio.run(run())


def test_filter_words_passes_non_matching_response():
    """A response whose word count is NOT in filter_words should pass through."""
    async def run():
        from vortex.fuzzer import fetch_directory
        import aiohttp

        body = b"one two three"  # 3 words
        mock_session = _make_get_mock(200, body)
        sem = asyncio.Semaphore(1)
        timeout_obj = aiohttp.ClientTimeout(total=5)
        result = await fetch_directory(
            'http://example.com/path',
            mock_session,
            sem,
            client_timeout=timeout_obj,
            filter_words={5},
        )
        assert result is not None
        url, status, body_size, word_count, line_count = result
        assert word_count == 3

    asyncio.run(run())


def test_filter_lines_filters_matching_response():
    """A response whose line count is in filter_lines should be suppressed."""
    async def run():
        from vortex.fuzzer import fetch_directory
        import aiohttp

        # Body with 3 lines (2 newlines + 1 last line).
        body = b"line1\nline2\nline3"
        mock_session = _make_get_mock(200, body)
        sem = asyncio.Semaphore(1)
        timeout_obj = aiohttp.ClientTimeout(total=5)
        result = await fetch_directory(
            'http://example.com/path',
            mock_session,
            sem,
            client_timeout=timeout_obj,
            filter_lines={3},
        )
        assert result is None

    asyncio.run(run())


def test_filter_lines_passes_non_matching_response():
    """A response whose line count is NOT in filter_lines should pass through."""
    async def run():
        from vortex.fuzzer import fetch_directory
        import aiohttp

        body = b"only one line"  # 1 line
        mock_session = _make_get_mock(200, body)
        sem = asyncio.Semaphore(1)
        timeout_obj = aiohttp.ClientTimeout(total=5)
        result = await fetch_directory(
            'http://example.com/path',
            mock_session,
            sem,
            client_timeout=timeout_obj,
            filter_lines={3},
        )
        assert result is not None
        url, status, body_size, word_count, line_count = result
        assert line_count == 1

    asyncio.run(run())


def test_filter_codes_filters_matching_status():
    """A response whose HTTP status code is in filter_codes should be suppressed."""
    async def run():
        from vortex.fuzzer import fetch_directory
        import aiohttp

        mock_session = _make_get_mock(403, b"Forbidden")
        sem = asyncio.Semaphore(1)
        timeout_obj = aiohttp.ClientTimeout(total=5)
        result = await fetch_directory(
            'http://example.com/path',
            mock_session,
            sem,
            client_timeout=timeout_obj,
            filter_codes={403},
        )
        assert result is None

    asyncio.run(run())


def test_filter_codes_passes_non_matching_status():
    """A response whose HTTP status code is NOT in filter_codes should pass through."""
    async def run():
        from vortex.fuzzer import fetch_directory
        import aiohttp

        mock_session = _make_get_mock(200, b"OK page")
        sem = asyncio.Semaphore(1)
        timeout_obj = aiohttp.ClientTimeout(total=5)
        result = await fetch_directory(
            'http://example.com/path',
            mock_session,
            sem,
            client_timeout=timeout_obj,
            filter_codes={403, 404},
        )
        assert result is not None
        url, status, body_size, word_count, line_count = result
        assert status == 200

    asyncio.run(run())


def test_multiple_filters_any_match_excludes():
    """If ANY active filter matches, the response is excluded (OR logic across filter types)."""
    async def run():
        from vortex.fuzzer import fetch_directory
        import aiohttp

        # 3-word body — filter_words matches but filter_size does not.
        body = b"one two three"
        mock_session = _make_get_mock(200, body)
        sem = asyncio.Semaphore(1)
        timeout_obj = aiohttp.ClientTimeout(total=5)
        result = await fetch_directory(
            'http://example.com/path',
            mock_session,
            sem,
            client_timeout=timeout_obj,
            filter_size={99999},    # does NOT match
            filter_words={3},       # DOES match → should exclude
        )
        assert result is None

    asyncio.run(run())


def test_auto_calibrate_returns_filter_values():
    """_auto_calibrate() should return size/words/lines sets when probes are consistent."""
    async def run():
        from vortex.fuzzer import _auto_calibrate
        import aiohttp

        # Consistent body across all 3 probes.
        body = b"word1 word2 word3\nline2\nline3"
        mock_resp = AsyncMock()
        mock_resp.status = 200
        mock_resp.read = AsyncMock(return_value=body)
        mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_resp.__aexit__ = AsyncMock(return_value=False)

        mock_session = MagicMock()
        mock_session.get = MagicMock(return_value=mock_resp)

        timeout_obj = aiohttp.ClientTimeout(total=5)
        result = await _auto_calibrate(
            mock_session, 'http://example.com', timeout_obj
        )
        assert result is not None
        assert "sizes" in result
        assert "words" in result
        assert "lines" in result
        assert len(result["sizes"]) == 1
        assert len(body) in result["sizes"]

    asyncio.run(run())


def test_auto_calibrate_returns_none_on_non_200():
    """_auto_calibrate() should return None if any probe returns non-200."""
    async def run():
        from vortex.fuzzer import _auto_calibrate
        import aiohttp

        mock_resp = AsyncMock()
        mock_resp.status = 404
        mock_resp.read = AsyncMock(return_value=b"Not Found")
        mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_resp.__aexit__ = AsyncMock(return_value=False)

        mock_session = MagicMock()
        mock_session.get = MagicMock(return_value=mock_resp)

        timeout_obj = aiohttp.ClientTimeout(total=5)
        result = await _auto_calibrate(
            mock_session, 'http://example.com', timeout_obj
        )
        assert result is None

    asyncio.run(run())

