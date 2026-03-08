"""Tests for vortex/sensitive_files.py."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch


def test_sensitive_paths_not_empty():
    """SENSITIVE_PATHS list should contain common paths."""
    from vortex.sensitive_files import SENSITIVE_PATHS
    assert len(SENSITIVE_PATHS) > 0
    assert "/.env" in SENSITIVE_PATHS
    assert "/.git/config" in SENSITIVE_PATHS


def test_sensitive_paths_fast_not_empty():
    """SENSITIVE_PATHS_FAST should contain a smaller set of critical paths."""
    from vortex.sensitive_files import SENSITIVE_PATHS, SENSITIVE_PATHS_FAST
    assert len(SENSITIVE_PATHS_FAST) > 0
    assert len(SENSITIVE_PATHS_FAST) < len(SENSITIVE_PATHS)
    assert "/.env" in SENSITIVE_PATHS_FAST
    assert "/.aws/credentials" in SENSITIVE_PATHS_FAST


def test_scan_sensitive_files_fast_mode_uses_reduced_paths():
    """In fast mode, scan_sensitive_files uses SENSITIVE_PATHS_FAST."""
    async def run():
        from vortex.sensitive_files import scan_sensitive_files, SENSITIVE_PATHS_FAST

        paths_checked = []

        resp = AsyncMock()
        resp.status = 404
        resp.headers = {"Content-Type": "text/plain"}
        resp.read = AsyncMock(return_value=b"Not Found")
        resp.__aenter__ = AsyncMock(return_value=resp)
        resp.__aexit__ = AsyncMock(return_value=False)

        def track_get(url, **kwargs):
            paths_checked.append(url)
            return resp

        mock_session = MagicMock()
        mock_session.get = MagicMock(side_effect=track_get)
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=False)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            with patch("aiohttp.TCPConnector", return_value=MagicMock()):
                await scan_sensitive_files(["https://example.com"], fast=True)

        assert len(paths_checked) == len(SENSITIVE_PATHS_FAST)

    asyncio.run(run())


def test_scan_sensitive_files_empty():
    """scan_sensitive_files with empty URL list returns empty findings."""
    async def run():
        from vortex.sensitive_files import scan_sensitive_files
        result = await scan_sensitive_files([])
        assert result == []

    asyncio.run(run())


def _make_mock_response(status=200, body=b"sensitive content here padded", headers=None):
    resp = AsyncMock()
    resp.status = status
    resp.headers = headers or {"Content-Type": "text/plain", "Content-Length": str(len(body))}
    resp.read = AsyncMock(return_value=body)
    resp.__aenter__ = AsyncMock(return_value=resp)
    resp.__aexit__ = AsyncMock(return_value=False)
    return resp


def test_scan_sensitive_files_finds_exposed_file():
    """A 200 response with meaningful content is reported as a finding."""
    async def run():
        from vortex.sensitive_files import scan_sensitive_files

        resp = _make_mock_response(
            status=200, body=b"DB_PASSWORD=secret123 and more text here"
        )
        mock_session = MagicMock()
        mock_session.get = MagicMock(return_value=resp)
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=False)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            with patch("aiohttp.TCPConnector", return_value=MagicMock()):
                result = await scan_sensitive_files(
                    ["https://example.com"],
                    paths=["/.env"],
                )

        assert len(result) == 1
        assert result[0]["status"] == 200
        assert result[0]["url"] == "https://example.com/.env"

    asyncio.run(run())


def test_scan_sensitive_files_ignores_404():
    """404 responses are not reported."""
    async def run():
        from vortex.sensitive_files import scan_sensitive_files

        resp = _make_mock_response(status=404, body=b"Not Found")
        mock_session = MagicMock()
        mock_session.get = MagicMock(return_value=resp)
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=False)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            with patch("aiohttp.TCPConnector", return_value=MagicMock()):
                result = await scan_sensitive_files(
                    ["https://example.com"],
                    paths=["/.env"],
                )

        assert result == []

    asyncio.run(run())


def test_scan_sensitive_files_output_file(tmp_path):
    """Findings are written to an output file."""
    async def run():
        from vortex.sensitive_files import scan_sensitive_files
        out = tmp_path / "sensitive.txt"

        resp = _make_mock_response(
            status=200, body=b"SECRET_KEY=abc123 padded content"
        )
        mock_session = MagicMock()
        mock_session.get = MagicMock(return_value=resp)
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=False)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            with patch("aiohttp.TCPConnector", return_value=MagicMock()):
                await scan_sensitive_files(
                    ["https://example.com"],
                    paths=["/.env"],
                    output_file=str(out),
                )

        assert out.exists()
        assert "200" in out.read_text()

    asyncio.run(run())
