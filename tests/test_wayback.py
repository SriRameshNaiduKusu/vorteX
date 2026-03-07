"""Tests for vortex/wayback.py."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch


def test_wayback_enum_success():
    """wayback_enum returns filtered URLs from CDX API."""
    async def run():
        from vortex.wayback import wayback_enum

        # CDX returns header row + data rows
        fake_data = [
            ["original"],  # header
            ["https://example.com/app.js"],
            ["https://example.com/config.php"],
            ["https://example.com/about"],  # no interesting extension — filtered
            ["https://example.com/app.js"],  # duplicate — filtered
        ]

        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.json = AsyncMock(return_value=fake_data)
        mock_response.__aenter__ = AsyncMock(return_value=mock_response)
        mock_response.__aexit__ = AsyncMock(return_value=False)

        mock_session = MagicMock()
        mock_session.get = MagicMock(return_value=mock_response)
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=False)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            with patch("aiohttp.TCPConnector", return_value=MagicMock()):
                result = await wayback_enum("example.com")

        assert "https://example.com/app.js" in result
        assert "https://example.com/config.php" in result
        # Non-interesting extension filtered by default
        assert "https://example.com/about" not in result
        # No duplicates
        assert result.count("https://example.com/app.js") == 1

    asyncio.run(run())


def test_wayback_enum_empty_extensions():
    """wayback_enum with filter_extensions=set() returns all unique URLs."""
    async def run():
        from vortex.wayback import wayback_enum

        fake_data = [
            ["original"],
            ["https://example.com/about"],
            ["https://example.com/contact"],
        ]

        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.json = AsyncMock(return_value=fake_data)
        mock_response.__aenter__ = AsyncMock(return_value=mock_response)
        mock_response.__aexit__ = AsyncMock(return_value=False)

        mock_session = MagicMock()
        mock_session.get = MagicMock(return_value=mock_response)
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=False)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            with patch("aiohttp.TCPConnector", return_value=MagicMock()):
                result = await wayback_enum("example.com", filter_extensions=set())

        assert "https://example.com/about" in result
        assert "https://example.com/contact" in result

    asyncio.run(run())


def test_wayback_enum_http_error():
    """wayback_enum returns empty list on non-200 response."""
    async def run():
        from vortex.wayback import wayback_enum

        mock_response = AsyncMock()
        mock_response.status = 500
        mock_response.__aenter__ = AsyncMock(return_value=mock_response)
        mock_response.__aexit__ = AsyncMock(return_value=False)

        mock_session = MagicMock()
        mock_session.get = MagicMock(return_value=mock_response)
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=False)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            with patch("aiohttp.TCPConnector", return_value=MagicMock()):
                result = await wayback_enum("example.com")

        assert result == []

    asyncio.run(run())


def test_wayback_enum_output_file(tmp_path):
    """wayback_enum writes results to output file."""
    async def run():
        from vortex.wayback import wayback_enum
        out = tmp_path / "wayback.txt"

        fake_data = [["original"], ["https://example.com/app.js"]]

        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.json = AsyncMock(return_value=fake_data)
        mock_response.__aenter__ = AsyncMock(return_value=mock_response)
        mock_response.__aexit__ = AsyncMock(return_value=False)

        mock_session = MagicMock()
        mock_session.get = MagicMock(return_value=mock_response)
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=False)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            with patch("aiohttp.TCPConnector", return_value=MagicMock()):
                await wayback_enum("example.com", output_file=str(out))

        assert out.exists()
        assert "app.js" in out.read_text()

    asyncio.run(run())
