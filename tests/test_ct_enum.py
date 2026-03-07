"""Tests for vortex/ct_enum.py."""

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch


def test_extract_names_basic():
    """_extract_names strips wildcards and blank lines."""
    from vortex.ct_enum import _extract_names
    names = list(_extract_names("*.example.com\nsub.example.com\n"))
    assert "example.com" in names
    assert "sub.example.com" in names


def test_extract_names_multiline():
    """_extract_names handles multi-line name_value fields."""
    from vortex.ct_enum import _extract_names
    names = list(_extract_names("a.example.com\nb.example.com\n"))
    assert "a.example.com" in names
    assert "b.example.com" in names


def test_ct_search_success():
    """ct_search returns a sorted list of unique subdomains."""
    async def run():
        from vortex.ct_enum import ct_search

        fake_data = [
            {"name_value": "www.example.com\n*.example.com"},
            {"name_value": "api.example.com"},
            {"name_value": "www.example.com"},  # duplicate
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
                result = await ct_search("example.com")

        assert "www.example.com" in result
        assert "api.example.com" in result
        # Duplicates removed
        assert result.count("www.example.com") == 1

    asyncio.run(run())


def test_ct_search_http_error():
    """ct_search returns empty list on non-200 response."""
    async def run():
        from vortex.ct_enum import ct_search

        mock_response = AsyncMock()
        mock_response.status = 503
        mock_response.__aenter__ = AsyncMock(return_value=mock_response)
        mock_response.__aexit__ = AsyncMock(return_value=False)

        mock_session = MagicMock()
        mock_session.get = MagicMock(return_value=mock_response)
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=False)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            with patch("aiohttp.TCPConnector", return_value=MagicMock()):
                result = await ct_search("example.com")

        assert result == []

    asyncio.run(run())


def test_ct_search_output_file_json(tmp_path):
    """ct_search writes JSON output file correctly."""
    async def run():
        from vortex.ct_enum import ct_search
        out = tmp_path / "ct.json"

        fake_data = [{"name_value": "sub.example.com"}]

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
                await ct_search("example.com", output_file=str(out), output_format="json")

        assert out.exists()
        data = json.loads(out.read_text())
        assert isinstance(data, list)
        assert "sub.example.com" in data

    asyncio.run(run())
