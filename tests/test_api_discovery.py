"""Tests for vortex/api_discovery.py."""

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch


def test_api_paths_not_empty():
    """API_PATHS list should contain common API paths."""
    from vortex.api_discovery import API_PATHS
    assert "/api/" in API_PATHS
    assert "/graphql" in API_PATHS
    assert "/swagger.json" in API_PATHS


def test_discover_api_endpoints_empty():
    """discover_api_endpoints with empty URL list returns empty results."""
    async def run():
        from vortex.api_discovery import discover_api_endpoints
        result = await discover_api_endpoints([])
        assert result["found_endpoints"] == []

    asyncio.run(run())


def _make_mock_response(status=200, body="", content_type="application/json"):
    resp = AsyncMock()
    resp.status = status
    resp.headers = {"Content-Type": content_type}
    resp.text = AsyncMock(return_value=body)
    resp.__aenter__ = AsyncMock(return_value=resp)
    resp.__aexit__ = AsyncMock(return_value=False)
    return resp


def test_discover_api_endpoints_finds_endpoint():
    """A 200 response on /api/v1/ is reported as a found endpoint."""
    async def run():
        from vortex.api_discovery import discover_api_endpoints

        resp_ok = _make_mock_response(status=200, body='{"status":"ok"}')
        resp_404 = _make_mock_response(status=404, body="Not Found")

        def response_for(*args, **kwargs):
            # Only /api/v1/ returns 200
            url = args[0] if args else ""
            if "/api/v1/" in str(url):
                return resp_ok
            return resp_404

        mock_session = MagicMock()
        mock_session.get = MagicMock(side_effect=response_for)
        mock_session.post = MagicMock(return_value=resp_404)
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=False)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            with patch("aiohttp.TCPConnector", return_value=MagicMock()):
                result = await discover_api_endpoints(["https://example.com"])

        endpoints = result["found_endpoints"]
        found_urls = [ep["url"] for ep in endpoints]
        assert any("/api/v1/" in u for u in found_urls)

    asyncio.run(run())


def test_discover_api_endpoints_output_file_json(tmp_path):
    """Results are written to a JSON output file."""
    async def run():
        from vortex.api_discovery import discover_api_endpoints
        out = tmp_path / "api.json"

        resp_ok = _make_mock_response(status=200, body='{"endpoints":[]}')
        resp_404 = _make_mock_response(status=404, body="Not Found")

        def response_for(*args, **kwargs):
            url = args[0] if args else ""
            if "/graphql" in str(url):
                return resp_ok
            return resp_404

        mock_session = MagicMock()
        mock_session.get = MagicMock(side_effect=response_for)
        mock_session.post = MagicMock(return_value=resp_404)
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=False)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            with patch("aiohttp.TCPConnector", return_value=MagicMock()):
                await discover_api_endpoints(
                    ["https://example.com"],
                    output_file=str(out),
                    output_format="json",
                )

        assert out.exists()
        data = json.loads(out.read_text())
        assert "found_endpoints" in data

    asyncio.run(run())


def test_discover_api_endpoints_no_findings():
    """When nothing responds with 200, found_endpoints is empty."""
    async def run():
        from vortex.api_discovery import discover_api_endpoints

        resp = _make_mock_response(status=404, body="Not Found")
        mock_session = MagicMock()
        mock_session.get = MagicMock(return_value=resp)
        mock_session.post = MagicMock(return_value=resp)
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=False)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            with patch("aiohttp.TCPConnector", return_value=MagicMock()):
                result = await discover_api_endpoints(["https://example.com"])

        assert result["found_endpoints"] == []

    asyncio.run(run())
