"""Tests for vortex/header_audit.py."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch


def test_security_headers_not_empty():
    """SECURITY_HEADERS dict is non-empty."""
    from vortex.header_audit import SECURITY_HEADERS
    assert len(SECURITY_HEADERS) >= 10


def test_grade_all_present():
    """_grade returns 'A' when all headers present."""
    from vortex.header_audit import _grade, SECURITY_HEADERS
    assert _grade(len(SECURITY_HEADERS)) == "A"


def test_grade_none_present():
    """_grade returns 'F' when no headers are present."""
    from vortex.header_audit import _grade
    assert _grade(0) == "F"


def test_grade_partial():
    """_grade returns appropriate letter for partial coverage."""
    from vortex.header_audit import _grade, SECURITY_HEADERS
    total = len(SECURITY_HEADERS)
    # 70-89% → B
    assert _grade(int(total * 0.8)) in ("A", "B")
    # 50-69% → C
    assert _grade(int(total * 0.6)) in ("B", "C")


def test_audit_headers_empty():
    """audit_headers with empty URL list returns empty results."""
    async def run():
        from vortex.header_audit import audit_headers
        result = await audit_headers([])
        assert result == []

    asyncio.run(run())


def _make_mock_response(status=200, response_headers=None):
    resp = AsyncMock()
    resp.status = status
    resp.headers = response_headers or {}
    resp.__aenter__ = AsyncMock(return_value=resp)
    resp.__aexit__ = AsyncMock(return_value=False)
    return resp


def test_audit_headers_all_missing():
    """When no security headers are present, grade is F."""
    async def run():
        from vortex.header_audit import audit_headers

        resp = _make_mock_response(status=200, response_headers={"Content-Type": "text/html"})
        mock_session = MagicMock()
        mock_session.get = MagicMock(return_value=resp)
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=False)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            with patch("aiohttp.TCPConnector", return_value=MagicMock()):
                result = await audit_headers(["https://example.com"])

        assert len(result) == 1
        assert result[0]["grade"] == "F"
        assert len(result[0]["missing"]) > 0

    asyncio.run(run())


def test_audit_headers_all_present():
    """When all security headers are present, grade is A."""
    async def run():
        from vortex.header_audit import audit_headers, SECURITY_HEADERS

        # Provide all security headers in the response
        headers = {h: "value" for h in SECURITY_HEADERS}
        resp = _make_mock_response(status=200, response_headers=headers)
        mock_session = MagicMock()
        mock_session.get = MagicMock(return_value=resp)
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=False)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            with patch("aiohttp.TCPConnector", return_value=MagicMock()):
                result = await audit_headers(["https://example.com"])

        assert len(result) == 1
        assert result[0]["grade"] == "A"
        assert len(result[0]["present"]) == len(SECURITY_HEADERS)

    asyncio.run(run())


def test_audit_headers_output_file(tmp_path):
    """Results are written to output file."""
    async def run():
        from vortex.header_audit import audit_headers
        out = tmp_path / "headers.txt"

        resp = _make_mock_response(status=200, response_headers={"Content-Type": "text/html"})
        mock_session = MagicMock()
        mock_session.get = MagicMock(return_value=resp)
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=False)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            with patch("aiohttp.TCPConnector", return_value=MagicMock()):
                await audit_headers(["https://example.com"], output_file=str(out))

        assert out.exists()
        assert "example.com" in out.read_text()

    asyncio.run(run())
