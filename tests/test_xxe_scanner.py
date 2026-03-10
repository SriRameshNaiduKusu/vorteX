"""Tests for vortex/xxe_scanner.py."""

import asyncio
import os
from unittest.mock import AsyncMock, MagicMock, patch

from vortex.xxe_scanner import scan_xxe, _check_xxe_response


# ── _check_xxe_response ───────────────────────────────────────────────────────

def test_xxe_file_disclosure_detected():
    """root:x:0:0 in response body → CRITICAL severity."""
    severity, evidence = _check_xxe_response("root:x:0:0:root:/root:/bin/bash\n")
    assert severity == "CRITICAL"
    assert "/etc/passwd" in evidence


def test_xxe_xml_error_detected():
    """XML parser error string in body → HIGH severity."""
    severity, evidence = _check_xxe_response("SAXParseException: mismatched tag")
    assert severity == "HIGH"
    assert "SAXParseException" in evidence


def test_xxe_no_vulnerability():
    """Clean response body → no finding."""
    severity, evidence = _check_xxe_response("<html><p>Hello World</p></html>")
    assert severity == ""
    assert evidence == ""


def test_xxe_aws_metadata_detected():
    """ami-id in body → CRITICAL (AWS metadata)."""
    severity, evidence = _check_xxe_response("ami-id: ami-0abcdef1234567890")
    assert severity == "CRITICAL"
    assert "AWS metadata" in evidence


def test_xxe_xml_error_entity():
    """DOCTYPE in body → HIGH severity."""
    severity, evidence = _check_xxe_response("Error: DOCTYPE not allowed")
    assert severity == "HIGH"


# ── scan_xxe ──────────────────────────────────────────────────────────────────

def _make_mock_post_response(body: str, status: int = 200):
    resp = AsyncMock()
    resp.status = status
    resp.text = AsyncMock(return_value=body)
    resp.__aenter__ = AsyncMock(return_value=resp)
    resp.__aexit__ = AsyncMock(return_value=False)
    return resp


def test_scan_xxe_empty_urls():
    """Empty URL list returns empty."""
    results = asyncio.run(scan_xxe([]))
    assert results == []


def test_scan_xxe_detects_file_disclosure():
    """Integration test: POST response with /etc/passwd content → CRITICAL finding."""
    passwd_body = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1"
    mock_resp = _make_mock_post_response(passwd_body)

    mock_session = MagicMock()
    mock_session.post = MagicMock(return_value=mock_resp)
    # GET should return clean body so finding comes from POST
    mock_get_resp = _make_mock_post_response("<html>OK</html>")
    mock_session.get = MagicMock(return_value=mock_get_resp)
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=False)

    with patch("vortex.xxe_scanner.aiohttp.ClientSession", return_value=mock_session):
        results = asyncio.run(scan_xxe(
            ["http://example.com/api/xml"],
            fast=True,
        ))

    assert len(results) >= 1
    assert results[0]["severity"] == "CRITICAL"
    assert results[0]["method"] == "POST"


def test_scan_xxe_xml_error_detected():
    """Integration test: POST response with XML error → HIGH finding."""
    xml_error_body = "SAXParseException: content is not allowed in prolog"
    mock_resp = _make_mock_post_response(xml_error_body)

    mock_session = MagicMock()
    mock_session.post = MagicMock(return_value=mock_resp)
    mock_session.get = MagicMock(return_value=_make_mock_post_response("<html>OK</html>"))
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=False)

    with patch("vortex.xxe_scanner.aiohttp.ClientSession", return_value=mock_session):
        results = asyncio.run(scan_xxe(
            ["http://example.com/api/xml"],
            fast=True,
        ))

    assert len(results) >= 1
    assert results[0]["severity"] == "HIGH"


def test_scan_xxe_no_vulnerability():
    """Clean POST response → no findings."""
    mock_resp = _make_mock_post_response("<response><status>ok</status></response>")

    mock_session = MagicMock()
    mock_session.post = MagicMock(return_value=mock_resp)
    mock_session.get = MagicMock(return_value=_make_mock_post_response("<html>OK</html>"))
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=False)

    with patch("vortex.xxe_scanner.aiohttp.ClientSession", return_value=mock_session):
        results = asyncio.run(scan_xxe(
            ["http://example.com/api/xml"],
            fast=True,
        ))

    assert results == []


def test_scan_xxe_output_file(tmp_path):
    """Output file is written when findings exist."""
    passwd_body = "root:x:0:0:root:/root:/bin/bash"
    mock_resp = _make_mock_post_response(passwd_body)

    mock_session = MagicMock()
    mock_session.post = MagicMock(return_value=mock_resp)
    mock_session.get = MagicMock(return_value=_make_mock_post_response("<html>OK</html>"))
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=False)

    out_file = str(tmp_path / "xxe_results.txt")
    with patch("vortex.xxe_scanner.aiohttp.ClientSession", return_value=mock_session):
        results = asyncio.run(scan_xxe(
            ["http://example.com/api/xml"],
            output_file=out_file,
            fast=True,
        ))

    if results:
        assert os.path.isfile(out_file)
