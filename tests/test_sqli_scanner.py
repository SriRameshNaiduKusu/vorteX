"""Tests for vortex/sqli_scanner.py."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

from vortex.sqli_scanner import scan_sqli, _detect_sqli_error


# ── _detect_sqli_error ───────────────────────────────────────────────────────

def test_detect_sqli_error_mysql():
    body = "You have an error in your SQL syntax; check the manual"
    found, db = _detect_sqli_error(body)
    assert found is True
    assert db == "MySQL"


def test_detect_sqli_error_postgres():
    body = "pg_query() failed: unterminated quoted string at or near"
    found, db = _detect_sqli_error(body)
    assert found is True
    assert db == "PostgreSQL"


def test_detect_sqli_error_mssql():
    body = "Microsoft OLE DB Provider for ODBC Drivers error"
    found, db = _detect_sqli_error(body)
    assert found is True
    assert db == "MSSQL"


def test_detect_sqli_error_oracle():
    body = "ORA-00933: SQL command not properly ended"
    found, db = _detect_sqli_error(body)
    assert found is True
    assert db == "Oracle"


def test_detect_sqli_error_sqlite():
    body = "SQLite error: no such column"
    found, db = _detect_sqli_error(body)
    assert found is True
    assert db == "SQLite"


def test_detect_sqli_error_none():
    body = "<html><p>Normal page</p></html>"
    found, db = _detect_sqli_error(body)
    assert found is False
    assert db == ""


# ── scan_sqli ────────────────────────────────────────────────────────────────

def _make_mock_response(body: str, status: int = 200):
    resp = AsyncMock()
    resp.status = status
    resp.text = AsyncMock(return_value=body)
    resp.__aenter__ = AsyncMock(return_value=resp)
    resp.__aexit__ = AsyncMock(return_value=False)
    return resp


def test_scan_sqli_empty_urls():
    results = asyncio.run(scan_sqli([]))
    assert results == []


def test_scan_sqli_no_params():
    results = asyncio.run(scan_sqli(["http://example.com/page"]))
    assert results == []


def test_scan_sqli_detects_error_based():
    error_body = "You have an error in your SQL syntax near ''"
    mock_resp = _make_mock_response(error_body)

    mock_session = MagicMock()
    mock_session.get = MagicMock(return_value=mock_resp)
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=False)

    with patch("vortex.sqli_scanner.aiohttp.ClientSession", return_value=mock_session):
        results = asyncio.run(scan_sqli(
            ["http://example.com/item?id=1"],
            fast=True,
        ))

    assert any(f["parameter"] == "id" for f in results)
    assert all(f["type"] == "error-based" for f in results)


def test_scan_sqli_no_error_in_body():
    mock_resp = _make_mock_response("<html><p>Results: 42</p></html>")

    mock_session = MagicMock()
    mock_session.get = MagicMock(return_value=mock_resp)
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=False)

    with patch("vortex.sqli_scanner.aiohttp.ClientSession", return_value=mock_session):
        results = asyncio.run(scan_sqli(
            ["http://example.com/item?id=1"],
            fast=True,
        ))

    assert results == []


def test_scan_sqli_output_file(tmp_path):
    error_body = "You have an error in your SQL syntax near ''"
    mock_resp = _make_mock_response(error_body)

    mock_session = MagicMock()
    mock_session.get = MagicMock(return_value=mock_resp)
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=False)

    out_file = str(tmp_path / "sqli_results.txt")
    with patch("vortex.sqli_scanner.aiohttp.ClientSession", return_value=mock_session):
        results = asyncio.run(scan_sqli(
            ["http://example.com/item?id=1"],
            output_file=out_file,
            fast=True,
        ))

    if results:
        import os
        assert os.path.isfile(out_file)
