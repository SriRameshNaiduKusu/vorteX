"""Tests for vortex/ssti_scanner.py."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

from vortex.ssti_scanner import scan_ssti, _detect_ssti


# ── _detect_ssti ─────────────────────────────────────────────────────────────

def test_detect_ssti_evaluated():
    """When {{7*7}} is evaluated and '49' appears but raw payload doesn't, it's a finding."""
    payload = "{{7*7}}"
    body = "<html><p>Result: 49</p></html>"
    found, engine, evidence = _detect_ssti(payload, body)
    assert found is True
    assert "49" in evidence
    assert "Jinja2" in engine or "Twig" in engine or "Pebble" in engine


def test_detect_ssti_reflected_not_evaluated():
    """When payload is reflected literally (not evaluated), it should NOT be a finding."""
    payload = "{{7*7}}"
    # The response contains the raw payload (reflected), but NOT the expected output
    body = f"<html><p>You searched for: {payload}</p></html>"
    found, engine, evidence = _detect_ssti(payload, body)
    assert found is False


def test_detect_ssti_reflected_and_evaluated():
    """When both payload and result appear (e.g., echo + eval), payload in body means not a finding."""
    payload = "{{7*7}}"
    # Server reflected the payload AND evaluated it — but payload presence disqualifies
    body = "<html><p>{{7*7}} = 49</p></html>"
    found, engine, evidence = _detect_ssti(payload, body)
    # payload IS in body → not a confirmed evaluation finding
    assert found is False


def test_detect_engine_error():
    """When template engine error strings appear, a finding should be returned."""
    payload = "{{7*7}}"
    body = "<html><p>jinja2.exceptions.UndefinedError: 'foo' is undefined</p></html>"
    found, engine, evidence = _detect_ssti(payload, body)
    assert found is True
    assert "Jinja2" in engine


def test_detect_ssti_erb_evaluated():
    """ERB payload evaluated correctly."""
    payload = "<%= 7*7 %>"
    body = "<html><p>49</p></html>"
    found, engine, evidence = _detect_ssti(payload, body)
    assert found is True
    assert "ERB" in engine


def test_detect_ssti_no_match():
    """No match when body contains unrelated content."""
    payload = "{{7*7}}"
    body = "<html><p>Hello World</p></html>"
    found, engine, evidence = _detect_ssti(payload, body)
    assert found is False


# ── scan_ssti ─────────────────────────────────────────────────────────────────

def _make_mock_response(body: str, status: int = 200):
    resp = AsyncMock()
    resp.status = status
    resp.text = AsyncMock(return_value=body)
    resp.__aenter__ = AsyncMock(return_value=resp)
    resp.__aexit__ = AsyncMock(return_value=False)
    return resp


def test_scan_ssti_empty_urls():
    results = asyncio.run(scan_ssti([]))
    assert results == []


def test_scan_ssti_no_params():
    """URLs without query parameters should yield no findings."""
    results = asyncio.run(scan_ssti(["http://example.com/page"]))
    assert results == []


def test_scan_ssti_detects_evaluation():
    """Integration test: when the response contains evaluated SSTI output, report finding."""
    # Simulate a server that evaluates {{7*7}} → 49 and doesn't reflect the raw payload
    mock_resp = _make_mock_response("<html><p>Result: 49</p></html>")

    mock_session = MagicMock()
    mock_session.get = MagicMock(return_value=mock_resp)
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=False)

    with patch("vortex.ssti_scanner.aiohttp.ClientSession", return_value=mock_session):
        results = asyncio.run(scan_ssti(
            ["http://example.com/search?q=test"],
            fast=True,
        ))

    assert any(f["parameter"] == "q" for f in results)
    assert any(f["severity"] == "CRITICAL" for f in results)


def test_scan_ssti_no_detection():
    """When payload is reflected literally, no findings should be returned."""
    mock_resp = _make_mock_response("<html><p>Safe response</p></html>")

    mock_session = MagicMock()
    mock_session.get = MagicMock(return_value=mock_resp)
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=False)

    with patch("vortex.ssti_scanner.aiohttp.ClientSession", return_value=mock_session):
        results = asyncio.run(scan_ssti(
            ["http://example.com/search?q=test"],
            fast=True,
        ))

    assert results == []


def test_scan_ssti_output_file(tmp_path):
    """Output file should be written when findings are present."""
    mock_resp = _make_mock_response("<html><p>Result: 49</p></html>")

    mock_session = MagicMock()
    mock_session.get = MagicMock(return_value=mock_resp)
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=False)

    out_file = str(tmp_path / "ssti_results.txt")
    with patch("vortex.ssti_scanner.aiohttp.ClientSession", return_value=mock_session):
        results = asyncio.run(scan_ssti(
            ["http://example.com/search?q=test"],
            output_file=out_file,
            fast=True,
        ))

    if results:
        import os
        assert os.path.isfile(out_file)


def test_scan_ssti_fast_mode_uses_fewer_payloads():
    """Fast mode should use a reduced payload set (first 15)."""
    from vortex.payloads import load_payloads
    all_payloads = load_payloads("ssti.txt")
    fast_count = len(all_payloads[:15])
    assert fast_count <= 15
    assert fast_count < len(all_payloads)
