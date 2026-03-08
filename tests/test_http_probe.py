"""Tests for vortex/http_probe.py."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

from vortex.http_probe import _normalise_target, probe_alive


# ---------------------------------------------------------------------------
# Unit tests for _normalise_target helper
# ---------------------------------------------------------------------------


def test_normalise_bare_hostname():
    assert _normalise_target("sub.example.com") == "sub.example.com"


def test_normalise_https_url():
    assert _normalise_target("https://sub.example.com") == "sub.example.com"


def test_normalise_http_url_with_path():
    assert _normalise_target("http://sub.example.com/some/path") == "sub.example.com"


def test_normalise_url_with_port():
    assert _normalise_target("https://sub.example.com:8443/path") == "sub.example.com"


def test_normalise_bare_hostname_with_port():
    assert _normalise_target("sub.example.com:8080") == "sub.example.com"


def test_normalise_ipv6():
    assert _normalise_target("[::1]") == "::1"


# ---------------------------------------------------------------------------
# Tests for probe_alive
# ---------------------------------------------------------------------------


def _make_mock_response(status: int, content_length: int | None = None):
    """Build a fake aiohttp response mock."""
    resp = AsyncMock()
    resp.status = status
    headers = {}
    if content_length is not None:
        headers["Content-Length"] = str(content_length)
    resp.headers = headers
    resp.__aenter__ = AsyncMock(return_value=resp)
    resp.__aexit__ = AsyncMock(return_value=False)
    return resp


def test_probe_alive_empty_returns_empty():
    result = asyncio.run(probe_alive([]))
    assert result == []


def test_probe_alive_returns_live_hosts():
    """Hosts that respond with any HTTP status should be returned."""

    async def run():
        import vortex.http_probe as hp

        call_count = [0]

        async def fake_probe_one(session, target, sem, timeout, proxy, random_ua):
            call_count[0] += 1
            # Unique content_length per host so wildcard detection doesn't fire
            return (f"https://{_normalise_target(target)}", 200, call_count[0])

        with patch.object(hp, "_probe_one", side_effect=fake_probe_one):
            live = await probe_alive(
                ["sub.example.com", "other.example.com"],
                max_threads=2,
                timeout=2.0,
            )
        # Both targets should be alive
        assert len(live) == 2
        assert all("://" in url for url in live)

    asyncio.run(run())


def test_probe_alive_filters_dead_hosts():
    """Hosts that raise connection errors should NOT be returned."""
    import aiohttp

    async def run():
        with patch(
            "aiohttp.ClientSession.request",
            side_effect=aiohttp.ClientConnectorError(
                connection_key=MagicMock(), os_error=OSError("refused")
            ),
        ):
            live = await probe_alive(
                ["dead.example.com"],
                max_threads=1,
                timeout=1.0,
            )
        assert live == []

    asyncio.run(run())


def test_probe_alive_wildcard_detection():
    """When >75 % of hosts share the same (status, content-length), all but
    one should be filtered out."""

    async def run():
        # 10 hosts all respond with 200 + length=500 → wildcard
        targets = [f"host{i}.example.com" for i in range(10)]
        mock_resp = _make_mock_response(200, 500)

        with patch("aiohttp.ClientSession.request", return_value=mock_resp):
            live = await probe_alive(targets, max_threads=5, timeout=2.0)

        # After wildcard dedup only 1 representative should remain
        assert len(live) == 1

    asyncio.run(run())


def test_probe_alive_max_targets_cap():
    """When more live hosts than max_targets are found, the list should be
    truncated to max_targets."""

    async def run():
        targets = [f"host{i}.example.com" for i in range(20)]
        # Each host gets a unique content-length so no wildcard filtering
        call_count = [0]

        import vortex.http_probe as hp

        async def fake_probe_one(session, target, sem, timeout, proxy, random_ua):
            call_count[0] += 1
            # Unique content_length per host to avoid wildcard dedup
            return (f"https://{_normalise_target(target)}", 200, call_count[0])

        with patch.object(hp, "_probe_one", side_effect=fake_probe_one):
            live = await probe_alive(targets, max_threads=5, timeout=2.0, max_targets=5)

        assert len(live) == 5

    asyncio.run(run())


def test_probe_alive_skip_via_full_recon():
    """When 'probe' is in skip_modules, probe_alive should not be called."""

    async def run():
        from vortex import full_recon as fr

        _probe = AsyncMock(return_value=[])

        with (
            patch("vortex.dns_records.dns_enum", AsyncMock(return_value={})),
            patch("vortex.ssl_analysis.ssl_check", AsyncMock(return_value={})),
            patch("vortex.port_scanner.port_scan", AsyncMock(return_value={"open_ports": []})),
            patch(
                "vortex.subdomain.enumerate_subdomains",
                AsyncMock(return_value=["sub.example.com"]),
            ),
            patch("vortex.fuzzer.directory_fuzzing", AsyncMock(return_value=[])),
            patch("vortex.tech_fingerprinting.fingerprint_technologies", AsyncMock(return_value={})),
            patch("vortex.crawler.crawl_domain", AsyncMock(return_value=None)),
            patch("vortex.js_discovery.discover_js_links", AsyncMock(return_value=None)),
            patch("vortex.email_harvester.harvest_emails", AsyncMock(return_value=[])),
            patch("vortex.param_fuzzer.parameter_discovery", AsyncMock(return_value=None)),
            patch("vortex.http_probe.probe_alive", _probe),
        ):
            await fr.run_full_recon(
                targets=["https://example.com"],
                domain="example.com",
                wordlist="/tmp/fake_wordlist.txt",
                threads=5,
                output=None,
                depth=1,
                method="GET",
                headers={},
                output_format="txt",
                proxy=None,
                rate_limit=None,
                random_ua=False,
                timeout=5,
                verbose=False,
                skip="probe",
            )

        _probe.assert_not_awaited()

    asyncio.run(run())


def test_probe_results_in_summary():
    """run_full_recon summary should contain probed_alive and probed_filtered."""

    async def run():
        from vortex import full_recon as fr

        with (
            patch("vortex.dns_records.dns_enum", AsyncMock(return_value={})),
            patch("vortex.ssl_analysis.ssl_check", AsyncMock(return_value={})),
            patch("vortex.port_scanner.port_scan", AsyncMock(return_value={"open_ports": []})),
            patch(
                "vortex.subdomain.enumerate_subdomains",
                AsyncMock(return_value=["sub.example.com", "dead.example.com"]),
            ),
            patch("vortex.fuzzer.directory_fuzzing", AsyncMock(return_value=[])),
            patch("vortex.tech_fingerprinting.fingerprint_technologies", AsyncMock(return_value={})),
            patch("vortex.crawler.crawl_domain", AsyncMock(return_value=None)),
            patch("vortex.js_discovery.discover_js_links", AsyncMock(return_value=None)),
            patch("vortex.email_harvester.harvest_emails", AsyncMock(return_value=[])),
            patch("vortex.param_fuzzer.parameter_discovery", AsyncMock(return_value=None)),
            patch(
                "vortex.http_probe.probe_alive",
                AsyncMock(return_value=["https://sub.example.com"]),
            ),
        ):
            result = await fr.run_full_recon(
                targets=["https://example.com"],
                domain="example.com",
                wordlist="/tmp/fake_wordlist.txt",
                threads=5,
                output=None,
                depth=1,
                method="GET",
                headers={},
                output_format="txt",
                proxy=None,
                rate_limit=None,
                random_ua=False,
                timeout=5,
                verbose=False,
            )

        assert "probe" in result
        assert result["probe"]["alive"] == 1
        assert result["probe"]["filtered"] == 1
        assert result["probe"]["total_probed"] == 2

    asyncio.run(run())
