"""Tests for vortex/takeover.py."""

import asyncio
from unittest.mock import AsyncMock, patch


def test_takeover_fingerprints_not_empty():
    """TAKEOVER_FINGERPRINTS list should be non-empty."""
    from vortex.takeover import TAKEOVER_FINGERPRINTS
    assert len(TAKEOVER_FINGERPRINTS) > 0


def test_takeover_fingerprints_structure():
    """Each fingerprint entry should be a 3-tuple."""
    from vortex.takeover import TAKEOVER_FINGERPRINTS
    for entry in TAKEOVER_FINGERPRINTS:
        assert len(entry) == 3, f"Expected 3-tuple, got: {entry}"
        cname_kw, service, body_fp = entry
        assert isinstance(cname_kw, str)
        assert isinstance(service, str)
        assert body_fp is None or isinstance(body_fp, str)


def test_check_takeover_empty_list():
    """check_takeover with an empty list returns empty results."""
    async def run():
        from vortex.takeover import check_takeover
        results = await check_takeover([])
        assert results == []

    asyncio.run(run())


def test_check_takeover_no_cname_match():
    """Subdomains with no CNAME match should produce no findings."""
    async def run():
        from vortex.takeover import check_takeover

        with patch("vortex.takeover._resolve_cname", new=AsyncMock(return_value="safe.example.com")):
            results = await check_takeover(["sub.example.com"])
        assert results == []

    asyncio.run(run())


def test_check_takeover_cname_match_with_body():
    """A matching CNAME with confirmed body fingerprint produces a HIGH finding."""
    async def run():
        from vortex.takeover import check_takeover

        async def fake_resolve(subdomain, resolver):
            return "target.github.io"

        async def fake_fetch(session, url, proxy=None, timeout=10):
            return "There isn't a GitHub Pages site here"

        with (
            patch("vortex.takeover._resolve_cname", side_effect=fake_resolve),
            patch("vortex.takeover._fetch_body", side_effect=fake_fetch),
        ):
            results = await check_takeover(["vulnerable.example.com"])

        assert len(results) == 1
        assert results[0]["service"] == "GitHub Pages"
        assert results[0]["severity"] == "HIGH"

    asyncio.run(run())


def test_check_takeover_output_file_txt(tmp_path):
    """Findings are written to a txt output file."""
    async def run():
        from vortex.takeover import check_takeover
        out = tmp_path / "takeover.txt"

        async def fake_resolve(subdomain, resolver):
            return "old.herokudns.com"

        async def fake_fetch(session, url, proxy=None, timeout=10):
            return "No such app"

        with (
            patch("vortex.takeover._resolve_cname", side_effect=fake_resolve),
            patch("vortex.takeover._fetch_body", side_effect=fake_fetch),
        ):
            await check_takeover(["sub.example.com"], output_file=str(out), output_format="txt")

        assert out.exists()
        content = out.read_text()
        assert "Heroku" in content

    asyncio.run(run())
