import argparse
import asyncio
import json
import os
import tempfile
from unittest.mock import AsyncMock, patch


# ---------------------------------------------------------------------------
# Helper: build a minimal parser with the -all flag (mirrors main.py)
# ---------------------------------------------------------------------------

def _build_parser():

    parser = argparse.ArgumentParser()
    parser.add_argument("-all", "--all", action="store_true")
    parser.add_argument("-d", "--domain")
    parser.add_argument("-url", "--target")
    parser.add_argument("-w", "--wordlist")
    parser.add_argument("-T", "--threads", type=int, default=20)
    parser.add_argument("-o", "--output")
    parser.add_argument("--depth", type=int, default=2)
    parser.add_argument("--method", choices=["GET", "POST"], default="GET")
    parser.add_argument("--headers", nargs="*", default=[])
    parser.add_argument("--format", choices=["json", "txt"], default="txt")
    parser.add_argument("--proxy")
    parser.add_argument("--rate-limit", type=float)
    parser.add_argument("--random-ua", action="store_true")
    parser.add_argument("--timeout", type=float, default=10)
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("--fast", action="store_true")
    parser.add_argument("--skip", default="")
    return parser


# ---------------------------------------------------------------------------
# Test: CLI parser recognises the -all flag
# ---------------------------------------------------------------------------

def test_all_flag_recognised():
    parser = _build_parser()
    args = parser.parse_args(["-all", "-url", "https://example.com"])
    assert args.all is True


def test_all_flag_default_false():
    parser = _build_parser()
    args = parser.parse_args(["-url", "https://example.com"])
    assert args.all is False


# ---------------------------------------------------------------------------
# Test: run_full_recon calls all modules
# ---------------------------------------------------------------------------

def test_run_full_recon_calls_all_modules():
    """Each module coroutine should be awaited exactly once (dns via domain)."""

    async def run():
        from vortex import full_recon as fr

        _dns = AsyncMock(return_value={"A": ["1.2.3.4"]})
        _ssl = AsyncMock(return_value={"host": "example.com"})
        _ports = AsyncMock(return_value={"open_ports": [80]})
        _subdomains = AsyncMock(return_value=["https://sub.example.com"])
        _fuzz = AsyncMock(return_value=["https://example.com/admin"])
        _tech = AsyncMock(return_value={"https://example.com": ["nginx"]})
        _crawl = AsyncMock(return_value=None)
        _js = AsyncMock(return_value=None)
        _emails = AsyncMock(return_value=["admin@example.com"])
        _params = AsyncMock(return_value=None)

        with (
            patch.object(fr, "run_full_recon", wraps=fr.run_full_recon),
            patch("vortex.dns_records.dns_enum", _dns),
            patch("vortex.ssl_analysis.ssl_check", _ssl),
            patch("vortex.port_scanner.port_scan", _ports),
            patch("vortex.subdomain.enumerate_subdomains", _subdomains),
            patch("vortex.fuzzer.directory_fuzzing", _fuzz),
            patch("vortex.tech_fingerprinting.fingerprint_technologies", _tech),
            patch("vortex.crawler.crawl_domain", _crawl),
            patch("vortex.js_discovery.discover_js_links", _js),
            patch("vortex.email_harvester.harvest_emails", _emails),
            patch("vortex.param_fuzzer.parameter_discovery", _params),
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

        _dns.assert_awaited_once()
        _ssl.assert_awaited_once()
        _ports.assert_awaited_once()
        _subdomains.assert_awaited_once()
        _fuzz.assert_awaited_once()
        _tech.assert_awaited_once()
        _crawl.assert_awaited_once()
        _js.assert_awaited_once()
        _emails.assert_awaited_once()
        _params.assert_awaited_once()

        assert "dns" in result
        assert "subdomains" in result
        assert "emails" in result

    asyncio.run(run())


# ---------------------------------------------------------------------------
# Test: module failures don't crash the pipeline
# ---------------------------------------------------------------------------

def test_module_failure_does_not_abort():
    """If every module raises, run_full_recon should still return without raising."""

    async def run():
        from vortex import full_recon as fr

        boom = AsyncMock(side_effect=RuntimeError("boom"))

        with (
            patch("vortex.dns_records.dns_enum", boom),
            patch("vortex.ssl_analysis.ssl_check", boom),
            patch("vortex.port_scanner.port_scan", boom),
            patch("vortex.subdomain.enumerate_subdomains", boom),
            patch("vortex.fuzzer.directory_fuzzing", boom),
            patch("vortex.tech_fingerprinting.fingerprint_technologies", boom),
            patch("vortex.crawler.crawl_domain", boom),
            patch("vortex.js_discovery.discover_js_links", boom),
            patch("vortex.email_harvester.harvest_emails", boom),
            patch("vortex.param_fuzzer.parameter_discovery", boom),
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
        # Should return a dict even when all modules fail
        assert isinstance(result, dict)

    asyncio.run(run())


# ---------------------------------------------------------------------------
# Test: consolidated JSON report is valid
# ---------------------------------------------------------------------------

def test_consolidated_json_report():
    """When -o + --format json are given, a valid JSON file should be written."""

    async def run():
        from vortex import full_recon as fr

        with (
            patch("vortex.dns_records.dns_enum", AsyncMock(return_value={"A": ["1.2.3.4"]})),
            patch("vortex.ssl_analysis.ssl_check", AsyncMock(return_value={"host": "example.com"})),
            patch("vortex.port_scanner.port_scan", AsyncMock(return_value={"open_ports": [80]})),
            patch("vortex.subdomain.enumerate_subdomains", AsyncMock(return_value=[])),
            patch("vortex.fuzzer.directory_fuzzing", AsyncMock(return_value=[])),
            patch("vortex.tech_fingerprinting.fingerprint_technologies", AsyncMock(return_value={})),
            patch("vortex.crawler.crawl_domain", AsyncMock(return_value=None)),
            patch("vortex.js_discovery.discover_js_links", AsyncMock(return_value=None)),
            patch("vortex.email_harvester.harvest_emails", AsyncMock(return_value=[])),
            patch("vortex.param_fuzzer.parameter_discovery", AsyncMock(return_value=None)),
        ):
            with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
                tmp_path = tmp.name

            try:
                await fr.run_full_recon(
                    targets=["https://example.com"],
                    domain="example.com",
                    wordlist="/tmp/fake_wordlist.txt",
                    threads=5,
                    output=tmp_path,
                    depth=1,
                    method="GET",
                    headers={},
                    output_format="json",
                    proxy=None,
                    rate_limit=None,
                    random_ua=False,
                    timeout=5,
                    verbose=False,
                )
                with open(tmp_path) as f:
                    report = json.load(f)

                assert "target" in report
                assert "scan_date" in report
                assert "phases" in report
                assert "summary" in report
                assert "dns" in report["phases"]
                assert "subdomains" in report["phases"]
                assert "emails" in report["phases"]
            finally:
                os.unlink(tmp_path)

    asyncio.run(run())


# ---------------------------------------------------------------------------
# Test: wordlist-dependent modules now use defaults when no wordlist provided
# ---------------------------------------------------------------------------

def test_wordlist_dependent_modules_use_defaults_without_wordlist():
    """With no user wordlist, subdomain enum, fuzzing, and paramfuzz should
    still be called using the built-in default wordlists (not skipped)."""

    async def run():
        from vortex import full_recon as fr

        _subdomains = AsyncMock(return_value=[])
        _fuzz = AsyncMock(return_value=[])
        _params = AsyncMock(return_value=None)

        with (
            patch("vortex.dns_records.dns_enum", AsyncMock(return_value={})),
            patch("vortex.ssl_analysis.ssl_check", AsyncMock(return_value={})),
            patch("vortex.port_scanner.port_scan", AsyncMock(return_value={"open_ports": []})),
            patch("vortex.subdomain.enumerate_subdomains", _subdomains),
            patch("vortex.fuzzer.directory_fuzzing", _fuzz),
            patch("vortex.tech_fingerprinting.fingerprint_technologies", AsyncMock(return_value={})),
            patch("vortex.crawler.crawl_domain", AsyncMock(return_value=None)),
            patch("vortex.js_discovery.discover_js_links", AsyncMock(return_value=None)),
            patch("vortex.email_harvester.harvest_emails", AsyncMock(return_value=[])),
            patch("vortex.param_fuzzer.parameter_discovery", _params),
        ):
            await fr.run_full_recon(
                targets=["https://example.com"],
                domain="example.com",
                wordlist=None,       # <-- no wordlist: defaults should kick in
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

        # All three should be awaited using built-in defaults
        _subdomains.assert_awaited_once()
        _fuzz.assert_awaited_once()
        _params.assert_awaited_once()

    asyncio.run(run())


# ---------------------------------------------------------------------------
# Test: --fast and --skip CLI flags are recognised
# ---------------------------------------------------------------------------

def test_fast_flag_recognised():
    parser = _build_parser()
    args = parser.parse_args(["-all", "-url", "https://example.com", "--fast"])
    assert args.fast is True


def test_fast_flag_default_false():
    parser = _build_parser()
    args = parser.parse_args(["-all", "-url", "https://example.com"])
    assert args.fast is False


def test_skip_flag_recognised():
    parser = _build_parser()
    args = parser.parse_args(["-all", "-url", "https://example.com", "--skip", "redirect,cors"])
    assert args.skip == "redirect,cors"


def test_skip_flag_default_empty():
    parser = _build_parser()
    args = parser.parse_args(["-all", "-url", "https://example.com"])
    assert args.skip == ""


# ---------------------------------------------------------------------------
# Test: --skip prevents skipped modules from being called
# ---------------------------------------------------------------------------

def test_skip_redirect_prevents_open_redirect_call():
    """When 'redirect' is in --skip, check_open_redirect should not be called."""

    async def run():
        from vortex import full_recon as fr

        _redirect = AsyncMock(return_value=[])

        with (
            patch("vortex.dns_records.dns_enum", AsyncMock(return_value={})),
            patch("vortex.ssl_analysis.ssl_check", AsyncMock(return_value={})),
            patch("vortex.port_scanner.port_scan", AsyncMock(return_value={"open_ports": []})),
            patch("vortex.subdomain.enumerate_subdomains", AsyncMock(return_value=[])),
            patch("vortex.fuzzer.directory_fuzzing", AsyncMock(return_value=[])),
            patch("vortex.tech_fingerprinting.fingerprint_technologies", AsyncMock(return_value={})),
            patch("vortex.crawler.crawl_domain", AsyncMock(return_value=None)),
            patch("vortex.js_discovery.discover_js_links", AsyncMock(return_value=None)),
            patch("vortex.email_harvester.harvest_emails", AsyncMock(return_value=[])),
            patch("vortex.param_fuzzer.parameter_discovery", AsyncMock(return_value=None)),
            patch("vortex.open_redirect.check_open_redirect", _redirect),
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
                skip="redirect",
            )

        _redirect.assert_not_awaited()

    asyncio.run(run())


def test_skip_cors_prevents_cors_call():
    """When 'cors' is in --skip, check_cors should not be called."""

    async def run():
        from vortex import full_recon as fr

        _cors = AsyncMock(return_value=[])

        with (
            patch("vortex.dns_records.dns_enum", AsyncMock(return_value={})),
            patch("vortex.ssl_analysis.ssl_check", AsyncMock(return_value={})),
            patch("vortex.port_scanner.port_scan", AsyncMock(return_value={"open_ports": []})),
            patch("vortex.subdomain.enumerate_subdomains", AsyncMock(return_value=[])),
            patch("vortex.fuzzer.directory_fuzzing", AsyncMock(return_value=[])),
            patch("vortex.tech_fingerprinting.fingerprint_technologies", AsyncMock(return_value={})),
            patch("vortex.crawler.crawl_domain", AsyncMock(return_value=None)),
            patch("vortex.js_discovery.discover_js_links", AsyncMock(return_value=None)),
            patch("vortex.email_harvester.harvest_emails", AsyncMock(return_value=[])),
            patch("vortex.param_fuzzer.parameter_discovery", AsyncMock(return_value=None)),
            patch("vortex.cors_scanner.check_cors", _cors),
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
                skip="cors",
            )

        _cors.assert_not_awaited()

    asyncio.run(run())
