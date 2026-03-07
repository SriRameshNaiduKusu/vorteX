import asyncio
import inspect
from unittest.mock import AsyncMock, patch

from vortex.tech_fingerprinting import analyze_headers, analyze_html, analyze_cookies, fingerprint_technologies


def test_fingerprint_technologies_accepts_rate_limit():
    """fingerprint_technologies must accept a rate_limit keyword argument."""
    sig = inspect.signature(fingerprint_technologies)
    assert 'rate_limit' in sig.parameters, (
        "fingerprint_technologies() must accept a 'rate_limit' parameter"
    )


def test_fingerprint_technologies_rate_limit_default_none():
    """rate_limit parameter must default to None."""
    sig = inspect.signature(fingerprint_technologies)
    assert sig.parameters['rate_limit'].default is None


def test_fingerprint_technologies_called_with_common_kwargs():
    """Calling fingerprint_technologies with a rate_limit kwarg must not raise TypeError."""
    common_kwargs = dict(proxy=None, timeout=10, random_ua=False, rate_limit=10)

    async def run():
        with patch('vortex.tech_fingerprinting.aiohttp.ClientSession') as mock_session_cls:
            mock_session = AsyncMock()
            mock_session_cls.return_value.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session_cls.return_value.__aexit__ = AsyncMock(return_value=False)
            mock_session.get = AsyncMock()
            # Empty URL list — just verify no TypeError is raised
            result = await fingerprint_technologies([], output_file=None, **common_kwargs)
            assert isinstance(result, dict)

    asyncio.run(run())


def test_analyze_headers_basic():
    headers = {
        'Server': 'nginx/1.18',
        'X-Powered-By': 'PHP/8.1',
    }
    result = analyze_headers(headers)
    assert any('nginx' in t for t in result)
    assert any('PHP' in t for t in result)


def test_analyze_headers_cloudflare():
    headers = {
        'CF-Ray': '123abc',
        'Server': 'cloudflare',
    }
    result = analyze_headers(headers)
    assert any('Cloudflare' in t for t in result)


def test_analyze_headers_aspnet():
    headers = {
        'X-AspNet-Version': '4.0.30319',
    }
    result = analyze_headers(headers)
    assert 'ASP.NET (version: 4.0.30319)' in result


def test_analyze_html_wordpress():
    html = '<script src="/wp-content/themes/theme/js/script.js"></script>'
    result = analyze_html(html)
    assert any('WordPress' in t for t in result)


def test_analyze_html_react():
    html = '<div data-reactroot=""></div>'
    result = analyze_html(html)
    assert any('React' in t for t in result)


def test_analyze_html_vuejs():
    html = '<div data-v-abc123=""></div>'
    result = analyze_html(html)
    assert any('Vue' in t for t in result)


def test_analyze_html_nextjs():
    html = '<script id="__NEXT_DATA__" type="application/json">{}</script>'
    result = analyze_html(html)
    assert any('Next.js' in t for t in result)


def test_analyze_html_django():
    html = '<input type="hidden" name="csrfmiddlewaretoken" value="abc123">'
    result = analyze_html(html)
    assert any('Django' in t for t in result)


def test_analyze_html_shopify():
    html = '<script src="https://cdn.shopify.com/s/files/1/0000/app.js"></script>'
    result = analyze_html(html)
    assert any('Shopify' in t for t in result)


def test_analyze_cookies_php():
    cookies = {'PHPSESSID': 'abc123'}
    result = analyze_cookies(cookies)
    assert any('PHP' in t for t in result)


def test_analyze_cookies_django():
    cookies = {'csrftoken': 'abc123'}
    result = analyze_cookies(cookies)
    assert any('Django' in t for t in result)


def test_analyze_cookies_java():
    cookies = {'JSESSIONID': 'abc123'}
    result = analyze_cookies(cookies)
    assert any('Java' in t for t in result)
