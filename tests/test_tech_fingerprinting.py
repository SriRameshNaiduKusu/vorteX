from vortex.tech_fingerprinting import analyze_headers, analyze_html, analyze_cookies


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
