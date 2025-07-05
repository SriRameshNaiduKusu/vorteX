import aiohttp
import asyncio
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import re
from tqdm.asyncio import tqdm


async def fetch(session, url):
    try:
        async with session.get(url, timeout=10, ssl=False) as response:
            text = await response.text(errors='ignore')
            headers = response.headers
            return url, headers, text
    except Exception:
        return url, {}, ''


def analyze_headers(headers):
    tech = []
    server = headers.get('Server')
    powered_by = headers.get('X-Powered-By')
    via = headers.get('Via')

    if server:
        tech.append(f"Server: {server}")
    if powered_by:
        tech.append(f"X-Powered-By: {powered_by}")
    if via:
        tech.append(f"Via: {via}")

    return tech


def analyze_html(html):
    tech = []
    soup = BeautifulSoup(html, 'html.parser')

    generator = soup.find('meta', attrs={'name': 'generator'})
    if generator and generator.get('content'):
        tech.append(f"Generator: {generator['content']}")

    scripts = soup.find_all('script', src=True)
    for script in scripts:
        src = script['src']
        if 'wp-content' in src or 'wp-includes' in src:
            tech.append('WordPress detected via script src')
            break

    if re.search(r'wp-login\\.php|wp-admin', html):
        tech.append('WordPress detected via login/admin page reference')

    if 'window.angular' in html:
        tech.append('AngularJS detected')
    if re.search(r'data-reactroot', html):
        tech.append('React detected')

    return tech


async def fingerprint_url(session, url, results):
    url, headers, html = await fetch(session, url)
    tech = analyze_headers(headers)
    tech += analyze_html(html)

    if tech:
        results[url] = tech
    else:
        results[url] = ['No identifiable technologies detected']


async def fingerprint_technologies(urls):
    results = {}
    connector = aiohttp.TCPConnector(limit=20)
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [fingerprint_url(session, url, results) for url in tqdm(urls, desc="Tech Fingerprinting")]
        await asyncio.gather(*tasks)

    with open('fingerprint_results.txt', 'w', encoding='utf-8') as f:
        for url, tech_list in results.items():
            f.write(f"URL: {url}\n")
            for tech in tech_list:
                f.write(f"  - {tech}\n")
            f.write("\n")

    print("\n[+] Technology Fingerprinting Completed. Results saved to fingerprint_results.txt")
