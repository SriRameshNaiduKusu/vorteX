import asyncio
import logging
import re
import json
import aiohttp
from bs4 import BeautifulSoup
from tqdm.asyncio import tqdm
from colorama import Fore, Style


async def fetch(session, url, proxy=None, timeout=10, random_ua=False):
    import random
    from vortex.user_agents import USER_AGENTS
    req_kwargs = {}
    if proxy:
        req_kwargs['proxy'] = proxy
    headers = {}
    if random_ua:
        headers['User-Agent'] = random.choice(USER_AGENTS)
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=timeout),
                               ssl=False, headers=headers or None, **req_kwargs) as response:
            text = await response.text(errors='ignore')
            headers_resp = response.headers
            cookies = response.cookies
            return url, headers_resp, text, cookies
    except Exception as e:
        logging.debug(f"Error fetching {url}: {e}")
        return url, {}, '', {}


def analyze_headers(headers):
    tech = []
    server = headers.get('Server', '')
    powered_by = headers.get('X-Powered-By', '')
    via = headers.get('Via', '')

    if server:
        tech.append(f"Server: {server}")
    if powered_by:
        tech.append(f"X-Powered-By: {powered_by}")
    if via:
        tech.append(f"Via: {via}")

    # ASP.NET
    if headers.get('X-AspNet-Version') or headers.get('X-AspNetMvc-Version'):
        tech.append(f"ASP.NET (version: {headers.get('X-AspNet-Version', 'unknown')})")

    # Drupal
    if headers.get('X-Drupal-Cache') or headers.get('X-Generator', '').lower().startswith('drupal'):
        tech.append("Drupal detected via headers")

    # WAF detection
    cf_ray = headers.get('cf-ray') or headers.get('CF-Ray')
    if cf_ray or 'cloudflare' in server.lower():
        tech.append("WAF/CDN: Cloudflare")

    if headers.get('x-amzn-RequestId') or headers.get('x-amz-cf-id') or 'awselb' in server.lower():
        tech.append("WAF/CDN: AWS")

    if 'akamai' in server.lower() or headers.get('x-akamai-transformed') or headers.get('x-check-cacheable'):
        tech.append("CDN: Akamai")

    if headers.get('x-sucuri-id') or headers.get('x-sucuri-cache'):
        tech.append("WAF: Sucuri")

    if headers.get('x-cdn') or headers.get('x-fastly-request-id') or 'fastly' in via.lower():
        tech.append("CDN: Fastly")

    return tech


def analyze_html(html):
    tech = []
    soup = BeautifulSoup(html, 'html.parser')

    # Generator meta tag
    generator = soup.find('meta', attrs={'name': 'generator'})
    if generator and generator.get('content'):
        tech.append(f"Generator: {generator['content']}")

    # Script sources
    scripts = soup.find_all('script', src=True)
    script_srcs = [s['src'] for s in scripts]
    script_text_tags = soup.find_all('script')
    inline_scripts = ' '.join(s.get_text() for s in script_text_tags)

    # WordPress
    for src in script_srcs:
        if 'wp-content' in src or 'wp-includes' in src:
            tech.append('WordPress detected via script src')
            break
    if re.search(r'wp-login\.php|wp-admin', html):
        tech.append('WordPress detected via login/admin page reference')

    # AngularJS / Angular
    if 'window.angular' in html or 'ng-app' in html or 'ng-controller' in html:
        tech.append('AngularJS/Angular detected')

    # React
    if re.search(r'data-reactroot|data-reactid|__reactFiber|__reactProps', html):
        tech.append('React detected')

    # Vue.js
    if '__vue__' in html or 'data-v-' in html:
        tech.append('Vue.js detected')
    for src in script_srcs:
        if 'vue' in src.lower() and ('vue.js' in src.lower() or 'vue.min.js' in src.lower()):
            tech.append('Vue.js detected via CDN')
            break

    # Next.js
    if '__NEXT_DATA__' in html:
        tech.append('Next.js detected')

    # Nuxt.js
    if '__NUXT__' in html or 'window.__NUXT__' in html:
        tech.append('Nuxt.js detected')

    # jQuery
    for src in script_srcs:
        if 'jquery' in src.lower():
            tech.append('jQuery detected')
            break
    if re.search(r'jQuery|window\.\$', inline_scripts):
        tech.append('jQuery detected via inline script')

    # Bootstrap
    all_links = [lnk.get('href', '') for lnk in soup.find_all('link')]
    for href in all_links:
        if 'bootstrap' in href.lower():
            tech.append('Bootstrap CSS detected')
            break
    for src in script_srcs:
        if 'bootstrap' in src.lower():
            tech.append('Bootstrap JS detected')
            break

    # Tailwind CSS — use specific color/spacing utility patterns unlikely to appear in other frameworks
    tailwind_specific = re.compile(
        r'\b(text-(?:gray|blue|red|green|yellow|purple|pink|indigo)-\d{2,3}|'
        r'bg-(?:gray|blue|red|green|yellow|purple|pink|indigo)-\d{2,3}|'
        r'(?:px|py|pt|pb|pl|pr|mx|my|mt|mb|ml|mr)-\d+|'
        r'(?:w|h)-(?:\d+|full|screen|auto)|'
        r'rounded-(?:sm|md|lg|xl|full)|'
        r'shadow-(?:sm|md|lg|xl)|'
        r'font-(?:thin|light|normal|medium|semibold|bold|extrabold))\b'
    )
    all_tag_classes = (tag.get('class', []) for tag in soup.find_all(class_=True) if isinstance(tag.get('class'), list))
    flat_classes = ' '.join(cls for classes in all_tag_classes for cls in classes)
    tailwind_matches = tailwind_specific.findall(flat_classes)
    if len(tailwind_matches) >= 3:
        tech.append('Tailwind CSS likely detected')
    for href in all_links:
        if 'tailwind' in href.lower():
            tech.append('Tailwind CSS detected via CDN')
            break

    # Django
    if soup.find('input', attrs={'name': 'csrfmiddlewaretoken'}):
        tech.append('Django detected (csrfmiddlewaretoken)')

    # Laravel
    if 'laravel' in html.lower() and ('_token' in html or 'csrf-token' in html):
        tech.append('Laravel likely detected')

    # Joomla
    for src in script_srcs:
        if '/media/jui/' in src or '/media/system/' in src:
            tech.append('Joomla detected via script src')
            break
    generator_content = generator['content'] if generator and generator.get('content') else ''
    if 'joomla' in generator_content.lower():
        tech.append('Joomla detected via generator meta tag')

    # Shopify
    if re.search(r'cdn\.shopify\.com', html):
        tech.append('Shopify detected')

    # Squarespace
    if re.search(r'squarespace', html, re.IGNORECASE) or re.search(r'static\.squarespace\.com', html):
        tech.append('Squarespace detected')

    # Wix
    if re.search(r'wix\.com', html) or 'X-Wix-Published-Version' in html:
        tech.append('Wix detected')

    # Webflow
    if re.search(r'webflow\.com', html) or 'Webflow' in html:
        tech.append('Webflow detected')

    return tech


def analyze_cookies(cookies):
    tech = []
    cookie_names = [c for c in cookies]
    for name in cookie_names:
        name_lower = name.lower()
        if name_lower == 'phpsessid':
            tech.append('PHP detected (PHPSESSID cookie)')
        elif name_lower == 'jsessionid':
            tech.append('Java/JVM detected (JSESSIONID cookie)')
        elif name_lower == 'csrftoken':
            tech.append('Django detected (csrftoken cookie)')
        elif name_lower == 'asp.net_sessionid':
            tech.append('ASP.NET detected (session cookie)')
        elif name_lower == 'laravel_session':
            tech.append('Laravel detected (laravel_session cookie)')
    return tech


async def fingerprint_url(session, url, results, proxy=None, timeout=10, random_ua=False):
    url, headers, html, cookies = await fetch(session, url, proxy=proxy, timeout=timeout, random_ua=random_ua)
    tech = analyze_headers(headers)
    tech += analyze_html(html)
    tech += analyze_cookies(cookies)

    if tech:
        results[url] = tech
        print(f"\n{Fore.CYAN}[+] Technologies for {url}:{Style.RESET_ALL}")
        for t in tech:
            print(f"  {Fore.GREEN}[✔] {t}{Style.RESET_ALL}")
    else:
        results[url] = ['No identifiable technologies detected']


async def fingerprint_technologies(urls, output_file='fingerprint_results.txt',
                                    output_format='txt', proxy=None, timeout=10,
                                    random_ua=False, max_threads=20):
    results = {}
    connector = aiohttp.TCPConnector(limit=max_threads)
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [fingerprint_url(session, url, results, proxy=proxy, timeout=timeout,
                                  random_ua=random_ua)
                 for url in tqdm(urls, desc="Tech Fingerprinting")]
        await asyncio.gather(*tasks)

    if output_file:
        with open(output_file, 'w', encoding='utf-8') as f:
            if output_format == 'json':
                json.dump([{"url": url, "technologies": tech_list} for url, tech_list in results.items()],
                          f, indent=2)
            else:
                for url, tech_list in results.items():
                    f.write(f"URL: {url}\n")
                    for tech in tech_list:
                        f.write(f"  - {tech}\n")
                    f.write("\n")
        print(f"\n[+] Technology Fingerprinting Completed. Results saved to {output_file}")

    return results
