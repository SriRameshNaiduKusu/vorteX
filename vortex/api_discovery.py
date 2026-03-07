"""API endpoint discovery module.

Discovers API endpoints, GraphQL interfaces, and API documentation files
by probing common API paths and extracting endpoints from JS files.
"""

import asyncio
import json
import logging
import re
import random

import aiohttp
from colorama import Fore, Style

from vortex.utils import stop_event, display_banner
from vortex.user_agents import USER_AGENTS

# Common API paths to check
API_PATHS = [
    "/api/",
    "/api/v1/",
    "/api/v2/",
    "/api/v3/",
    "/api/v4/",
    "/graphql",
    "/graphiql",
    "/swagger.json",
    "/swagger-ui.html",
    "/openapi.json",
    "/openapi.yaml",
    "/api-docs",
    "/api-docs/",
    "/_api/",
    "/rest/",
    "/services/",
    "/ws/",
    "/rpc/",
    "/v1/",
    "/v2/",
    "/v3/",
    "/.well-known/",
    "/health",
    "/status",
    "/ping",
    "/metrics",
    "/version",
    "/info",
]

# GraphQL introspection query
_GRAPHQL_INTROSPECTION = json.dumps({
    "query": "{ __schema { queryType { name } types { name kind } } }"
})

# Pattern to extract API paths from JS files
_API_PATH_RE = re.compile(
    r"""['"]((?:/api/|/rest/|/graphql|/v\d)[^'"<>\s]{0,200})['"]""",
    re.IGNORECASE,
)


async def _probe_path(session, base_url, path, proxy=None, timeout=10, random_ua=False):
    """Return a finding dict if *base_url + path* returns a non-error response."""
    url = base_url.rstrip("/") + path
    headers = {}
    if random_ua:
        headers["User-Agent"] = random.choice(USER_AGENTS)
    req_kwargs = {}
    if proxy:
        req_kwargs["proxy"] = proxy
    try:
        async with session.get(
            url,
            headers=headers,
            timeout=aiohttp.ClientTimeout(total=timeout),
            allow_redirects=True,
            **req_kwargs,
        ) as resp:
            status = resp.status
            content_type = resp.headers.get("Content-Type", "")
            if status in (200, 201, 204):
                body = await resp.text(errors="replace")
                return {
                    "url": url,
                    "status": status,
                    "content_type": content_type,
                    "is_graphql": "graphql" in path,
                    "is_swagger": any(k in path for k in ("swagger", "openapi", "api-docs")),
                    "body_preview": body[:200],
                }
    except Exception as exc:
        logging.debug(f"API probe error {url}: {exc}")
    return None


async def _graphql_introspect(session, url, proxy=None, timeout=10):
    """Attempt GraphQL introspection on *url* and return schema info."""
    req_kwargs = {}
    if proxy:
        req_kwargs["proxy"] = proxy
    try:
        async with session.post(
            url,
            data=_GRAPHQL_INTROSPECTION,
            headers={"Content-Type": "application/json"},
            timeout=aiohttp.ClientTimeout(total=timeout),
            **req_kwargs,
        ) as resp:
            if resp.status == 200:
                data = await resp.json(content_type=None)
                types = [
                    t["name"]
                    for t in data.get("data", {}).get("__schema", {}).get("types", [])
                    if not t["name"].startswith("__")
                ]
                return types
    except Exception as exc:
        logging.debug(f"GraphQL introspection error {url}: {exc}")
    return []


async def _extract_js_endpoints(session, base_url, proxy=None, timeout=10):
    """Fetch *base_url* as HTML, find JS files, extract API paths."""
    extracted = set()
    req_kwargs = {}
    if proxy:
        req_kwargs["proxy"] = proxy
    try:
        from bs4 import BeautifulSoup
        async with session.get(
            base_url, timeout=aiohttp.ClientTimeout(total=timeout), **req_kwargs
        ) as resp:
            if resp.status != 200:
                return []
            html = await resp.text(errors="replace")
            soup = BeautifulSoup(html, "html.parser")
            js_urls = [
                tag["src"]
                for tag in soup.find_all("script", src=True)
                if "src" in tag.attrs
            ]
    except Exception:
        return []

    from urllib.parse import urljoin
    for js_path in js_urls[:10]:  # limit to first 10 JS files
        js_url = urljoin(base_url, js_path)
        try:
            async with session.get(
                js_url, timeout=aiohttp.ClientTimeout(total=timeout), **req_kwargs
            ) as resp:
                if resp.status != 200:
                    continue
                js_text = await resp.text(errors="replace")
                for match in _API_PATH_RE.findall(js_text):
                    extracted.add(match)
        except Exception:
            continue

    return list(extracted)


async def discover_api_endpoints(
    urls,
    output_file=None,
    output_format="txt",
    proxy=None,
    timeout=10,
    random_ua=False,
    rate_limit=None,
    max_threads=20,
):
    """Discover API endpoints for each URL in *urls*.

    Parameters
    ----------
    urls : list[str]
        Base URLs to probe.
    output_file : str or None
        Path to write results.
    output_format : str
        ``'json'`` or ``'txt'``.

    Returns
    -------
    dict
        Keys: ``found_endpoints``, ``graphql_types``, ``js_api_paths``.
    """
    display_banner()
    print(
        f"{Fore.CYAN}[*] Discovering API endpoints on "
        f"{len(urls)} target(s)...{Style.RESET_ALL}"
    )

    found_endpoints = []
    graphql_types = {}
    js_api_paths = {}
    sem = asyncio.Semaphore(max_threads)

    async def handle_url(base_url):
        if stop_event.is_set():
            return
        connector = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(connector=connector) as session:
            # Probe common API paths
            for path in API_PATHS:
                if stop_event.is_set():
                    return
                async with sem:
                    result = await _probe_path(
                        session, base_url, path, proxy, timeout, random_ua
                    )
                    if result:
                        found_endpoints.append(result)
                        print(
                            f"{Fore.GREEN}[✔] API endpoint: {result['url']} "
                            f"(HTTP {result['status']}, {result['content_type']}){Style.RESET_ALL}"
                        )
                        # Try GraphQL introspection
                        if result["is_graphql"]:
                            types = await _graphql_introspect(session, result["url"], proxy, timeout)
                            if types:
                                graphql_types[result["url"]] = types
                                print(
                                    f"{Fore.YELLOW}  [GraphQL] Types: "
                                    f"{', '.join(types[:10])}{Style.RESET_ALL}"
                                )
                    if rate_limit:
                        await asyncio.sleep(1.0 / rate_limit)

            # Extract API paths from JS files
            js_paths = await _extract_js_endpoints(session, base_url, proxy, timeout)
            if js_paths:
                js_api_paths[base_url] = js_paths
                print(
                    f"{Fore.YELLOW}  [JS] Extracted {len(js_paths)} API path(s) "
                    f"from JS files on {base_url}{Style.RESET_ALL}"
                )

    await asyncio.gather(*[handle_url(u) for u in urls])

    results = {
        "found_endpoints": found_endpoints,
        "graphql_types": graphql_types,
        "js_api_paths": js_api_paths,
    }

    if not found_endpoints and not js_api_paths:
        print(f"{Fore.GREEN}[✔] No API endpoints discovered.{Style.RESET_ALL}")

    if output_file:
        with open(output_file, "w") as fh:
            if output_format == "json":
                json.dump(results, fh, indent=2)
            else:
                fh.write(f"=== API Endpoints ({len(found_endpoints)}) ===\n")
                for ep in found_endpoints:
                    fh.write(f"  [{ep['status']}] {ep['url']}\n")
                if graphql_types:
                    fh.write("\n=== GraphQL Types ===\n")
                    for u, types in graphql_types.items():
                        fh.write(f"  {u}: {', '.join(types)}\n")
                if js_api_paths:
                    fh.write("\n=== JS-Extracted API Paths ===\n")
                    for u, paths in js_api_paths.items():
                        fh.write(f"  {u}:\n")
                        for p in paths:
                            fh.write(f"    {p}\n")

    print(
        f"{Fore.CYAN}[✔] API discovery complete — "
        f"{len(found_endpoints)} endpoint(s) found.{Style.RESET_ALL}"
    )
    return results
