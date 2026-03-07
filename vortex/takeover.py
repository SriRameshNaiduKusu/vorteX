"""Subdomain takeover detection module.

Checks discovered subdomains for dangling CNAME records that point to
deprovisioned cloud services (potential subdomain takeover).
"""

import asyncio
import json

import aiohttp

try:
    import aiodns
    _AIODNS_AVAILABLE = True
except ImportError:  # pragma: no cover
    _AIODNS_AVAILABLE = False

from colorama import Fore, Style

from vortex.utils import stop_event, display_banner

# ---------------------------------------------------------------------------
# Fingerprint database
# Each entry maps a CNAME keyword to (service_name, body_fingerprint_or_None)
# ---------------------------------------------------------------------------
TAKEOVER_FINGERPRINTS = [
    # (cname_keyword, service_name, body_fingerprint_or_None)
    ("github.io",            "GitHub Pages",   "There isn't a GitHub Pages site here"),
    ("herokudns.com",        "Heroku",         "No such app"),
    ("herokuapp.com",        "Heroku",         "No such app"),
    ("s3.amazonaws.com",     "AWS S3",         "NoSuchBucket"),
    ("s3-website",           "AWS S3",         "NoSuchBucket"),
    ("myshopify.com",        "Shopify",        "Sorry, this shop is currently unavailable"),
    ("tumblr.com",           "Tumblr",         "There's nothing here"),
    ("azurewebsites.net",    "Azure",          None),
    ("cloudapp.azure.com",   "Azure",          None),
    ("trafficmanager.net",   "Azure Traffic",  None),
    ("fastly.net",           "Fastly",         "Fastly error: unknown domain"),
    ("pantheonsite.io",      "Pantheon",       None),
    ("cargocollective.com",  "Cargo",          None),
    ("zendesk.com",          "Zendesk",        "Help Center Closed"),
    ("wpengine.com",         "WP Engine",      None),
    ("ghost.io",             "Ghost",          None),
    ("surge.sh",             "Surge",          "project not found"),
    ("bitbucket.io",         "Bitbucket",      "Repository not found"),
    ("netlify.com",          "Netlify",        "Not Found"),
    ("readme.io",            "ReadMe",         "Project doesnt exist"),
]


async def _resolve_cname(subdomain, resolver):
    """Return the CNAME chain string for *subdomain*, or empty string."""
    if not _AIODNS_AVAILABLE:
        return ""
    try:
        result = await resolver.query_dns(subdomain, "CNAME")
        if result:
            return result[0].host
    except Exception:
        pass
    return ""


async def _fetch_body(session, url, proxy=None, timeout=10):
    """Return the response body text for *url*, or empty string on error."""
    req_kwargs = {}
    if proxy:
        req_kwargs["proxy"] = proxy
    try:
        async with session.get(
            url, timeout=aiohttp.ClientTimeout(total=timeout),
            allow_redirects=True, **req_kwargs
        ) as resp:
            return await resp.text(errors="replace")
    except Exception:
        return ""


async def check_takeover(
    subdomains,
    output_file=None,
    output_format="txt",
    proxy=None,
    timeout=10,
    random_ua=False,
    rate_limit=None,
    max_threads=20,
):
    """Check *subdomains* for potential takeover vulnerabilities.

    Parameters
    ----------
    subdomains : list[str]
        List of subdomain hostnames (or full URLs).
    output_file : str or None
        Path to write results.
    output_format : str
        ``'json'`` or ``'txt'``.

    Returns
    -------
    list[dict]
        Findings, each with keys ``subdomain``, ``cname``, ``service``,
        ``severity``, and ``detail``.
    """
    display_banner()
    # Normalise inputs — strip scheme/path if URLs were passed
    clean = []
    for s in subdomains:
        host = s.replace("https://", "").replace("http://", "").split("/")[0]
        if host:
            clean.append(host)

    print(
        f"{Fore.CYAN}[*] Checking {len(clean)} subdomain(s) for takeover "
        f"vulnerabilities...{Style.RESET_ALL}"
    )

    findings = []

    resolver = None
    if _AIODNS_AVAILABLE:
        loop = asyncio.get_event_loop()
        resolver = aiodns.DNSResolver(loop=loop)

    connector = aiohttp.TCPConnector(ssl=False)
    sem = asyncio.Semaphore(max_threads)

    async def check_one(subdomain):
        if stop_event.is_set():
            return
        async with sem:
            cname = await _resolve_cname(subdomain, resolver) if resolver else ""
            matched_service = None
            body_fp = None

            for keyword, service, body_fingerprint in TAKEOVER_FINGERPRINTS:
                if keyword in cname:
                    matched_service = service
                    body_fp = body_fingerprint
                    break

            if not matched_service:
                return

            # Verify with HTTP body check when a fingerprint is provided
            detail = f"CNAME: {cname}"
            confirmed = body_fp is None  # If no body FP, flag as potential

            if body_fp:
                async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False)) as s:
                    body = await _fetch_body(s, f"http://{subdomain}", proxy, timeout)
                    if body_fp.lower() in body.lower():
                        confirmed = True
                        detail += f" | Body match: '{body_fp}'"

            if confirmed:
                severity = "HIGH" if body_fp else "MEDIUM"
                finding = {
                    "subdomain": subdomain,
                    "cname": cname,
                    "service": matched_service,
                    "severity": severity,
                    "detail": detail,
                }
                findings.append(finding)
                color = Fore.RED if severity == "HIGH" else Fore.YELLOW
                print(
                    f"{color}[!] Potential takeover [{severity}]: {subdomain} → "
                    f"{matched_service} | {detail}{Style.RESET_ALL}"
                )
            if rate_limit:
                await asyncio.sleep(1.0 / rate_limit)

    async with aiohttp.ClientSession(connector=connector):
        tasks = [check_one(s) for s in clean]
        await asyncio.gather(*tasks)

    if not findings:
        print(f"{Fore.GREEN}[✔] No takeover vulnerabilities detected.{Style.RESET_ALL}")

    if output_file and findings:
        with open(output_file, "w") as fh:
            if output_format == "json":
                json.dump(findings, fh, indent=2)
            else:
                for f in findings:
                    fh.write(
                        f"[{f['severity']}] {f['subdomain']} → {f['service']} "
                        f"| {f['detail']}\n"
                    )

    print(
        f"{Fore.CYAN}[✔] Takeover scan complete — "
        f"{len(findings)} potential issue(s) found.{Style.RESET_ALL}"
    )
    return findings
