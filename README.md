# VorteX - The Ultimate Recon Tool 🚀

> Advanced Asynchronous Reconnaissance Tool For Bug Bounty Hunters & Pentesters  
> Developed with Async Python | Clean CLI Based | Fast & Efficient  
> **v3.0.0** — Comprehensive Bug Bounty Recon Platform

---

## Features 🚀

- **Full Automated Recon Pipeline** (`-all`) — run every module in one command, **zero config needed**
- **Built-in Wordlists** — bundled default wordlists for subdomain enumeration, directory fuzzing, and parameter discovery; no `-w` required
- **SecLists Auto-Detection** — automatically uses SecLists wordlists when installed
- Subdomain Enumeration (Async DNS Bruteforce)
- **Subdomain Takeover Detection** (`-takeover`)
- **Certificate Transparency Log Mining** (`-ct`)
- **Wayback Machine URL Mining** (`-wayback`)
- **CORS Misconfiguration Scanner** (`-cors`)
- **Sensitive File & Path Detection** (`-sensitive`)
- **Security Header Analysis** (`-header-audit`)
- **Open Redirect Detection** (`-redirect`)
- **API Endpoint Discovery** (`-api`)
- Directory & File Fuzzing (Async Requests)
- Parameter Discovery
- Web Crawler with:
  - Third-Party Link Finder
  - JavaScript File Discovery
  - JS Endpoint Extraction
  - Technology Fingerprinting
  - stdin support for tool chaining
- DNS Record Enumeration (A, AAAA, MX, TXT, CNAME, NS, SOA)
- SSL/TLS Certificate Analysis
- Port Scanning (async, lightweight)
- Email Harvesting

---

## Installation

```bash
git clone https://github.com/SriRameshNaiduKusu/vorteX.git
cd vorteX
pip install .

```
>if you get "error: externally-managed-environment", Use this to install

```
pip install . --break-system-packages
```
---

## Usage

```
vorteX -h
```
```
  
usage: vorteX [OPTIONS]

Options:
  -d DOMAIN                Target domain for subdomain enumeration (e.g., example.com)
  -url TARGET              A single target URL (if not piping from stdin)
  
  -fuzz                    Enable directory fuzzing on target(s)
  -crawl                   Crawl target(s) for third-party links
  -js                      Discover JS files and endpoints on target(s)
  -tech                    Enable technology fingerprinting on target(s)
  -paramfuzz               Enable parameter discovery on a single URL
  -dns                     DNS record enumeration for a domain
  -ssl                     SSL/TLS certificate analysis
  -ports                   Lightweight async port scanner
  -emails                  Harvest emails from target URLs
  -all                     Run ALL recon modules automatically in sequence

  -takeover                Check subdomains for takeover vulnerabilities
  -ct                      Mine Certificate Transparency logs for subdomains (crt.sh)
  -wayback                 Mine Wayback Machine for historical URLs
  -cors                    Scan for CORS misconfigurations
  -sensitive               Check for exposed sensitive files and paths
  -header-audit            Audit HTTP security headers and provide a grade (A-F)
  -redirect                Test for open redirect vulnerabilities
  -api                     Discover API endpoints, GraphQL, and OpenAPI specs

  -w WORDLIST              Wordlist to use (optional — built-in defaults used when omitted)
  --wordlist-size SIZE     SecLists wordlist size: small (default), medium, or large
  -T THREADS               Number of threads [default: 20]
  -o OUTPUT                Output file to save primary results
  --depth DEPTH            Crawling depth [default: 2]
  --method METHOD          HTTP method for -paramfuzz (GET/POST) [default: GET]
  --headers HEADERS        Custom headers for requests (e.g., "User-Agent:Custom")
  --format FORMAT          Output format (json/txt) [default: txt]
  --proxy PROXY            HTTP/SOCKS proxy URL
  --rate-limit RATE        Max requests per second
  --random-ua              Rotate User-Agent strings randomly
  --timeout TIMEOUT        Request timeout in seconds [default: 10]
  --fast                   Enable fast mode — reduced payloads and checks for quicker scans
  --skip MODULES           Comma-separated list of modules to skip during -all mode
                           (e.g., redirect,wayback,cors)
```

---

### Full Automated Recon Pipeline (`-all`)

The `-all` flag runs **every recon module sequentially** in seven phases, feeding
results from earlier phases into later ones. A single consolidated report is
generated when `-o` is specified.

vorteX ships with built-in wordlists, so **`-w` is completely optional**. When
`-w` is omitted, each phase automatically uses the appropriate built-in default:

```
Phase 1: Reconnaissance & Discovery   → DNS, SSL/TLS, Port Scan
Phase 2: Subdomain & Surface Expansion → Subdomain Enumeration
Phase 3: Active Scanning              → Directory Fuzzing, Tech Fingerprinting
Phase 4: Deep Analysis                → Crawling, JS Discovery, Email Harvesting
Phase 5: Parameter Analysis           → Parameter Fuzzing
Phase 6: Passive Recon                → CT Log Mining, Wayback Machine
Phase 7: Vulnerability Scanning       → Takeover, CORS, Sensitive Files, Headers, Redirects, API
```

```bash
# Full auto recon — zero config needed! 🔥
vorteX -all -d example.com -o report.json --format json

# Full recon on a domain with custom wordlist (JSON report)
vorteX -all -d example.com -w /path/to/wordlist.txt -o full_report.json --format json

# Full recon on a URL (subdomain enum skipped — no -d)
vorteX -all -url https://example.com -o report.txt

# Full recon with proxy and rate limiting
vorteX -all -d example.com --proxy http://127.0.0.1:8080 --rate-limit 10 --random-ua

# Fast mode — reduced payloads and checks for quicker scans
vorteX -all -d example.com --fast

# Skip slow modules (redirect, wayback)
vorteX -all -d example.com --skip redirect,wayback

# Combine fast mode with skipping
vorteX -all -d example.com --fast --skip cors

# Pipe targets for full recon
echo "https://example.com" | vorteX -all -o report.json --format json
```

---

### Performance Optimization (`--fast` & `--skip`)

For large targets with thousands of discovered URLs, the `-all` mode can be slow due to combinatorial testing in modules like open redirect. Use these flags to speed things up:

#### `--fast` — Reduced Payloads & Smart Filtering

Enables fast mode across all supported modules:

- **Open redirect**: Uses 5 core params × 3 payloads instead of 21 params × 6 payloads. For URLs that already have query parameters, still tests the full parameter list but with reduced payloads.
- **CORS scan**: Tests with 1 origin (`https://evil.com`) instead of 3.
- **Sensitive files**: Checks ~15 most critical paths instead of the full list.

```bash
vorteX -all -d example.com --fast
```

#### `--skip` — Skip Specific Modules

Provides a comma-separated list of module names to skip entirely during `-all` mode:

| Skip value   | Module skipped                    |
|--------------|-----------------------------------|
| `redirect`   | Open redirect detection           |
| `cors`       | CORS misconfiguration scan        |
| `sensitive`  | Sensitive file detection          |
| `headers`    | Security header audit             |
| `takeover`   | Subdomain takeover detection      |
| `wayback`    | Wayback Machine URL mining        |
| `ct`         | Certificate Transparency log mining |
| `api`        | API endpoint discovery            |

```bash
# Skip open redirect and Wayback (slowest modules on large targets)
vorteX -all -d example.com --skip redirect,wayback

# Combine fast mode with skipping CORS
vorteX -all -d example.com --fast --skip cors

# Speed-optimised scan
vorteX -all -d example.com -T 50 --timeout 5 --fast --skip wayback
```

#### Scale Warning

When a large number of URLs is discovered (500+), vorteX automatically prints an estimate:

```
[ℹ] Large scan detected: 14081 URLs discovered. Estimated open redirect checks: ~1,774,206 requests.
[ℹ] Tip: Use --fast for quicker scans, or --skip redirect to skip slow modules.
```

---

### SecLists Integration

vorteX automatically detects [danielmiessler/SecLists](https://github.com/danielmiessler/SecLists) — the industry-standard security wordlist collection — and uses it instead of the bundled wordlists when available. On **Kali Linux** and **Parrot OS**, SecLists is typically pre-installed at `/usr/share/seclists/` and detected with **zero configuration**.

#### Installing SecLists

```bash
# Kali / Parrot / Debian-based
apt install seclists

# Or clone manually
git clone https://github.com/danielmiessler/SecLists ~/SecLists
```

#### Auto-detection search paths (in order)

| Path | Notes |
|------|-------|
| `$SECLISTS_PATH` env var | Highest priority override |
| `/usr/share/seclists/` | Kali/Parrot default |
| `/usr/share/SecLists/` | Some distros |
| `/opt/seclists/` | Manual install |
| `~/SecLists/` | Git clone |

#### `--wordlist-size` option

Use `--wordlist-size` to trade scan speed for coverage when SecLists is detected:

| Size | Subdomains | Directories | Parameters |
|------|-----------|-------------|-----------|
| `small` *(default)* | `subdomains-top1million-5000.txt` | `common.txt` | `burp-parameter-names.txt` |
| `medium` | `subdomains-top1million-20000.txt` | `raft-medium-directories.txt` | `burp-parameter-names.txt` |
| `large` | `subdomains-top1million-110000.txt` | `directory-list-2.3-medium.txt` | `burp-parameter-names.txt` |

```bash
# Use medium SecLists wordlists
vorteX -d example.com --wordlist-size medium

# Use large wordlists for full recon
vorteX -all -d example.com --wordlist-size large

# Override the SecLists path manually
SECLISTS_PATH=/custom/path vorteX -d example.com
```

When SecLists is **not** found, vorteX falls back to its bundled wordlists and prints a helpful install suggestion:

```
[*] SecLists not found. Using built-in wordlist: subdomains.txt (347 entries). Install SecLists for better results: apt install seclists
```

> **User-supplied `-w` always wins** — an explicit wordlist path always overrides both SecLists and bundled defaults.

---

### Subdomain Takeover Detection (`-takeover`)

Checks discovered subdomains for dangling CNAME records pointing to deprovisioned cloud services.

**Fingerprinted services:** GitHub Pages, Heroku, AWS S3, Shopify, Tumblr, Azure, Fastly, Pantheon, Cargo, Zendesk, Surge, Bitbucket, Netlify, ReadMe, Ghost, WP Engine, and more.

```bash
# Enumerate subdomains then check for takeover
vorteX -d example.com -takeover -o takeover.json --format json

# Check a specific list of subdomains
cat subdomains.txt | vorteX -takeover -o takeover.txt
```

---

### Certificate Transparency Log Mining (`-ct`)

Passively discovers subdomains by querying the [crt.sh](https://crt.sh) public CT log API — no DNS bruteforce needed.

```bash
vorteX -d example.com -ct -o ct-subdomains.txt
```

---

### Wayback Machine URL Mining (`-wayback`)

Discovers historical URLs from the Internet Archive's CDX API. Automatically filters for interesting file extensions (`.js`, `.php`, `.env`, `.bak`, `.sql`, etc.).

```bash
vorteX -d example.com -wayback -o wayback-urls.txt
```

---

### CORS Misconfiguration Scanner (`-cors`)

Tests endpoints for CORS misconfigurations by injecting malicious `Origin` headers.

**Severity levels:**
- 🔴 **CRITICAL** — Origin reflected with `Access-Control-Allow-Credentials: true`
- 🟡 **HIGH** — Origin reflected without credentials
- 🟣 **MEDIUM** — `null` origin accepted

```bash
cat urls.txt | vorteX -cors -o cors-findings.json --format json
vorteX -cors -url https://api.example.com -o cors.txt
```

---

### Sensitive File & Path Detection (`-sensitive`)

Probes for commonly exposed sensitive files and paths (`.env`, `.git/config`, `phpinfo.php`, Spring Boot actuators, backup files, etc.).

```bash
vorteX -sensitive -url https://example.com -o sensitive.txt
cat targets.txt | vorteX -sensitive -o sensitive.json --format json
```

---

### Security Header Analysis (`-header-audit`)

Audits HTTP security headers and assigns a letter grade (A–F) based on how many recommended headers are present.

**Checked headers:** `Content-Security-Policy`, `Strict-Transport-Security`, `X-Content-Type-Options`, `X-Frame-Options`, `X-XSS-Protection`, `Referrer-Policy`, `Permissions-Policy`, `Cross-Origin-Opener-Policy`, `Cross-Origin-Resource-Policy`, `Cross-Origin-Embedder-Policy`

```bash
vorteX -header-audit -url https://example.com
cat urls.txt | vorteX -header-audit -o headers.json --format json
```

---

### Open Redirect Detection (`-redirect`)

Tests URL parameters for open redirect vulnerabilities using common parameter names and payloads.

```bash
cat urls.txt | vorteX -redirect -o redirects.txt
vorteX -redirect -url "https://example.com/login" -o redirects.json --format json
```

---

### API Endpoint Discovery (`-api`)

Discovers API endpoints, GraphQL interfaces, OpenAPI/Swagger specs, and extracts API paths from JavaScript files.

```bash
vorteX -api -url https://example.com -o api-endpoints.json --format json
cat targets.txt | vorteX -api -o api.txt
```

---

### Built-in Wordlists (fallback)

vorteX includes small bundled wordlists used as fallback when SecLists is not installed:

| Module | Default Wordlist |
|--------|-----------------|
| Subdomain enumeration (`-d`) | `subdomains.txt` |
| Directory fuzzing (`-fuzz`) | `directories.txt` |
| Parameter discovery (`-paramfuzz`) | `parameters.txt` |

You can always override with your own wordlist using `-w`:

```bash
# Individual modes without -w (uses SecLists or built-in defaults)
vorteX -d example.com                                       # SecLists or built-in subdomain wordlist
vorteX -fuzz -url https://example.com                       # SecLists or built-in directory wordlist
vorteX -paramfuzz -url https://example.com/search           # SecLists or built-in parameter wordlist

# Override with custom wordlist
vorteX -d example.com -w /path/to/custom-subdomains.txt
vorteX -fuzz -url https://example.com -w /path/to/dirs.txt
```

---

### Chaining with other tools (stdin) 
vorteX accepts a list of targets from standard input (stdin). This allows you to pipe the output from other tools directly into vorteX to create powerful, one-line commands.

#### Example 1: Fuzzing & Tech-ID on Live Subdomains

##### Find subdomains -> check for live web servers -> fuzz and fingerprint them with vorteX

```bash
subfinder -d example.com -silent | httpx -silent | vorteX -fuzz -w /path/to/wordlist.txt -tech
```

#### Example 2: Using a Local File as Input

##### cat reads the file and pipes the URLs to vorteX for JS discovery

```bash
cat my_urls.txt | vorteX -js
```

---

### Subdomain Enumeration + Tech Fingerprinting

```bash
# Uses built-in subdomain wordlist by default
vorteX -d example.com -o subdomains.txt -tech

# Or specify a custom wordlist
vorteX -d example.com -w /path/to/subdomain-wordlist.txt -o subdomains.txt -tech
```

---

### Directory Fuzzing + Tech Fingerprinting

```bash
# Uses built-in directory wordlist by default
vorteX -url https://example.com -fuzz -o directories.txt -tech

# Or specify a custom wordlist
vorteX -url https://example.com -w /path/to/directory-wordlist.txt -fuzz -o directories.txt -tech
```

---

### Third-Party Link Crawling

```bash
vorteX -crawl https://example.com --depth 3 -o crawl-links.txt
```

---

### JavaScript File & Endpoint Discovery

```bash
vorteX -js https://example.com --depth 3 -o js-links.txt
```

---

### Parameter Discovery

```bash
# Uses built-in parameter wordlist by default
vorteX -paramfuzz -url https://example.com/search --method GET --format json -o params.json

# Or specify a custom wordlist
vorteX -paramfuzz -url https://example.com/search -w /path/to/param-wordlist.txt --method GET --headers "User-Agent:Mozilla/5.0" --format json -o params.json
```
---

### Technology Fingerprinting (-tech) (New Feature)

- Works with Subdomain Enumeration and Directory Fuzzing. 
- Detects server, CMS, frameworks on discovered URLs. 
- Saves results in fingerprint_results.txt.

```bash
vorteX -url https://example.com -tech
```
---

## Disclaimer

>**This tool is intended for security testing and educational purposes only. Do not use this tool against targets without proper authorization.**

