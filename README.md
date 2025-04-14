# VorteX - The Ultimate Recon Tool 🚀

> Advanced Asynchronous Reconnaissance Tool For Bug Bounty Hunters & Pentesters  
> Developed with Async Python | Clean CLI Based | Fast & Efficient  

---

## Features 🚀

- Subdomain Enumeration (Async DNS Bruteforce)
- Directory & File Fuzzing (Async Requests)
- Parameter Discovery
- Web Crawler with:
  - Third-Party Link Finder
  - JavaScript File Discovery
  - JS Endpoint Extraction

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
  -url TARGET              Target URL for directory fuzzing
  -fuzz                    Enable directory fuzzing
  -crawl TARGET            Target URL to crawl for third-party links
  -js TARGET               Target URL to discover JavaScript files and endpoints
  -paramfuzz               Enable parameter discovery
  --method METHOD          HTTP method to use for parameter discovery (GET/POST) [default: GET]
  --headers HEADERS        Custom headers for requests (e.g., "User-Agent:Custom")
  --format FORMAT          Output format for parameter discovery (json/txt) [default: txt]
  --depth DEPTH            Crawling depth [default: 2]
  -w WORDLIST              Wordlist to use (required for subdomain, fuzzing, and paramfuzz)
  -T THREADS               Number of threads [default: 10]
  -o OUTPUT                Output file to save results
```
---

### Subdomain Enumeration

```bash
vorteX -d example.com -w /path/to/subdomain-wordlist.txt -o subdomains.txt
```

---

### Directory Fuzzing

```bash
vorteX -url https://example.com -w /path/to/directory-wordlist.txt -fuzz -o directories.txt
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
vorteX -paramfuzz -url https://example.com/search -w /path/to/param-wordlist.txt --method GET --headers "User-Agent:Mozilla/5.0" --format json -o params.json
```

---
## Disclaimer

>**This tool is intended for security testing and educational purposes only. Do not use this tool against targets without proper authorization.**



