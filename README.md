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
  - NEW: Technology Fingerprinting
  - NEW: stdin support for tool chaining

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

  -w WORDLIST              Wordlist to use (for -d, -fuzz, -paramfuzz)
  -T THREADS               Number of threads [default: 20]
  -o OUTPUT                Output file to save primary results
  --depth DEPTH            Crawling depth [default: 2]
  --method METHOD          HTTP method for -paramfuzz (GET/POST) [default: GET]
  --headers HEADERS        Custom headers for requests (e.g., "User-Agent:Custom")
  --format FORMAT          Output format for -paramfuzz (json/txt) [default: txt]
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
vorteX -d example.com -w /path/to/subdomain-wordlist.txt -o subdomains.txt -tech
```

---

### Directory Fuzzing + Tech Fingerprinting

```bash
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



