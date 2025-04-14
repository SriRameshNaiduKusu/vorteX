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
vortex -h
```

---

## Example Commands

### Subdomain Enumeration

```bash
vortex -d example.com -w /path/to/subdomain-wordlist.txt -o subdomains.txt
```

---

### Directory Fuzzing

```bash
vortex -url https://example.com -w /path/to/directory-wordlist.txt -fuzz -o directories.txt
```

---

### Third-Party Link Crawling

```bash
vortex -crawl https://example.com --depth 3 -o crawl-links.txt
```

---

### JavaScript File & Endpoint Discovery

```bash
vortex -js https://example.com --depth 3 -o js-links.txt
```

---

### Parameter Discovery

```bash
vortex -paramfuzz -url https://example.com/search -w /path/to/param-wordlist.txt --method GET --headers "User-Agent:Mozilla/5.0" --format json -o params.json
```


---

## Contribution

Contributions are welcome! Feel free to open an issue or PR.

---


