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
pip install -r requirements.txt
python3 main.py -h

```
---

## (Optional) Install globally

```
git clone https://github.com/SriRameshNaiduKusu/vorteX.git
cd vorteX
pip install .
```
---

## Usage

```
python main.py -h
```
>If Installed Globally

```
vortex -h
```

---

## Example Commands

```
python main.py -d target.com -wsub wordlist.txt -o subdomains.txt
python main.py -url https://target.com -fuzz -wdir wordlist.txt -o fuzz.txt
python main.py -crawl https://target.com --depth 3 -o crawl.txt
python main.py -js https://target.com --depth 3 -o js.txt
python main.py -paramfuzz -url https://target.com -wparam params.txt -o params.json --format json

```

---

## Contribution

Contributions are welcome! Feel free to open an issue or PR.

---


