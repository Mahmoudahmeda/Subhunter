# Subhunter

**Subhunter** is a powerful subdomain enumeration tool that aggregates subdomains from multiple sources, including public search engines, APIs, and wordlist-based fuzzing. It supports scraping, API integration, and browser automation (using Selenium and Chromium) for comprehensive subdomain discovery.

---

## Features

- **Multi-source Subdomain Enumeration:**  
  Harvests subdomains using crt.sh, Yahoo, c99, Netcraft, and more.
- **API Integration:**  
  Supports Shodan, SecurityTrails, VirusTotal, Bevigil, and other APIs for extended results.
- **Wordlist Fuzzing:**  
  Brute-force subdomain discovery using a custom wordlist.
- **Proxy & Timeout Support:**  
  Easily configure request timeouts and proxy settings.
- **Optional Live Check:**  
  Supports checking for live subdomains using [httpx](https://github.com/projectdiscovery/httpx).
- **Customizable Output:**  
  Save results to a file of your choice.

---

## Prerequisites

Before using Subhunter, ensure the following dependencies are installed on your system:

### 1. Python Packages

Install required Python modules using pip:

```bash
pip install -r requirements.txt
```

**Or install manually:**

```bash
pip install requests beautifulsoup4 pyyaml colorama selenium
```

### 2. Chromium and Chromium Driver

Subhunter relies on headless browser automation via Selenium.  
**You must have Chromium and Chromium Driver installed on your system.**

**Install them using:**

```bash
sudo apt update
sudo apt install chromium chromium-driver
```

- On some systems, the packages might be named `chromium-browser` and `chromium-chromedriver`.

---

## Subdomain Wordlist

For brute-force or fuzzing mode, you need a subdomain wordlist.

- You can use any wordlist you like, but for best results, a large and comprehensive list is recommended.
- I have used [`n0kovo_subdomains_huge.txt`](https://github.com/n0kovo/n0kovo_subdomains/blob/main/n0kovo_subdomains_huge.txt) as a reference wordlist.
- You can find it and other quality lists in the [n0kovo/n0kovo_subdomains](https://github.com/n0kovo/n0kovo_subdomains) repository.

**Example:**
```bash
python Subhunter.py -d example.com -o results.txt -w n0kovo_subdomains_huge.txt
```

---

## Usage

```bash
python Subhunter.py -d <target_domain> -o <output_file.txt> [options]
```

### **Options**

- `-d`, `--target`      : Target domain (**required**)
- `-o`, `--output`      : Output file name (**required**)
- `-w`, `--wordlist`    : Wordlist file for brute-force fuzzing
- `-c`, `--config`      : YAML config file with API keys for supported services
- `--proxy`             : HTTP/HTTPS proxy (e.g., http://127.0.0.1:8080)
- `-mc`                 : Match status code for fuzzing (default: 200)
- `-t`                  : Timeout for requests (default: 20)
- `--delay`             : Delay between requests (default: 5 seconds)
- `--httpx`             : Use httpx to check for live subdomains
- `--bin`               : Path to Chromium binary (default: /usr/local/bin/chromium)
- `--driver`            : Path to Chrome Driver (default: /usr/local/bin/chromedriver)

### **Examples**

**Basic Enumeration:**
```bash
python Subhunter.py -d example.com -o results.txt
```

**With Wordlist Fuzzing:**
```bash
python Subhunter.py -d example.com -o results.txt -w n0kovo_subdomains_huge.txt
```

**With API Config:**
```bash
python Subhunter.py -d example.com -o results.txt -c apis.yaml
```

**Using Proxy and Custom Timeout:**
```bash
python Subhunter.py -d example.com -o results.txt --proxy http://127.0.0.1:8080 -t 10
```

---

## Notes

- **Do not use both `--config` and `--wordlist` at the same time.**  
  Choose one mode per run.
- For best results, use your own API keys for supported services (Shodan, SecurityTrails, etc.) in a YAML config file.
- Ensure that the Chromium and Chromium Driver versions match your installed browser.

---

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

## Disclaimer

Use responsibly and only on domains you have explicit permission to test.