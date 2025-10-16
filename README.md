# Subhunter

```ascii
 _____ _   _______      _   _ _   _ _   _ _____ ___________ 
/  ___| | | | ___ \    | | | | | | | \ | |_   _|  ___| ___ \ 
\ `--.| | | | |_/ /_  _| |_| | | | |  \| | | | | |__ | |_/ /
 `--. \ | | | ___ \ \/ /  _  | | | | . ` | | | |  __||    / 
/\__/ / |_| | |_/ />  <| | | | |_| | |\  | | | | |___| |\ \ 
\____/ \___/\____//_/\_\_| |_/\___/\_| \_/ \_/ \____/\_| \_|
                                                            
    Subxhunter - Subdomain Enumeration Tool by Mahmoud Ahmed
```

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

### Linux

you can run the installer.sh file and it will install all the requirements

```bash
chmod +x installer.sh
sudo ./installer.sh
```

### Windows

**1. Python Packages**

Install required Python modules using pip:

```bash
pip install -r requirements.txt
```

### 2. Chromium and Chromium Driver

Subhunter relies on headless browser automation via Selenium.  
**You must have Chromium and Chromium Driver installed on your system.**

**Install them using:**

you can install them from [Chromium](https://googlechromelabs.github.io/chrome-for-testing/)
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

## API Configuration

Some data sources in Subhunter require API keys. You can supply these by creating a YAML configuration file.

**The default configuration file name is `config.yaml`.**

### Example `config.yaml`:

```yaml
shodan:
  api_key: "YOUR_SHODAN_API_KEY"
bevigil:
  api_key: "YOUR_BEVIGIL_API_KEY"
digitalyama:
  api_key: "YOUR_DIGITALYAMA_API_KEY"
dnsdumpster:
  api_key: "YOUR_DNSDUMPSTER_API_KEY"
fullhunt:
  api_key: "YOUR_FULLHUNT_API_KEY"
leakix:
  api_key: "YOUR_LEAKIX_API_KEY"
netlas:
  api_key: "YOUR_NETLAS_API_KEY"
pugrecon:
  api_key: "YOUR_PUGRECON_API_KEY"
rsecloud:
  api_key: "YOUR_RSECLOUD_API_KEY"
securitytrails:
  api_key: "YOUR_SECURITYTRAILS_API_KEY"
virustotal:
  api_key: "YOUR_VIRUSTOTAL_API_KEY"
google:
  api_key: "YOUR_GOOGLE_API_KEY"
```

- Replace each `"YOUR_..._API_KEY"` with your actual API key for that service.
- You can leave any unused API key field blank, or remove it entirely if you don't have an account for that service.
- The config file must be valid YAML format.

### How to Use

Run Subhunter with the `-c` or `--config` option and supply your config file (default: `config.yaml`):

```bash
python Subhunter.py -d example.com -o results.txt -c config.yaml
```

**Note:**  
- You only need to include the APIs you have keys for; the others can be omitted.

---

## Usage

```bash
python Subhunter.py -d <target_domain> -o <output_file.txt> [options]
```

### **Options**

- `-d`, `--target`      : Target domain (**required**)
- `-o`, `--output`      : Output file name (**required**)
- `-w`, `--wordlist`    : Wordlist file for brute-force fuzzing
- `-c`, `--config`      : YAML config file with API keys for supported services (default: `config.yaml`)
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
python Subhunter.py -d example.com -o results.txt -c config.yaml
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
- **It's preferred to filter the output file for duplicates** to ensure each subdomain appears only once in the results.

---

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

## Disclaimer

Use responsibly and only on domains you have explicit permission to test.