# bypass-cloudflare-get-origin-IP

An advanced OSINT reconnaissance tool designed to bypass Cloudflare protection and uncover the real origin IP of a protected domain.

This tool employs multiple detection vectors—including Certificate Transparency (crt.sh), SPF/TXT record IP extraction, multi-threaded subdomain enumeration, and MX record analysis—coupled with active origin validation (SSL certificate SAN matching and direct HTTP Host Header probing) to minimize false positives.

---

### Key Features

* **Certificate Transparency (crt.sh)**: Automatically queries public SSL/TLS certificate logs to discover active and historical subdomains without needing any API key.
* **SPF & TXT Record Extraction**: Extracts IPv4 and IPv6 addresses configured in email SPF records (`v=spf1 ...`), which frequently leak origin server IPs.
* **Multi-Threaded Subdomain Enumeration**: Fast concurrent DNS resolution with support for external wordlists.
* **MX Record Checking**: Analyzes Mail Exchange records and resolves mail server IPs.
* **Origin Verification & Anti-False Positive (Active Probing)**:
  * Probes candidate IPs directly with `Host: <domain>` headers.
  * Compares HTML title and status codes against baseline target signatures.
  * Inspects SSL/TLS certificates on port 443 to match Subject Alternative Names (SAN) and Common Names (CN).
  * Classifies results with high-confidence tags (`[CONFIRMED ORIGIN]`).
* **Precise Cloudflare CIDR Filtering**: Dynamically fetches official Cloudflare IPv4 & IPv6 ranges and performs CIDR subnet matching.
* **JSON & TXT Export**: Easily export structured scan results for reports, automation, and tooling integration.
* **Custom DNS Resolver**: Bypass local ISP DNS filtering or caching by specifying custom resolvers (e.g., `1.1.1.1`, `8.8.8.8`).

---

### Installation

1. **Prerequisites**: Python 3.8 or newer.
2. **Clone the Repository**:
   ```bash
   git clone https://github.com/bimantaraz/bypass-cloudflare-get-origin-IP.git
   cd bypass-cloudflare-get-origin-IP
   ```
3. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

---

### Usage

#### Basic Scan
```bash
python teraz.py example.com
```

#### Advanced Options & Examples

* **Save results to JSON or TXT file**:
  ```bash
  python teraz.py example.com -o results.json
  python teraz.py example.com -o report.txt
  ```

* **Use a custom subdomain wordlist**:
  ```bash
  python teraz.py example.com -w subdomains-top1000.txt
  ```

* **Use a custom DNS resolver (e.g. Cloudflare DNS or Google DNS)**:
  ```bash
  python teraz.py example.com -r 1.1.1.1
  ```

* **Adjust worker threads for faster scanning**:
  ```bash
  python teraz.py example.com -t 30
  ```

* **Specify DNS record types**:
  ```bash
  python teraz.py example.com --dns-types A MX TXT
  ```

* **Disable Certificate Transparency (crt.sh) query (offline / fast mode)**:
  ```bash
  python teraz.py example.com --no-crt
  ```

* **Disable active HTTP/SSL Origin verification**:
  ```bash
  python teraz.py example.com --no-probe
  ```

* **Enable verbose logging**:
  ```bash
  python teraz.py example.com -v
  ```

---

### Command-Line Arguments Reference

| Argument | Short | Description | Default |
| :--- | :--- | :--- | :--- |
| `domain` | - | Target domain to scan (e.g., `example.com`) | *Required* |
| `--wordlist` | `-w` | Path to custom subdomain wordlist file | `None` |
| `--max-workers`| `-t` | Number of concurrent worker threads | `15` |
| `--resolver` | `-r` | Custom DNS resolver IP (e.g. `1.1.1.1`, `8.8.8.8`) | System default |
| `--output` | `-o` | Output file path (`.json` or `.txt`) | `None` |
| `--dns-types` | - | DNS record types to inspect (`A`, `MX`, `TXT`) | `A MX TXT` |
| `--no-crt` | - | Disable Certificate Transparency lookup | `False` |
| `--no-probe` | - | Disable active HTTP/SSL verification | `False` |
| `--verbose` | `-v` | Enable verbose logging | `False` |

---

### Example Output

```text
  ________________  ___ _____ 
 /_  __/ ____/ __ \/   /__  / 
  / / / __/ / /_/ / /| | / / 
 / / / /___/ _, _/ ___ |/ /__ 
/_/ /_____/_/ |_/_/  |_/____/ v2.0 - Pro Recon Edition
         By github.com/bimantaraz

[INFO] Loaded 22 official Cloudflare IP ranges.

--- Initiating Reconnaissance for example.com ---
[INFO] Confirmed: example.com is protected by Cloudflare.

[PHASE 1] Querying Certificate Transparency (crt.sh)...
  [+] crt.sh discovered 14 unique subdomains.

[PHASE 2] Analyzing SPF & TXT Records for Origin IPs...
  [~] Found SPF Record: v=spf1 ip4:198.51.100.25 include:_spf.google.com ~all
  [+] [SUCCESS] Potential Origin IP Found: 198.51.100.25 (Source: SPF Record (Direct IP))

[PHASE 3] Analyzing MX Records...
  [~] Found MX record: mail.example.com
  [+] [SUCCESS] Potential Origin IP Found: 198.51.100.26 (Source: MX Host (mail.example.com))

[PHASE 4] Commencing Subdomain Enumeration...
  [INFO] Scanning 75 subdomains with 15 threads...
  [-] IP 104.21.82.74 is protected by Cloudflare. (Found via: Subdomain: api.example.com)
  [+] [SUCCESS] Potential Origin IP Found: 198.51.100.27 (Source: Subdomain: direct.example.com)

[PHASE 5] Probing Potential Origin IPs (SSL & HTTP Host Header Match)...
  [★★★ CONFIRMED ORIGIN] -> 198.51.100.25
      - SSL Certificate SAN matched domain: ['example.com', '*.example.com']
      - HTML Title matched target website: 'Example Portal'
  [?] Candidate -> 198.51.100.26 (HTTP Status: 200, Title: 'Webmail Login')

==================================================
           RECONNAISSANCE COMPLETE
==================================================

[★★★] CONFIRMED ORIGIN IPs FOUND:
  -> 198.51.100.25 [CONFIRMED] (Discovered via: SPF Record (Direct IP))

[+] POTENTIAL ORIGIN IPs (Non-Cloudflare):
  -> 198.51.100.26 (Discovered via: MX Host (mail.example.com))
  -> 198.51.100.27 (Discovered via: Subdomain: direct.example.com)

[INFO] Saving scan results to results.json...
[SUCCESS] Results successfully written to results.json
```

---

### License
This project is licensed under the [MIT License](LICENSE).
