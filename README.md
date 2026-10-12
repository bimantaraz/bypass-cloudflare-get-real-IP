# bypass-cloudflare-get-origin-IP

An advanced OSINT reconnaissance tool designed to bypass Cloudflare protection and uncover the real origin IP of a protected domain.

This tool employs multiple detection vectors—including Certificate Transparency (crt.sh), passive DNS from HackerTarget & AlienVault OTX, SPF/TXT/DMARC record extraction, IPv6-aware multi-threaded subdomain enumeration, and MX record analysis—coupled with active origin validation (SSL SAN matching, HTML body similarity scoring, and HTTP Host Header probing) to minimize false positives.

---

### Key Features

* **Certificate Transparency (crt.sh)**: Queries public SSL/TLS certificate logs to discover active and historical subdomains. Multi-level subdomain extraction (e.g., `api.v2.example.com`) now fully supported.
* **Passive OSINT — HackerTarget & AlienVault OTX** *(Free, No API Key)*: Enriches subdomain and IP discovery using two independent passive DNS databases without requiring any registration or API key.
* **SPF & TXT Record Extraction**: Extracts IPv4 and IPv6 addresses from SPF records (`v=spf1 ...`), which frequently leak origin server IPs.
* **DMARC Record Parsing**: Inspects `_dmarc.<domain>` for `mailto:` references that may expose internal mail handling hosts.
* **Subdomain Hunter Mode (`--hunter`)**: Deep brute-force using built-in 30k+ wordlist (`subdomain.txt`) with chunked batch processing, adaptive 50-thread scaling, and real-time hit tracking.
* **IPv6-Aware Subdomain Enumeration**: Resolves both `A` (IPv4) and `AAAA` (IPv6) records concurrently with CNAME tracking.
* **MX Record Checking**: Resolves Mail Exchange records for both IPv4 and IPv6 mail server addresses.
* **Multi-Factor Origin Verification** *(Active Probing)*:
  * Probes candidate IPs with `Host: <domain>` headers.
  * Matches SSL/TLS certificate SANs on port 443.
  * Compares SHA-256 body hash and HTML content similarity ratio (`difflib`) against the live target baseline.
  * Computes a weighted confidence score per IP — classified as `High`, `Medium`, or `Low (Potential)`.
* **Precise Cloudflare CIDR Filtering**: Dynamically fetches official Cloudflare IPv4 & IPv6 ranges at startup with full CIDR subnet matching.
* **HTTP Session with Auto-Retry**: Uses `requests.Session` with `HTTPAdapter` retry logic — handles transient 5xx errors and connection drops automatically.
* **Progress Bar**: Real-time `tqdm` progress display during subdomain brute-force and IP probing phases.
* **Global Scan Timeout**: Abort long-running scans automatically with `--timeout`.
* **JSON, CSV & TXT Export**: Export structured results for reports, automation pipelines, or spreadsheet analysis.
* **Custom DNS Resolver**: Override local ISP DNS with any custom resolver (e.g., `1.1.1.1`, `8.8.8.8`).

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

* **Save results to JSON, CSV, or TXT**:
  ```bash
  python teraz.py example.com -o results.json
  python teraz.py example.com -o results.csv
  python teraz.py example.com -o report.txt
  ```

* **Force output format regardless of file extension**:
  ```bash
  python teraz.py example.com -o results.out --format csv
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

* **Specify DNS record types (including IPv6)**:
  ```bash
  python teraz.py example.com --dns-types A AAAA MX TXT
  ```

* **Set a global scan timeout (in seconds)**:
  ```bash
  python teraz.py example.com --timeout 120
  ```

* **Subdomain Hunter Mode (30,000+ entries from `subdomain.txt`)**:
  ```bash
  python teraz.py example.com --hunter
  python teraz.py example.com --hunter --hunter-threads 100 --timeout 60
  ```

* **Passive only — disable all active probing**:
  ```bash
  python teraz.py example.com --no-probe --timeout 30
  ```

* **Disable Certificate Transparency query**:
  ```bash
  python teraz.py example.com --no-crt
  ```

* **Disable third-party passive OSINT (HackerTarget, AlienVault)**:
  ```bash
  python teraz.py example.com --no-osint
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
| `--max-workers` | `-t` | Number of concurrent worker threads | `15` |
| `--resolver` | `-r` | Custom DNS resolver IP (e.g. `1.1.1.1`, `8.8.8.8`) | System default |
| `--output` | `-o` | Output file path (`.json`, `.csv`, or `.txt`) | `None` |
| `--format` | - | Force output format: `auto`, `json`, `csv`, `txt` | `auto` |
| `--dns-types` | - | DNS record types to inspect (`A`, `AAAA`, `MX`, `TXT`) | `A AAAA MX TXT` |
| `--timeout` | - | Global scan timeout in seconds | `None` |
| `--hunter` | - | Enable Subdomain Hunter mode using `subdomain.txt` (30k+ entries) | `False` |
| `--hunter-threads` | - | Worker threads for Hunter mode | `50` |
| `--hunter-chunk` | - | Batch chunk size for Hunter mode | `1000` |
| `--no-crt` | - | Disable Certificate Transparency (crt.sh) lookup | `False` |
| `--no-osint` | - | Disable HackerTarget & AlienVault OTX passive OSINT | `False` |
| `--no-probe` | - | Disable active HTTP/SSL verification probing | `False` |
| `--verbose` | `-v` | Enable verbose logging | `False` |

---

### Example Output

```text
  ________________  ___ _____ 
 /_  __/ ____/ __ \/   /__  / 
  / / / __/ / /_/ / /| | / / 
 / / / /___/ _, _/ ___ |/ /__ 
/_/ /_____/_/ |_/_/  |_/____/ v2.9 - Ultimate Origin Recon Edition
         By github.com/bimantaraz

[INFO] Loaded 22 official Cloudflare IP ranges.

--- Initiating Reconnaissance for example.com ---
[INFO] Confirmed: example.com is protected by Cloudflare.

[PHASE 1] Querying Certificate Transparency (crt.sh)...
  [+] crt.sh discovered 17 unique subdomains.

[PHASE 2] Querying HackerTarget Passive DNS...
  [+] HackerTarget found 9 subdomains and 3 passive DNS IPs.

[PHASE 3] Querying AlienVault OTX Passive DNS...
  [+] AlienVault OTX found 6 subdomains and 2 passive DNS IPs.

[PHASE 4] Analyzing SPF & TXT Records for Origin IPs...
  [~] Found SPF Record: v=spf1 ip4:198.51.100.25 include:_spf.google.com ~all
  [+] [SUCCESS] Potential Origin IP Found: 198.51.100.25 (Source: SPF Record (Direct IP))

[PHASE 5] Found DMARC Record: v=DMARC1; p=quarantine; rua=mailto:dmarc@mail.example.com

[PHASE 6] Analyzing MX Records...
  [~] Found MX record: mail.example.com
  [+] [SUCCESS] Potential Origin IP Found: 198.51.100.26 (Source: MX Host [A] (mail.example.com))

[PHASE 7] Commencing Subdomain Enumeration...
  [INFO] Scanning 280 subdomains with 15 threads...
Subdomain Brute: 100%|████████████████████| 280/280 [00:09<00:00, 30.1sub/s]
  [-] IP 104.21.82.74 is protected by Cloudflare. (Found via: Subdomain A: api.example.com)
  [+] [SUCCESS] Potential Origin IP Found: 198.51.100.27 (Source: Subdomain A: direct.example.com)
  [+] [SUCCESS] Potential Origin IP Found: 2606:4700::c0a3:1 (Source: Subdomain AAAA: origin.example.com)

[PHASE 8] Probing Potential Origin IPs (SSL, Host Header & Content Match)...
Probing Candidates: 100%|████████████████████| 4/4 [00:05<00:00, 1.3ip/s]
  [★★★ HIGH (CONFIRMED ORIGIN)] -> 198.51.100.25
      - SSL Certificate SAN matched domain: ['example.com', '*.example.com']
      - HTML Title matched target website: 'Example Portal'
      - Content similarity ratio: 96.3% (Hash match: False)
  [★★★ MEDIUM (STRONG CANDIDATE)] -> 198.51.100.27
      - SSL Certificate SAN matched domain: ['direct.example.com']
      - Content similarity ratio: 71.2% (Hash match: False)
  [?] Candidate -> 198.51.100.26 (Status: 200, Title: 'Webmail Login', Similarity: 12.4%)

==================================================
           RECONNAISSANCE COMPLETE
==================================================

[★★★] CONFIRMED ORIGIN IPs FOUND:
  -> 198.51.100.25 [High (Confirmed Origin)] (Sources: SPF Record (Direct IP))
  -> 198.51.100.27 [Medium (Strong Candidate)] (Sources: Subdomain A: direct.example.com)

[+] POTENTIAL ORIGIN IPs (Non-Cloudflare):
  -> 198.51.100.26 (Discovered via: MX Host [A] (mail.example.com))

[INFO] Saving scan results to results.csv...
[SUCCESS] Results successfully written to results.csv (Format: CSV)
```

---

### License
This project is licensed under the [MIT License](LICENSE).
