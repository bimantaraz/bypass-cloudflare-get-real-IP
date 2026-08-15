import dns.resolver
import socket
import ssl
import re
import json
import argparse
import sys
import time
import ipaddress
import warnings
from concurrent.futures import ThreadPoolExecutor, as_completed

# Suppress noisy library warnings
warnings.filterwarnings('ignore')

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False

from termcolor import colored

LOGO = """
  ________________  ___ _____ 
 /_  __/ ____/ __ \/   /__  / 
  / / / __/ / /_/ / /| | / / 
 / / / /___/ _, _/ ___ |/ /__ 
/_/ /_____/_/ |_/_/  |_/____/ v2.0 - Pro Recon Edition
         By github.com/bimantaraz
"""

DEFAULT_SUBDOMAINS = [
    # Mail & Communications
    "mail", "email", "webmail", "mail1", "mail2", "mx", "mx1", "mx2", "smtp", "smtp1", 
    "smtp2", "pop", "pop3", "imap", "exchange", "owa", "autodiscover", "autoconfig",
    "direct", "direct-connect", "origin", "origin-www", "origin-app", "origin-api", 
    "origin-mail", "server", "host", "host1", "host2", "ip", "realip", "vps", "node",
    "admin", "administrator", "manage", "management", "portal", "cp", "cpanel", "whm", 
    "webdisk", "plesk", "panel", "control", "dashboard", "root", "superadmin",
    "dev", "devel", "development", "staging", "stage", "stg", "test", "testing", 
    "uat", "sandbox", "demo", "preview", "beta", "alpha", "prod", "production", 
    "release", "qa", "lab", "temp", "tmp", "old", "new", "v1", "v2", "v3",
    "auth", "login", "signin", "sso", "oauth", "id", "identity", "account", 
    "accounts", "register", "signup", "users", "member", "members", "profile",
    "api", "api-dev", "api-stage", "api-test", "api-prod", "api1", "api2", "apis", 
    "rest", "graphql", "ws", "websocket", "socket", "gateway", "gw", "backend", 
    "frontend", "app", "apps", "m", "mobile", "web", "www2", "www1",
    "ci", "cd", "git", "gitlab", "github", "jenkins", "registry", "docker", "k8s", 
    "kube", "devops", "cloud", "public", "cluster", "monitor", "monitoring", 
    "grafana", "kibana", "prometheus", "zabbix", "status", "health", "nagios", 
    "uptime", "alert", "alerts", "log", "logs", "logging", "sentry",
    "db", "database", "sql", "mysql", "postgres", "pg", "mongo", "mongodb", 
    "redis", "elastic", "elasticsearch", "memcached", "phpmyadmin", "pma", "adminer", 
    "backup", "backups", "bak", "storage", "files", "fileserver", "file", "assets", 
    "static", "media", "images", "img", "cdn", "s3", "bucket", "minio", "webdav", 
    "upload", "uploads", "download", "downloads", "share", "nas",
    "internal", "intranet", "corp", "corporate", "office", "vpn", "vpn1", "vpn2", 
    "remote", "access", "connect", "ssh", "sftp", "rdp", "vnc", "proxy", "relay", 
    "fw", "firewall", "router", "ns", "ns1", "ns2", "ns3", "ns4", "dns", "dns1", "dns2",
    "shop", "store", "cart", "checkout", "pay", "payment", "billing", "invoice", 
    "support", "help", "helpdesk", "ticket", "tickets", "desk", "crm", "erp", 
    "hrm", "sales", "leads", "affiliates", "affiliate", "partner", "partners", 
    "docs", "documentation", "wiki", "confluence", "jira", "chat", "forum", 
    "community", "blog", "news", "press",
    "wp", "wordpress", "magento", "joomla", "drupal", "laravel", "django"
]

class OriginReaper:
    def __init__(self, domain, wordlist=None, max_workers=15, resolver=None, 
                 output=None, dns_types=None, no_crt=False, no_probe=False, verbose=False):
        if not domain:
            raise ValueError("Domain cannot be null or empty.")
            
        self.domain = domain.lower().strip()
        self.wordlist = wordlist
        self.max_workers = max_workers
        self.output_file = output
        self.no_crt = no_crt
        self.no_probe = no_probe
        self.verbose = verbose
        
        # DNS types filtering
        if dns_types:
            self.dns_types = [t.upper() for t in dns_types]
        else:
            self.dns_types = ["A", "MX", "TXT"]

        # Results tracking
        self.real_ips = {}           # ip -> set of sources
        self.cf_ips = set()           # set of cf ips
        self.confirmed_origins = {}   # ip -> validation details
        self.subdomains_to_scan = set()

        # DNS resolver initialization
        self.resolver = dns.resolver.Resolver()
        if resolver:
            self.resolver.nameservers = [resolver]
            print(colored(f"[INFO] Using custom DNS Resolver: {resolver}", "cyan"))
        self.resolver.timeout = 5
        self.resolver.lifetime = 5

        # Fetch Cloudflare CIDRs
        self.cloudflare_networks = self._fetch_cloudflare_ips()
        print(colored(f"[INFO] Loaded {len(self.cloudflare_networks)} official Cloudflare IP ranges.", "cyan", attrs=["bold"]))

        # Baseline website signature
        self.target_signature = self._get_target_signature()

    def _fetch_cloudflare_ips(self):
        try:
            v4_response = requests.get("https://www.cloudflare.com/ips-v4", timeout=10)
            v6_response = requests.get("https://www.cloudflare.com/ips-v6", timeout=10)
            v4_response.raise_for_status()
            v6_response.raise_for_status()
            lines = v4_response.text.splitlines() + v6_response.text.splitlines()
            networks = []
            for line in lines:
                line = line.strip()
                if line:
                    networks.append(ipaddress.ip_network(line))
            return networks
        except requests.exceptions.RequestException as e:
            print(colored(f"[ERROR] Could not fetch Cloudflare IP ranges: {e}", "red"))
            return []
        except ValueError as e:
            print(colored(f"[ERROR] Invalid CIDR in Cloudflare IPs: {e}", "red"))
            return []

    def _is_cloudflare_ip(self, ip_str):
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            for net in self.cloudflare_networks:
                if ip_obj in net:
                    return True
        except ValueError:
            pass
        return False

    def is_domain_cloudflare(self, domain_str):
        try:
            answers = self.resolver.resolve(domain_str, 'A')
            for rdata in answers:
                if self._is_cloudflare_ip(str(rdata)):
                    return True
        except Exception:
            try:
                domain_ips = set([str(i[4][0]) for i in socket.getaddrinfo(domain_str, None)])
                for dip in domain_ips:
                    if self._is_cloudflare_ip(dip):
                        return True
            except socket.gaierror:
                pass
        return False

    def _get_target_signature(self):
        """Fetches baseline signature from public domain (Title, Server header, Status Code)."""
        signature = {"title": None, "status_code": None, "server": None}
        for proto in ["https", "http"]:
            url = f"{proto}://{self.domain}"
            try:
                res = requests.get(url, timeout=6, headers={"User-Agent": "Mozilla/5.0"}, verify=False)
                signature["status_code"] = res.status_code
                signature["server"] = res.headers.get("Server", "")
                title_match = re.search(r"<title[^>]*>(.*?)</title>", res.text, re.IGNORECASE | re.DOTALL)
                if title_match:
                    signature["title"] = title_match.group(1).strip()
                break
            except Exception:
                continue
        return signature

    def _add_result(self, ip, source):
        if not ip:
            return
        
        # Clean IP representation
        ip = str(ip).strip()
        
        if self._is_cloudflare_ip(ip):
            if ip not in self.cf_ips:
                print(colored(f"  [-] IP {ip} is protected by Cloudflare. (Found via: {source})", "yellow"))
                self.cf_ips.add(ip)
        else:
            if ip not in self.real_ips:
                self.real_ips[ip] = set()
                print(colored(f"  [+] [SUCCESS] Potential Origin IP Found: {ip} (Source: {source})", "green", attrs=['bold']))
            self.real_ips[ip].add(source)

    def fetch_crt_sh_subdomains(self):
        """Queries Certificate Transparency logs (crt.sh) for historical and active subdomains."""
        if self.no_crt:
            return set()
            
        print(colored("\n[PHASE 1] Querying Certificate Transparency (crt.sh)...", "yellow", attrs=["bold"]))
        discovered = set()
        url = f"https://crt.sh/?q=%.{self.domain}&output=json"
        try:
            headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
            response = requests.get(url, headers=headers, timeout=15)
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    name_value = entry.get("name_value", "")
                    for sub in name_value.splitlines():
                        sub = sub.strip().lower()
                        # Clean wildcards
                        if sub.startswith("*."):
                            sub = sub[2:]
                        if sub and sub.endswith(f".{self.domain}"):
                            # Extract subdomain prefix
                            sub_prefix = sub[:-len(f".{self.domain}")]
                            if sub_prefix and "." not in sub_prefix:
                                discovered.add(sub_prefix)
                print(colored(f"  [+] crt.sh discovered {len(discovered)} unique subdomains.", "cyan"))
            else:
                print(colored(f"  [!] crt.sh returned status code {response.status_code}. Skipping.", "magenta"))
        except requests.exceptions.Timeout:
            print(colored("  [!] crt.sh query timed out. Skipping to next phase.", "magenta"))
        except Exception as e:
            print(colored(f"  [!] Could not retrieve data from crt.sh: {e}", "magenta"))
            
        return discovered

    def check_spf_txt_records(self):
        """Extracts IPv4 and IPv6 addresses directly from SPF / TXT records."""
        if "TXT" not in self.dns_types:
            return

        print(colored("\n[PHASE 2] Analyzing SPF & TXT Records for Origin IPs...", "yellow", attrs=["bold"]))
        try:
            answers = self.resolver.resolve(self.domain, 'TXT', lifetime=5)
            for rdata in answers:
                txt_record = str(rdata).strip('"')
                if "v=spf1" in txt_record:
                    print(colored(f"  [~] Found SPF Record: {txt_record}", "cyan"))
                    
                    # Extract ip4 and ip6 items
                    ip4_matches = re.findall(r'ip4:([0-9a-fA-F\.\/]+)', txt_record)
                    ip6_matches = re.findall(r'ip6:([0-9a-fA-F:\.\/]+)', txt_record)
                    
                    for match in ip4_matches + ip6_matches:
                        try:
                            # Check if single IP or small CIDR
                            if "/" in match:
                                net = ipaddress.ip_network(match, strict=False)
                                if net.num_addresses <= 16:
                                    for host_ip in net.hosts():
                                        self._add_result(str(host_ip), f"SPF Record ({match})")
                                else:
                                    self._add_result(str(net.network_address), f"SPF Network ({match})")
                            else:
                                self._add_result(match, "SPF Record (Direct IP)")
                        except ValueError:
                            continue
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            print(colored("  [INFO] No TXT records found.", "cyan"))
        except Exception as e:
            print(colored(f"  [!] Error resolving TXT records: {e}", "red"))

    def check_mx_records(self):
        """Resolves mail exchange (MX) hosts to inspect mail server origin IPs."""
        if "MX" not in self.dns_types:
            return

        print(colored("\n[PHASE 3] Analyzing MX Records...", "yellow", attrs=["bold"]))
        try:
            answers = self.resolver.resolve(self.domain, 'MX', lifetime=5)
            for rdata in answers:
                mail_server = str(rdata.exchange).rstrip('.')
                if not mail_server:
                    continue
                print(colored(f"  [~] Found MX record: {mail_server}", "cyan"))
                try:
                    mail_ips = self.resolver.resolve(mail_server, 'A', lifetime=5)
                    for ip_data in mail_ips:
                        self._add_result(str(ip_data), f"MX Host ({mail_server})")
                except Exception as e:
                    if self.verbose:
                        print(colored(f"  [!] Could not resolve mail server {mail_server}: {e}", "magenta"))
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            print(colored("  [INFO] No MX records found.", "cyan"))
        except Exception as e:
            print(colored(f"  [!] Error resolving MX records: {e}", "red"))

    def _resolve_subdomain(self, subdomain):
        target = f"{subdomain}.{self.domain}"
        try:
            answers = self.resolver.resolve(target, 'A', lifetime=5)
            for rdata in answers:
                ip = str(rdata)
                if self.verbose:
                    print(colored(f"  [~] Resolved {target} -> {ip}", "magenta"))
                self._add_result(ip, f"Subdomain: {target}")
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
            pass
        except Exception as e:
            if self.verbose:
                print(colored(f"  [!] Error resolving {target}: {e}", "red"))

    def scan_subdomains(self, crt_subs=None):
        """Builds combined subdomain list and performs concurrent DNS resolution."""
        if "A" not in self.dns_types:
            return

        print(colored("\n[PHASE 4] Commencing Subdomain Enumeration...", "yellow", attrs=["bold"]))
        
        # Build list
        subdomain_set = set(DEFAULT_SUBDOMAINS)
        
        # Merge external wordlist if specified
        if self.wordlist:
            try:
                with open(self.wordlist, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        w = line.strip().lower()
                        if w and not w.startswith("#"):
                            subdomain_set.add(w)
                print(colored(f"  [INFO] Loaded wordlist from {self.wordlist} (Total targets: {len(subdomain_set)})", "cyan"))
            except Exception as e:
                print(colored(f"  [ERROR] Could not read wordlist file: {e}", "red"))

        # Merge crt.sh discovered subdomains
        if crt_subs:
            subdomain_set.update(crt_subs)
        
        print(colored(f"  [INFO] Scanning {len(subdomain_set)} subdomains with {self.max_workers} threads...", "cyan"))

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(self._resolve_subdomain, sub): sub for sub in subdomain_set}
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception:
                    pass

    def _get_ssl_sans(self, ip, port=443, timeout=4):
        """Extracts SSL SANs and Common Name from IP on port 443."""
        sans = []
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((ip, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.domain) as ssock:
                    der_cert = ssock.getpeercert(binary_form=True)
                    if der_cert and CRYPTOGRAPHY_AVAILABLE:
                        cert = x509.load_der_x509_certificate(der_cert, default_backend())
                        try:
                            ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                            sans = ext.value.get_values_for_type(x509.DNSName)
                        except Exception:
                            pass
        except Exception:
            pass
        return sans

    def _probe_single_ip(self, ip):
        """Performs SSL certificate inspection and direct HTTP/HTTPS Host Header probing."""
        probe_data = {
            "ip": ip,
            "ssl_sans": [],
            "ssl_matched": False,
            "http_status": None,
            "http_title": None,
            "http_server": None,
            "title_matched": False,
            "is_confirmed": False,
            "confidence": "Potential"
        }

        # 1. SSL SAN Check
        sans = self._get_ssl_sans(ip)
        probe_data["ssl_sans"] = sans
        for san in sans:
            san_clean = san.lower().strip()
            if san_clean == self.domain or san_clean == f"*.{self.domain}" or (san_clean.endswith(f".{self.domain}")):
                probe_data["ssl_matched"] = True
                break

        # 2. HTTP / HTTPS Host Header Probing
        headers = {
            "Host": self.domain,
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        }
        
        for proto in ["https", "http"]:
            url = f"{proto}://{ip}"
            try:
                res = requests.get(url, headers=headers, timeout=5, verify=False, allow_redirects=True)
                probe_data["http_status"] = res.status_code
                probe_data["http_server"] = res.headers.get("Server", "Unknown")
                
                title_match = re.search(r"<title[^>]*>(.*?)</title>", res.text, re.IGNORECASE | re.DOTALL)
                if title_match:
                    probe_data["http_title"] = title_match.group(1).strip()
                    if self.target_signature["title"] and (probe_data["http_title"] == self.target_signature["title"]):
                        probe_data["title_matched"] = True
                break
            except Exception:
                continue

        # Determine Confirmation
        if probe_data["ssl_matched"] or probe_data["title_matched"]:
            probe_data["is_confirmed"] = True
            probe_data["confidence"] = "High (Confirmed Origin)"
        
        return probe_data

    def validate_origin_ips(self):
        """Probes all non-Cloudflare candidate IPs to filter out false positives."""
        if self.no_probe or not self.real_ips:
            return

        print(colored("\n[PHASE 5] Probing Potential Origin IPs (SSL & HTTP Host Header Match)...", "yellow", attrs=["bold"]))
        
        with ThreadPoolExecutor(max_workers=min(10, len(self.real_ips))) as executor:
            future_to_ip = {executor.submit(self._probe_single_ip, ip): ip for ip in self.real_ips}
            for future in as_completed(future_to_ip):
                ip = future_to_ip[future]
                try:
                    result = future.result()
                    self.confirmed_origins[ip] = result
                    
                    if result["is_confirmed"]:
                        print(colored(f"  [★★★ CONFIRMED ORIGIN] -> {ip}", "green", attrs=["bold"]))
                        if result["ssl_matched"]:
                            print(colored(f"      - SSL Certificate SAN matched domain: {result['ssl_sans']}", "green"))
                        if result["title_matched"]:
                            print(colored(f"      - HTML Title matched target website: '{result['http_title']}'", "green"))
                    else:
                        print(colored(f"  [?] Candidate -> {ip} (HTTP Status: {result['http_status']}, Title: '{result['http_title']}')", "cyan"))
                except Exception as e:
                    if self.verbose:
                        print(colored(f"  [!] Error probing {ip}: {e}", "red"))

    def export_results(self):
        """Saves scan results to JSON or TXT file if requested."""
        if not self.output_file:
            return

        print(colored(f"\n[INFO] Saving scan results to {self.output_file}...", "cyan"))
        
        confirmed_list = []
        potential_list = []
        
        for ip, sources in self.real_ips.items():
            probe_info = self.confirmed_origins.get(ip, {})
            item = {
                "ip": ip,
                "sources": list(sources),
                "is_confirmed": probe_info.get("is_confirmed", False),
                "ssl_matched": probe_info.get("ssl_matched", False),
                "ssl_sans": probe_info.get("ssl_sans", []),
                "http_status": probe_info.get("http_status"),
                "http_title": probe_info.get("http_title"),
                "http_server": probe_info.get("http_server")
            }
            if item["is_confirmed"]:
                confirmed_list.append(item)
            else:
                potential_list.append(item)

        export_data = {
            "target_domain": self.domain,
            "scan_timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "target_baseline": self.target_signature,
            "summary": {
                "confirmed_origins_count": len(confirmed_list),
                "potential_origins_count": len(potential_list),
                "cloudflare_ips_count": len(self.cf_ips)
            },
            "confirmed_origin_ips": confirmed_list,
            "potential_origin_ips": potential_list,
            "cloudflare_ips": list(self.cf_ips)
        }

        try:
            if self.output_file.lower().endswith(".json"):
                with open(self.output_file, 'w', encoding='utf-8') as f:
                    json.dump(export_data, f, indent=4)
            else:
                with open(self.output_file, 'w', encoding='utf-8') as f:
                    f.write(f"=== OriginReaper Scan Report for {self.domain} ===\n")
                    f.write(f"Date: {export_data['scan_timestamp']}\n\n")
                    f.write("[+] CONFIRMED ORIGIN IPs:\n")
                    for item in confirmed_list:
                        f.write(f"  -> {item['ip']} (Sources: {', '.join(item['sources'])})\n")
                        f.write(f"     Title: {item['http_title']} | SSL SANs: {item['ssl_sans']}\n")
                    f.write("\n[~] POTENTIAL ORIGIN IPs:\n")
                    for item in potential_list:
                        f.write(f"  -> {item['ip']} (Sources: {', '.join(item['sources'])})\n")
                    f.write("\n[-] CLOUDFLARE IPs:\n")
                    for cf in self.cf_ips:
                        f.write(f"  -> {cf}\n")
            print(colored(f"[SUCCESS] Results successfully written to {self.output_file}", "green", attrs=["bold"]))
        except Exception as e:
            print(colored(f"[ERROR] Failed to save output file: {e}", "red"))

    def run(self):
        print(colored(f"\n--- Initiating Reconnaissance for {self.domain} ---", "white", attrs=["bold"]))
        
        if not self.is_domain_cloudflare(self.domain):
            print(colored(f"[WARNING] {self.domain} does not appear to be protected by Cloudflare. Direct resolution may be possible.", "magenta"))
        else:
            print(colored(f"[INFO] Confirmed: {self.domain} is protected by Cloudflare.", "green"))

        # Execution Phases
        crt_subs = self.fetch_crt_sh_subdomains()
        self.check_spf_txt_records()
        self.check_mx_records()
        self.scan_subdomains(crt_subs)
        self.validate_origin_ips()

        # Final Summary
        print(colored("\n" + "="*50, "white"))
        print(colored("           RECONNAISSANCE COMPLETE", "white", attrs=["bold"]))
        print(colored("="*50, "white"))

        confirmed = [ip for ip, data in self.confirmed_origins.items() if data.get("is_confirmed")]
        
        if confirmed:
            print(colored("\n[★★★] CONFIRMED ORIGIN IPs FOUND:", "green", attrs=["bold"]))
            for ip in confirmed:
                sources = ", ".join(self.real_ips[ip])
                print(colored(f"  -> {ip} [CONFIRMED] (Discovered via: {sources})", "green", attrs=['bold']))
        
        remaining_potentials = [ip for ip in self.real_ips if ip not in confirmed]
        if remaining_potentials:
            print(colored("\n[+] POTENTIAL ORIGIN IPs (Non-Cloudflare):", "cyan", attrs=["bold"]))
            for ip in remaining_potentials:
                sources = ", ".join(self.real_ips[ip])
                print(colored(f"  -> {ip} (Discovered via: {sources})", "cyan"))

        if not self.real_ips:
            if self.cf_ips:
                print(colored("\n[-] Could not find the real origin IP.", "red", attrs=["bold"]))
                print(colored("All discovered IPs are protected by Cloudflare:", "yellow"))
                for ip in self.cf_ips:
                    print(colored(f"  -> {ip}", "yellow"))
            else:
                print(colored("\nMission concluded. No origin IPs discovered through these vectors.", "red", attrs=["bold"]))

        # Output to file
        self.export_results()

def main():
    print(colored(LOGO, "cyan", attrs=["bold"]))
    
    parser = argparse.ArgumentParser(
        description="OriginReaper v2.0 - Advanced OSINT tool to bypass Cloudflare and uncover real origin IPs.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("domain", help="The target domain to scan (e.g. example.com).")
    parser.add_argument("-w", "--wordlist", help="Path to custom subdomain wordlist file.", default=None)
    parser.add_argument("-t", "--max-workers", help="Number of concurrent worker threads (default: 15).", type=int, default=15)
    parser.add_argument("-r", "--resolver", help="Custom DNS resolver IP address (e.g. 1.1.1.1, 8.8.8.8).", default=None)
    parser.add_argument("-o", "--output", help="Save scan results to a JSON or TXT file.", default=None)
    parser.add_argument("--dns-types", nargs="+", help="Specific DNS record types to check (e.g. A MX TXT).", default=None)
    parser.add_argument("--no-crt", action="store_true", help="Disable Certificate Transparency (crt.sh) queries.")
    parser.add_argument("--no-probe", action="store_true", help="Disable active HTTP / SSL Origin verification probing.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output during scanning.")
    
    args = parser.parse_args()

    try:
        reaper = OriginReaper(
            domain=args.domain,
            wordlist=args.wordlist,
            max_workers=args.max_workers,
            resolver=args.resolver,
            output=args.output,
            dns_types=args.dns_types,
            no_crt=args.no_crt,
            no_probe=args.no_probe,
            verbose=args.verbose
        )
        reaper.run()
    except KeyboardInterrupt:
        print(colored("\n[!] Scan aborted by user.", "yellow"))
        sys.exit(0)
    except Exception as e:
        print(colored(f"\n[FATAL] A critical error occurred: {e}", "red", attrs=['bold']), file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
