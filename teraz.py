import dns.resolver
import socket
import ssl
import re
import json
import csv
import hashlib
import difflib
import argparse
import sys
import time
import ipaddress
import warnings
import threading
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

BUILTIN_HUNTER_FILE = Path(__file__).resolve().parent / "subdomain.txt"

warnings.filterwarnings('ignore')

import requests
import urllib3
from requests.adapters import HTTPAdapter
from urllib3.util import Retry
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False

try:
    from tqdm import tqdm
    TQDM_AVAILABLE = True
except ImportError:
    TQDM_AVAILABLE = False

from termcolor import colored

LOGO = """
  ________________  ___ _____ 
 /_  __/ ____/ __ \\/   /__  / 
  / / / __/ / /_/ / /| | / / 
 / / / /___/ _, _/ ___ |/ /__ 
/_/ /_____/_/ |_/_/  |_/____/ v2.9 - Ultimate Origin Recon Edition
         By github.com/bimantaraz
"""

DEFAULT_SUBDOMAINS = [
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
                 output=None, output_format="auto", dns_types=None, no_crt=False,
                 no_osint=False, no_probe=False, verbose=False, timeout=None,
                 hunter=False, hunter_threads=50, hunter_chunk=1000):
        if not domain:
            raise ValueError("Domain cannot be null or empty.")
            
        self.domain = domain.lower().strip()
        self.wordlist = wordlist
        self.hunter = hunter
        self.hunter_chunk = hunter_chunk
        if self.hunter and (max_workers == 15 or max_workers is None):
            self.max_workers = hunter_threads
        else:
            self.max_workers = max_workers
        self.output_file = output
        self.output_format = output_format.lower()
        self.no_crt = no_crt
        self.no_osint = no_osint
        self.no_probe = no_probe
        self.verbose = verbose
        self.timeout = timeout
        self.start_time = time.time()
        
        self.lock = threading.Lock()

        self.session = self._create_session()
        
        if dns_types:
            self.dns_types = [t.upper() for t in dns_types]
        else:
            self.dns_types = ["A", "AAAA", "MX", "TXT"]

        self.real_ips = {}
        self.cf_ips = set()
        self.confirmed_origins = {}
        self.cnames = {}
        self.subdomains_to_scan = set()

        self.resolver = dns.resolver.Resolver()
        if resolver:
            self.resolver.nameservers = [resolver]
            print(colored(f"[INFO] Using custom DNS Resolver: {resolver}", "cyan"))
        dns_timeout = 3 if self.hunter else 5
        self.resolver.timeout = dns_timeout
        self.resolver.lifetime = dns_timeout

        self.cloudflare_networks = self._fetch_cloudflare_ips()
        print(colored(f"[INFO] Loaded {len(self.cloudflare_networks)} official Cloudflare IP ranges.", "cyan", attrs=["bold"]))

        self.target_signature = self._get_target_signature()

    def _create_session(self):
        session = requests.Session()
        retries = Retry(
            total=2,
            backoff_factor=0.3,
            status_forcelist=[500, 502, 503, 504],
            raise_on_status=False
        )
        adapter = HTTPAdapter(max_retries=retries, pool_connections=self.max_workers, pool_maxsize=self.max_workers * 2)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        return session

    def _is_timed_out(self):
        if self.timeout and (time.time() - self.start_time) > self.timeout:
            return True
        return False

    def _fetch_cloudflare_ips(self):
        try:
            v4_response = self.session.get("https://www.cloudflare.com/ips-v4", timeout=10)
            v6_response = self.session.get("https://www.cloudflare.com/ips-v6", timeout=10)
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
        signature = {
            "title": None,
            "status_code": None,
            "server": None,
            "body_hash": None,
            "body_sample": None,
            "content_length": None
        }
        for proto in ["https", "http"]:
            url = f"{proto}://{self.domain}"
            try:
                res = self.session.get(
                    url,
                    timeout=7,
                    headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"},
                    verify=False,
                    allow_redirects=True
                )
                signature["status_code"] = res.status_code
                signature["server"] = res.headers.get("Server", "")
                signature["content_length"] = len(res.content)
                signature["body_hash"] = hashlib.sha256(res.content).hexdigest()
                signature["body_sample"] = res.text[:8000]
                
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
        
        ip = str(ip).strip()
        
        with self.lock:
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
        if self.no_crt or self._is_timed_out():
            return set()
            
        print(colored("\n[PHASE 1] Querying Certificate Transparency (crt.sh)...", "yellow", attrs=["bold"]))
        discovered = set()
        url = f"https://crt.sh/?q=%.{self.domain}&output=json"
        try:
            headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
            response = self.session.get(url, headers=headers, timeout=15)
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    name_value = entry.get("name_value", "")
                    for sub in name_value.splitlines():
                        sub = sub.strip().lower()
                        sub = re.sub(r'^\*+\.?', '', sub).strip('.')
                        if sub == self.domain:
                            continue
                        if sub.endswith(f".{self.domain}"):
                            sub_prefix = sub[:-len(f".{self.domain}")].strip('.')
                            if sub_prefix:
                                discovered.add(sub_prefix)
                print(colored(f"  [+] crt.sh discovered {len(discovered)} unique subdomains.", "cyan"))
            else:
                print(colored(f"  [!] crt.sh returned status code {response.status_code}. Skipping.", "magenta"))
        except requests.exceptions.Timeout:
            print(colored("  [!] crt.sh query timed out. Skipping to next phase.", "magenta"))
        except Exception as e:
            print(colored(f"  [!] Could not retrieve data from crt.sh: {e}", "magenta"))
            
        return discovered

    def fetch_hackertarget_records(self):
        if self.no_osint or self._is_timed_out():
            return set()
        
        print(colored("\n[PHASE 2] Querying HackerTarget Passive DNS...", "yellow", attrs=["bold"]))
        discovered_subs = set()
        url = f"https://api.hackertarget.com/hostsearch/?q={self.domain}"
        try:
            headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
            res = self.session.get(url, headers=headers, timeout=12)
            if res.status_code == 200 and "error" not in res.text.lower():
                lines = res.text.splitlines()
                count = 0
                for line in lines:
                    line = line.strip()
                    if not line or "," not in line:
                        continue
                    parts = line.split(",", 1)
                    host = parts[0].strip().lower()
                    ip = parts[1].strip() if len(parts) > 1 else ""
                    if host.endswith(f".{self.domain}") and host != self.domain:
                        sub_prefix = host[:-len(f".{self.domain}")].strip('.')
                        if sub_prefix:
                            discovered_subs.add(sub_prefix)
                    if ip:
                        self._add_result(ip, f"HackerTarget ({host})")
                        count += 1
                print(colored(f"  [+] HackerTarget found {len(discovered_subs)} subdomains and {count} passive DNS IPs.", "cyan"))
            else:
                if self.verbose:
                    print(colored(f"  [!] HackerTarget response: {res.text[:80]}", "magenta"))
        except Exception as e:
            if self.verbose:
                print(colored(f"  [!] Error querying HackerTarget: {e}", "magenta"))
        return discovered_subs

    def fetch_alienvault_records(self):
        if self.no_osint or self._is_timed_out():
            return set()

        print(colored("\n[PHASE 3] Querying AlienVault OTX Passive DNS...", "yellow", attrs=["bold"]))
        discovered_subs = set()
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{self.domain}/passive_dns"
        try:
            headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
            res = self.session.get(url, headers=headers, timeout=15)
            if res.status_code == 200:
                data = res.json()
                records = data.get("passive_dns", [])
                count = 0
                for r in records:
                    hostname = r.get("hostname", "").strip().lower()
                    address = r.get("address", "").strip()
                    record_type = r.get("record_type", "").upper()
                    if hostname.endswith(f".{self.domain}") and hostname != self.domain:
                        sub_prefix = hostname[:-len(f".{self.domain}")].strip('.')
                        if sub_prefix:
                            discovered_subs.add(sub_prefix)
                    if address and record_type in ["A", "AAAA"]:
                        self._add_result(address, f"AlienVault OTX ({hostname})")
                        count += 1
                print(colored(f"  [+] AlienVault OTX found {len(discovered_subs)} subdomains and {count} passive DNS IPs.", "cyan"))
        except Exception as e:
            if self.verbose:
                print(colored(f"  [!] Error querying AlienVault OTX: {e}", "magenta"))
        return discovered_subs

    def check_spf_txt_records(self):
        if "TXT" not in self.dns_types or self._is_timed_out():
            return

        print(colored("\n[PHASE 4] Analyzing SPF & TXT Records for Origin IPs...", "yellow", attrs=["bold"]))
        try:
            answers = self.resolver.resolve(self.domain, 'TXT', lifetime=5)
            for rdata in answers:
                txt_record = str(rdata).strip('"')
                if "v=spf1" in txt_record:
                    print(colored(f"  [~] Found SPF Record: {txt_record}", "cyan"))
                    
                    ip4_matches = re.findall(r'ip4:([0-9a-fA-F\.\/]+)', txt_record)
                    ip6_matches = re.findall(r'ip6:([0-9a-fA-F:\.\/]+)', txt_record)
                    
                    for match in ip4_matches + ip6_matches:
                        try:
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

    def check_dmarc_records(self):
        if "TXT" not in self.dns_types or self._is_timed_out():
            return
        
        target = f"_dmarc.{self.domain}"
        try:
            answers = self.resolver.resolve(target, 'TXT', lifetime=5)
            for rdata in answers:
                txt_record = str(rdata).strip('"')
                if "v=dmarc1" in txt_record.lower():
                    print(colored(f"\n[PHASE 5] Found DMARC Record: {txt_record}", "yellow", attrs=["bold"]))
                    mailtos = re.findall(r'mailto:([^\s,;@]+@([a-zA-Z0-9.-]+))', txt_record)
                    for _, host in mailtos:
                        host = host.lower().strip()
                        if host != self.domain and host.endswith(f".{self.domain}"):
                            try:
                                ips = self.resolver.resolve(host, 'A', lifetime=5)
                                for ip in ips:
                                    self._add_result(str(ip), f"DMARC Host ({host})")
                            except Exception:
                                pass
        except Exception:
            pass

    def check_mx_records(self):
        if "MX" not in self.dns_types or self._is_timed_out():
            return

        print(colored("\n[PHASE 6] Analyzing MX Records...", "yellow", attrs=["bold"]))
        try:
            answers = self.resolver.resolve(self.domain, 'MX', lifetime=5)
            for rdata in answers:
                mail_server = str(rdata.exchange).rstrip('.')
                if not mail_server:
                    continue
                print(colored(f"  [~] Found MX record: {mail_server}", "cyan"))
                try:
                    records_to_check = [rtype for rtype in ["A", "AAAA"] if rtype in self.dns_types]
                    for rtype in records_to_check:
                        mail_ips = self.resolver.resolve(mail_server, rtype, lifetime=5)
                        for ip_data in mail_ips:
                            self._add_result(str(ip_data), f"MX Host [{rtype}] ({mail_server})")
                except Exception as e:
                    if self.verbose:
                        print(colored(f"  [!] Could not resolve mail server {mail_server}: {e}", "magenta"))
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            print(colored("  [INFO] No MX records found.", "cyan"))
        except Exception as e:
            print(colored(f"  [!] Error resolving MX records: {e}", "red"))

    def _resolve_subdomain(self, subdomain):
        if self._is_timed_out():
            return
        target = f"{subdomain}.{self.domain}"
        
        try:
            cnames = self.resolver.resolve(target, 'CNAME', lifetime=4)
            for cname in cnames:
                cname_target = str(cname.target).rstrip('.')
                with self.lock:
                    self.cnames[target] = cname_target
                if self.verbose:
                    print(colored(f"  [~] CNAME: {target} -> {cname_target}", "magenta"))
        except Exception:
            pass

        records_to_check = [rtype for rtype in ["A", "AAAA"] if rtype in self.dns_types]
        for rtype in records_to_check:
            try:
                answers = self.resolver.resolve(target, rtype, lifetime=4)
                for rdata in answers:
                    ip = str(rdata).strip()
                    if self.verbose:
                        print(colored(f"  [~] Resolved {target} [{rtype}] -> {ip}", "magenta"))
                    self._add_result(ip, f"Subdomain {rtype}: {target}")
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
                pass
            except Exception as e:
                if self.verbose:
                    print(colored(f"  [!] Error resolving {target} [{rtype}]: {e}", "red"))

    def scan_subdomains(self, extra_subs=None):
        if not any(t in self.dns_types for t in ["A", "AAAA"]) or self._is_timed_out():
            return

        phase_title = "\n[PHASE 7] Commencing Subdomain Hunter (30k+ Wordlist)..." if self.hunter else "\n[PHASE 7] Commencing Subdomain Enumeration..."
        print(colored(phase_title, "yellow", attrs=["bold"]))
        
        subdomain_set = set(DEFAULT_SUBDOMAINS)
        
        if self.hunter:
            if BUILTIN_HUNTER_FILE.exists():
                try:
                    with open(BUILTIN_HUNTER_FILE, 'r', encoding='utf-8', errors='ignore') as f:
                        for line in f:
                            w = line.strip().lower()
                            if w and not w.startswith("#"):
                                subdomain_set.add(w)
                    print(colored(f"  [HUNTER] Activated! Loaded list from {BUILTIN_HUNTER_FILE.name} (Total targets: {len(subdomain_set)})", "cyan", attrs=["bold"]))
                except Exception as e:
                    print(colored(f"  [ERROR] Could not load hunter file: {e}", "red"))
            else:
                print(colored(f"  [!] Hunter file {BUILTIN_HUNTER_FILE} not found.", "magenta"))

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

        if extra_subs:
            subdomain_set.update(extra_subs)
        
        subdomain_list = list(subdomain_set)
        total_targets = len(subdomain_list)
        chunk_size = self.hunter_chunk if self.hunter else total_targets

        print(colored(f"  [INFO] Scanning {total_targets} subdomains with {self.max_workers} threads...", "cyan"))

        pbar = None
        if TQDM_AVAILABLE and not self.verbose:
            desc_text = "Hunter 30k" if self.hunter else "Subdomain Brute"
            pbar = tqdm(total=total_targets, desc=desc_text, unit="sub", ncols=90)

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            for i in range(0, total_targets, chunk_size):
                if self._is_timed_out():
                    break
                chunk = subdomain_list[i:i + chunk_size]
                futures = {executor.submit(self._resolve_subdomain, sub): sub for sub in chunk}
                for future in as_completed(futures):
                    try:
                        future.result()
                    except Exception:
                        pass
                    if pbar:
                        pbar.update(1)
                        with self.lock:
                            found_ips = len(self.real_ips)
                        pbar.set_postfix(found=found_ips)

        if pbar:
            pbar.close()

    def _get_ssl_sans(self, ip, port=443, timeout=4):
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
        probe_data = {
            "ip": ip,
            "ssl_sans": [],
            "ssl_matched": False,
            "http_status": None,
            "http_title": None,
            "http_server": None,
            "title_matched": False,
            "body_similarity": 0.0,
            "hash_matched": False,
            "score": 0,
            "is_confirmed": False,
            "confidence": "Low (Potential)"
        }

        sans = self._get_ssl_sans(ip)
        probe_data["ssl_sans"] = sans
        for san in sans:
            san_clean = san.lower().strip()
            if san_clean == self.domain or san_clean == f"*.{self.domain}" or (san_clean.endswith(f".{self.domain}")):
                probe_data["ssl_matched"] = True
                probe_data["score"] += 45
                break

        headers = {
            "Host": self.domain,
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        }
        
        ip_formatted = f"[{ip}]" if ":" in ip else ip
        
        for proto in ["https", "http"]:
            url = f"{proto}://{ip_formatted}"
            try:
                res = self.session.get(url, headers=headers, timeout=5, verify=False, allow_redirects=True)
                probe_data["http_status"] = res.status_code
                probe_data["http_server"] = res.headers.get("Server", "Unknown")
                
                title_match = re.search(r"<title[^>]*>(.*?)</title>", res.text, re.IGNORECASE | re.DOTALL)
                if title_match:
                    probe_data["http_title"] = title_match.group(1).strip()
                    if self.target_signature.get("title") and (probe_data["http_title"] == self.target_signature["title"]):
                        probe_data["title_matched"] = True
                        probe_data["score"] += 30

                res_hash = hashlib.sha256(res.content).hexdigest()
                if self.target_signature.get("body_hash") and (res_hash == self.target_signature["body_hash"]):
                    probe_data["hash_matched"] = True
                    probe_data["score"] += 40
                    probe_data["body_similarity"] = 1.0
                elif self.target_signature.get("body_sample"):
                    probe_sample = res.text[:8000]
                    ratio = difflib.SequenceMatcher(None, self.target_signature["body_sample"], probe_sample).ratio()
                    probe_data["body_similarity"] = round(ratio, 3)
                    if ratio >= 0.85:
                        probe_data["score"] += 35
                    elif ratio >= 0.60:
                        probe_data["score"] += 20
                    elif ratio >= 0.35:
                        probe_data["score"] += 10

                if probe_data["http_server"] and probe_data["http_server"].lower() != "cloudflare":
                    if self.target_signature.get("server") and probe_data["http_server"] == self.target_signature["server"]:
                        probe_data["score"] += 10
                break
            except Exception:
                continue

        if probe_data["hash_matched"] or (probe_data["ssl_matched"] and probe_data["body_similarity"] >= 0.5) or probe_data["score"] >= 65:
            probe_data["is_confirmed"] = True
            probe_data["confidence"] = "High (Confirmed Origin)"
        elif probe_data["ssl_matched"] or probe_data["title_matched"] or probe_data["score"] >= 35:
            probe_data["is_confirmed"] = True
            probe_data["confidence"] = "Medium (Strong Candidate)"
        else:
            probe_data["confidence"] = "Low (Potential)"
        
        return probe_data

    def validate_origin_ips(self):
        if self.no_probe or not self.real_ips or self._is_timed_out():
            return

        print(colored("\n[PHASE 8] Probing Potential Origin IPs (SSL, Host Header & Content Match)...", "yellow", attrs=["bold"]))
        
        candidates = list(self.real_ips.keys())
        with ThreadPoolExecutor(max_workers=min(10, len(candidates))) as executor:
            future_to_ip = {executor.submit(self._probe_single_ip, ip): ip for ip in candidates}
            
            if TQDM_AVAILABLE and not self.verbose:
                with tqdm(total=len(candidates), desc="Probing Candidates", unit="ip", ncols=80) as pbar:
                    for future in as_completed(future_to_ip):
                        ip = future_to_ip[future]
                        try:
                            result = future.result()
                            with self.lock:
                                self.confirmed_origins[ip] = result
                        except Exception as e:
                            if self.verbose:
                                print(colored(f"  [!] Error probing {ip}: {e}", "red"))
                        pbar.update(1)
            else:
                for future in as_completed(future_to_ip):
                    ip = future_to_ip[future]
                    try:
                        result = future.result()
                        with self.lock:
                            self.confirmed_origins[ip] = result
                    except Exception as e:
                        if self.verbose:
                            print(colored(f"  [!] Error probing {ip}: {e}", "red"))

            for ip in candidates:
                result = self.confirmed_origins.get(ip)
                if not result:
                    continue
                if result["is_confirmed"]:
                    print(colored(f"  [★★★ {result['confidence'].upper()}] -> {ip}", "green", attrs=["bold"]))
                    if result["ssl_matched"]:
                        print(colored(f"      - SSL Certificate SAN matched domain: {result['ssl_sans']}", "green"))
                    if result["title_matched"]:
                        print(colored(f"      - HTML Title matched target website: '{result['http_title']}'", "green"))
                    if result["body_similarity"] > 0:
                        print(colored(f"      - Content similarity ratio: {result['body_similarity'] * 100:.1f}% (Hash match: {result['hash_matched']})", "green"))
                else:
                    print(colored(f"  [?] Candidate -> {ip} (Status: {result['http_status']}, Title: '{result['http_title']}', Similarity: {result['body_similarity']*100:.1f}%)", "cyan"))

    def export_results(self):
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
                "confidence": probe_info.get("confidence", "Low (Potential)"),
                "score": probe_info.get("score", 0),
                "ssl_matched": probe_info.get("ssl_matched", False),
                "ssl_sans": probe_info.get("ssl_sans", []),
                "title_matched": probe_info.get("title_matched", False),
                "hash_matched": probe_info.get("hash_matched", False),
                "body_similarity": probe_info.get("body_similarity", 0.0),
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
            "target_baseline": {
                "title": self.target_signature.get("title"),
                "status_code": self.target_signature.get("status_code"),
                "server": self.target_signature.get("server"),
                "body_hash": self.target_signature.get("body_hash")
            },
            "summary": {
                "hunter_mode": self.hunter,
                "confirmed_origins_count": len(confirmed_list),
                "potential_origins_count": len(potential_list),
                "cloudflare_ips_count": len(self.cf_ips)
            },
            "confirmed_origin_ips": confirmed_list,
            "potential_origin_ips": potential_list,
            "cloudflare_ips": list(self.cf_ips),
            "discovered_cnames": self.cnames
        }

        fmt = self.output_format
        if fmt == "auto":
            if self.output_file.lower().endswith(".json"):
                fmt = "json"
            elif self.output_file.lower().endswith(".csv"):
                fmt = "csv"
            else:
                fmt = "txt"

        try:
            if fmt == "json":
                with open(self.output_file, 'w', encoding='utf-8') as f:
                    json.dump(export_data, f, indent=4)
            elif fmt == "csv":
                fieldnames = [
                    "ip", "status", "confidence", "score", "ssl_matched", "title_matched",
                    "hash_matched", "body_similarity_pct", "http_status", "http_server",
                    "http_title", "ssl_sans", "sources"
                ]
                with open(self.output_file, 'w', encoding='utf-8', newline='') as f:
                    writer = csv.DictWriter(f, fieldnames=fieldnames)
                    writer.writeheader()
                    for item in confirmed_list + potential_list:
                        writer.writerow({
                            "ip": item["ip"],
                            "status": "CONFIRMED" if item["is_confirmed"] else "POTENTIAL",
                            "confidence": item["confidence"],
                            "score": item["score"],
                            "ssl_matched": item["ssl_matched"],
                            "title_matched": item["title_matched"],
                            "hash_matched": item["hash_matched"],
                            "body_similarity_pct": f"{item['body_similarity'] * 100:.1f}%",
                            "http_status": item["http_status"],
                            "http_server": item["http_server"],
                            "http_title": item["http_title"],
                            "ssl_sans": ";".join(item["ssl_sans"]),
                            "sources": ";".join(item["sources"])
                        })
            else:
                with open(self.output_file, 'w', encoding='utf-8') as f:
                    f.write(f"=== OriginReaper Scan Report for {self.domain} ===\n")
                    f.write(f"Date: {export_data['scan_timestamp']}\n\n")
                    f.write("[+] CONFIRMED ORIGIN IPs:\n")
                    for item in confirmed_list:
                        f.write(f"  -> {item['ip']} [{item['confidence']}] (Score: {item['score']})\n")
                        f.write(f"     Sources: {', '.join(item['sources'])}\n")
                        f.write(f"     Title: {item['http_title']} | Similarity: {item['body_similarity']*100:.1f}%\n")
                        f.write(f"     SSL SANs: {item['ssl_sans']}\n")
                    f.write("\n[~] POTENTIAL ORIGIN IPs:\n")
                    for item in potential_list:
                        f.write(f"  -> {item['ip']} (Sources: {', '.join(item['sources'])})\n")
                    f.write("\n[-] CLOUDFLARE IPs:\n")
                    for cf in self.cf_ips:
                        f.write(f"  -> {cf}\n")
            print(colored(f"[SUCCESS] Results successfully written to {self.output_file} (Format: {fmt.upper()})", "green", attrs=["bold"]))
        except Exception as e:
            print(colored(f"[ERROR] Failed to save output file: {e}", "red"))

    def run(self):
        print(colored(f"\n--- Initiating Reconnaissance for {self.domain} ---", "white", attrs=["bold"]))
        
        if not self.is_domain_cloudflare(self.domain):
            print(colored(f"[WARNING] {self.domain} does not appear to be protected by Cloudflare. Direct resolution may be possible.", "magenta"))
        else:
            print(colored(f"[INFO] Confirmed: {self.domain} is protected by Cloudflare.", "green"))

        crt_subs = self.fetch_crt_sh_subdomains()
        ht_subs = self.fetch_hackertarget_records()
        otx_subs = self.fetch_alienvault_records()
        
        all_passive_subs = set(crt_subs) | set(ht_subs) | set(otx_subs)
        
        self.check_spf_txt_records()
        self.check_dmarc_records()
        self.check_mx_records()
        self.scan_subdomains(all_passive_subs)
        self.validate_origin_ips()

        print(colored("\n" + "="*50, "white"))
        print(colored("           RECONNAISSANCE COMPLETE", "white", attrs=["bold"]))
        print(colored("="*50, "white"))

        confirmed = [ip for ip, data in self.confirmed_origins.items() if data.get("is_confirmed")]
        
        if confirmed:
            print(colored("\n[★★★] CONFIRMED ORIGIN IPs FOUND:", "green", attrs=["bold"]))
            for ip in confirmed:
                info = self.confirmed_origins[ip]
                sources = ", ".join(self.real_ips[ip])
                print(colored(f"  -> {ip} [{info['confidence']}] (Sources: {sources})", "green", attrs=['bold']))
        
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

        self.export_results()

def main():
    print(colored(LOGO, "cyan", attrs=["bold"]))
    
    parser = argparse.ArgumentParser(
        description="OriginReaper v2.9 - Ultimate OSINT tool to bypass Cloudflare and uncover real origin IPs.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("domain", help="The target domain to scan (e.g. example.com).")
    parser.add_argument("-w", "--wordlist", help="Path to custom subdomain wordlist file.", default=None)
    parser.add_argument("-t", "--max-workers", help="Number of concurrent worker threads (default: 15).", type=int, default=15)
    parser.add_argument("-r", "--resolver", help="Custom DNS resolver IP address (e.g. 1.1.1.1, 8.8.8.8).", default=None)
    parser.add_argument("-o", "--output", help="Save scan results to a JSON, CSV, or TXT file.", default=None)
    parser.add_argument("--format", choices=["auto", "json", "csv", "txt"], default="auto", help="Output file format (default: auto detect from extension).")
    parser.add_argument("--dns-types", nargs="+", help="Specific DNS record types to check (e.g. A AAAA MX TXT).", default=None)
    parser.add_argument("--timeout", type=int, default=None, help="Global scan timeout limit in seconds.")
    parser.add_argument("--hunter", action="store_true", help="Enable Subdomain Hunter mode using built-in 30k+ list (subdomain.txt).")
    parser.add_argument("--hunter-threads", type=int, default=50, help="Worker threads for Hunter mode (default: 50).")
    parser.add_argument("--hunter-chunk", type=int, default=1000, help="Batch chunk size for Hunter mode (default: 1000).")
    parser.add_argument("--no-crt", action="store_true", help="Disable Certificate Transparency (crt.sh) queries.")
    parser.add_argument("--no-osint", action="store_true", help="Disable third-party passive OSINT (HackerTarget, AlienVault).")
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
            output_format=args.format,
            dns_types=args.dns_types,
            no_crt=args.no_crt,
            no_osint=args.no_osint,
            no_probe=args.no_probe,
            verbose=args.verbose,
            timeout=args.timeout,
            hunter=args.hunter,
            hunter_threads=args.hunter_threads,
            hunter_chunk=args.hunter_chunk
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
