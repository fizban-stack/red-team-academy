---
layout: training-page
title: "Python Port Scanner & Service Enumeration — Red Team Academy"
module: "Tool Development"
tags:
  - python
  - port-scanning
  - masscan
  - asyncio
  - nmap
  - service-enumeration
  - tls
  - fingerprinting
page_key: "tooldev-python-port-scanner"
render_with_liquid: false
---

# Python Port Scanner & Service Enumeration

## Overview

A complete Python-driven scanning pipeline answers one question first — *which IP:port tuples are reachable?* — then escalates each hit through progressively deeper probers: nmap version detection, TLS certificate inspection, SSH key fingerprinting, and HTTP banner grabbing. All results land in a unified SQLite database (`recon.db`) with a risk score per service. The pipeline is designed to be modular: swap the discovery driver (masscan vs. async connect) based on your rules of engagement.

Dependencies: `pip install rich dnspython cryptography paramiko httpx pandas` plus `masscan` and `nmap` as system binaries (optional but recommended).

## Stage 1 — Fast Discovery

### Discovery Mode Comparison

| Mode | Speed | Noise | Root Required | Use When |
|---|---|---|---|---|
| Raw SYN (masscan) | 1–10 M pps | Medium | Yes | Large CIDRs, short windows |
| TCP connect (async) | 30–100 k pps | Low | No | Stealth, host lists, OT networks |
| ICMP sweep | 100 k pps | Varies | Yes | Quick liveness check before scanning |

### masscan Driver (INI scope → NDJSON)

```
#!/usr/bin/env python3
"""
masscan_driver.py — Run masscan from an INI scope file, output NDJSON.

INI sample (scope.ini):
  [cidrs]
  nets = 192.168.10.0/24, 10.10.10.5
  [ports]
  tiers = t0          # t0=top1k, t1=extended, full=1-65535
"""
from __future__ import annotations
import argparse, configparser, json, pathlib, shlex, subprocess, sys, tempfile

TOP1K = ",".join(map(str, range(1, 1025)))

def parse_scope(path: pathlib.Path) -> tuple[list[str], str]:
    cfg = configparser.ConfigParser()
    cfg.read(path)
    nets = [x.strip() for x in cfg["cidrs"]["nets"].split(",")]
    tier = cfg["ports"].get("tiers", "t0")
    return nets, tier

def tier_to_ports(tier: str) -> str:
    if tier in ("t0", "quick"):
        return TOP1K
    if tier == "t1":
        return TOP1K + ",3306,5432,6379,27017,5000-5099,8080-8090"
    return "1-65535"

def run_masscan(nets: list[str], ports: str, rate: int, out: pathlib.Path):
    cmd = shlex.split(
        f"masscan -p{ports} --rate {rate} --wait 0 -oJ {out} " + " ".join(nets)
    )
    print("[*]", " ".join(cmd))
    proc = subprocess.Popen(cmd)
    proc.wait()
    if proc.returncode:
        sys.exit("[-] masscan failed")

def json_to_ndjson(src: pathlib.Path, dst: pathlib.Path):
    """Masscan outputs a JSON array with trailing commas — convert to NDJSON."""
    with src.open() as sj, dst.open("w") as dj:
        for line in sj:
            line = line.strip().rstrip(",")
            if line.startswith("{"):
                dj.write(line + "\n")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("scope", type=pathlib.Path)
    ap.add_argument("--rate", type=int, default=50_000)
    ap.add_argument("--out", type=pathlib.Path, default=pathlib.Path("mscan.ndjson"))
    args = ap.parse_args()

    nets, tier = parse_scope(args.scope)
    ports      = tier_to_ports(tier)

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        tmp_path = pathlib.Path(tmp.name)
        run_masscan(nets, ports, args.rate, tmp_path)
        json_to_ndjson(tmp_path, args.out)

    print(f"[+] Discovery done — {args.out}  ({args.out.stat().st_size/1e6:.1f} MB)")

if __name__ == "__main__":
    main()
```

### Async TCP Connect Scanner (no root, resumable)

```
#!/usr/bin/env python3
"""
connect_driver.py — Pure-Python async TCP connect scanner.
Safe on networks where raw SYN triggers alarms.
Features:
  • Resumable: checkpoint file every N hosts
  • Concurrency capped via --workers semaphore
  • Same NDJSON output schema as masscan_driver
"""
from __future__ import annotations
import argparse, asyncio, json, pathlib, random, time
from rich.progress import Progress, BarColumn, TimeRemainingColumn

DEFAULT_PORTS = [21, 22, 23, 25, 80, 110, 135, 139, 143, 443,
                 445, 3306, 3389, 5432, 5985, 6379, 8080, 8443, 27017]

async def probe(ip: str, port: int, timeout: float) -> bool:
    try:
        conn = asyncio.open_connection(ip, port)
        reader, writer = await asyncio.wait_for(conn, timeout)
        writer.close()
        await writer.wait_closed()
        return True
    except Exception:
        return False

async def scan_host(ip: str, ports: list[int],
                    sem: asyncio.Semaphore, out_fh, timeout: float):
    for port in ports:
        async with sem:
            if await probe(ip, port, timeout):
                out_fh.write(json.dumps({"ip": ip, "port": port}) + "\n")
                out_fh.flush()
        await asyncio.sleep(random.uniform(0.01, 0.05))   # per-port jitter

async def main(ip_file: pathlib.Path, out: pathlib.Path,
               workers: int, timeout: float, ports: list[int]):
    ips = [ln.strip() for ln in ip_file.read_text().splitlines() if ln.strip()]

    # Checkpoint: resume from last processed IP
    ckpt = out.with_suffix(".ckpt")
    done: set[str] = set()
    if ckpt.exists():
        done = set(ckpt.read_text().splitlines())
        print(f"[*] Resuming — skipping {len(done)} already-done IPs")

    sem = asyncio.Semaphore(workers)
    with out.open("a") as fh, Progress(
        "{task.description}", BarColumn(), TimeRemainingColumn()
    ) as bar:
        task = bar.add_task("[cyan]connect-scan", total=len(ips))
        for ip in ips:
            bar.advance(task)
            if ip in done:
                continue
            await scan_host(ip, ports, sem, fh, timeout)
            with ckpt.open("a") as cf:
                cf.write(ip + "\n")

    print(f"[+] Scan complete → {out}")

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("ips",     type=pathlib.Path, help="one IP per line")
    ap.add_argument("--out",   type=pathlib.Path, default=pathlib.Path("open.ndjson"))
    ap.add_argument("--workers", type=int, default=500)
    ap.add_argument("--timeout", type=float, default=1.5)
    ap.add_argument("--ports", default=",".join(map(str, DEFAULT_PORTS)))
    args = ap.parse_args()
    asyncio.run(main(
        args.ips, args.out, args.workers, args.timeout,
        list(map(int, args.ports.split(",")))
    ))
```

## Stage 2 — Service Enumeration Escalation

### Strategy

```
1. Read open-port list (all_open.ndjson)
2. Bucket targets by port hints (80→HTTP, 22→SSH, 443→TLS, …)
3. Run light nmap -sV/-sC pass for baseline versions
4. Route each port to a protocol-specific deep prober
5. Flatten everything into recon.db
```

### Nmap XML Parser

```
#!/usr/bin/env python3
"""
parse_nmap.py — Parse nmap XML output into recon.db.
Run nmap first:
  nmap -sV -sC -oX out.xml -iL targets.txt
"""
import sqlite3, xml.etree.ElementTree as ET, pathlib, sys

DB = sqlite3.connect("recon.db")
DB.execute("""CREATE TABLE IF NOT EXISTS nmap (
    ip TEXT, port INT, protocol TEXT,
    state TEXT, service TEXT, product TEXT, version TEXT, extra TEXT,
    PRIMARY KEY (ip, port, protocol)
)""")

def parse(xml_file: str):
    tree = ET.parse(xml_file)
    for host in tree.findall("host"):
        addr = host.find("address").get("addr")
        for port_el in host.findall(".//port"):
            port     = int(port_el.get("portid"))
            proto    = port_el.get("protocol")
            state_el = port_el.find("state")
            svc_el   = port_el.find("service") or {}
            if (state_el is None or state_el.get("state") != "open"):
                continue
            DB.execute("INSERT OR REPLACE INTO nmap VALUES (?,?,?,?,?,?,?,?)", (
                addr, port, proto,
                state_el.get("state"),
                svc_el.get("name"),
                svc_el.get("product"),
                svc_el.get("version"),
                svc_el.get("extrainfo"),
            ))
    DB.commit()
    print(f"[+] Imported {xml_file}")

if __name__ == "__main__":
    parse(sys.argv[1])
```

## Stage 3 — TLS / SSH / HTTP Deep Probers

### TLS Fingerprinting

Extract certificate CN, issuer, expiry, and key strength from any TLS port.

```
#!/usr/bin/env python3
"""
tls_probe.py — Pull TLS certificate metadata from open ports.
Dependencies: pip install cryptography
Usage: python3 tls_probe.py 10.10.10.5 443
"""
import ssl, socket, sys, csv
from datetime import datetime
from cryptography import x509
from cryptography.hazmat.backends import default_backend

def probe_tls(ip: str, port: int) -> dict:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE
    with socket.create_connection((ip, port), timeout=5) as sock:
        with ctx.wrap_socket(sock, server_hostname=ip) as tls:
            der = tls.getpeercert(binary_form=True)
    cert = x509.load_der_x509_certificate(der, default_backend())
    try:
        cn = cert.subject.get_attributes_for_oid(
                 x509.NameOID.COMMON_NAME)[0].value
    except Exception:
        cn = ""
    try:
        san = cert.extensions.get_extension_for_class(
                  x509.SubjectAlternativeName).value.get_values_for_type(
                  x509.DNSName)
    except Exception:
        san = []
    return {
        "ip":      ip,
        "port":    port,
        "cn":      cn,
        "san":     ",".join(san),
        "issuer":  cert.issuer.rfc4514_string(),
        "not_before": cert.not_valid_before.isoformat(),
        "not_after":  cert.not_valid_after.isoformat(),
        "expired": cert.not_valid_after < datetime.utcnow(),
        "key_bits": cert.public_key().key_size,
    }

if __name__ == "__main__":
    result = probe_tls(sys.argv[1], int(sys.argv[2]))
    for k, v in result.items():
        print(f"  {k:15s} {v}")
```

### SSH Key Fingerprinting

```
#!/usr/bin/env python3
"""
ssh_probe.py — Get SSH host key type and length.
Dependencies: pip install paramiko
"""
import paramiko, socket, sys

def probe_ssh(ip: str, port: int = 22) -> dict:
    transport = paramiko.Transport((ip, port))
    try:
        transport.connect()
        key = transport.get_remote_server_key()
        return {
            "ip":       ip,
            "port":     port,
            "key_type": key.get_name(),
            "key_bits": key.get_bits() if hasattr(key, "get_bits") else "N/A",
            "fingerprint": key.get_fingerprint().hex(),
        }
    finally:
        transport.close()

if __name__ == "__main__":
    r = probe_ssh(sys.argv[1], int(sys.argv[2] if len(sys.argv) > 2 else 22))
    print(r)
```

### HTTP Banner + Title Grab

```
#!/usr/bin/env python3
"""
http_probe.py — Grab Server header, title, and redirect chain from HTTP/S.
"""
import httpx, re, sys

TITLE_RE = re.compile(r"<title[^>]*>([^<]+)</title>", re.I)

def probe_http(ip: str, port: int) -> dict:
    for scheme in ("https", "http"):
        url = f"{scheme}://{ip}:{port}/"
        try:
            r = httpx.get(url, follow_redirects=True, verify=False,
                          timeout=6,
                          headers={"User-Agent": "Mozilla/5.0 (compatible)"})
            title_m = TITLE_RE.search(r.text)
            return {
                "ip":     ip,
                "port":   port,
                "scheme": scheme,
                "status": r.status_code,
                "server": r.headers.get("server", ""),
                "title":  (title_m.group(1).strip() if title_m else ""),
                "final_url": str(r.url),
                "x_powered": r.headers.get("x-powered-by", ""),
            }
        except Exception:
            continue
    return {"ip": ip, "port": port, "error": "unreachable"}

if __name__ == "__main__":
    print(probe_http(sys.argv[1], int(sys.argv[2])))
```

## Stage 4 — Risk Scoring & HTML Report

Score each service using simple heuristics: weak key size, outdated version strings, unusual TLS fingerprints, dangerous service on exposed port.

```
#!/usr/bin/env python3
"""
risk_report.py — Generate a risk-scored HTML dashboard from recon.db.
"""
import sqlite3, pandas as pd, pathlib

DB = sqlite3.connect("recon.db")

# Load nmap results
df = pd.read_sql("""
    SELECT ip, port, service, product, version, extra
    FROM nmap WHERE state='open'
""", DB)

def score(row) -> int:
    s = 0
    prod = str(row["product"]).lower()
    port = int(row["port"])
    # Dangerous services on public ports
    if port in (21, 23, 25, 110) and "ssl" not in prod:
        s += 3    # plaintext protocol
    if "openssh" in prod:
        ver = str(row["version"])
        major = int(ver.split(".")[0]) if ver and ver[0].isdigit() else 99
        if major < 8:
            s += 2  # outdated SSH
    if port == 3389:
        s += 2      # RDP exposed
    if port in (6379, 27017) and not row["extra"]:
        s += 4      # Redis/Mongo with no auth
    return min(s, 10)

df["risk"] = df.apply(score, axis=1)
df.sort_values("risk", ascending=False, inplace=True)

# Write HTML dashboard
html = df.to_html(index=False, classes="risk-table", border=0)
template = f"""<!DOCTYPE html>
<html><head><title>Recon Risk Report</title>
<style>
body {{ font-family: monospace; background: #111; color: #ccc; padding: 2em; }}
table {{ border-collapse: collapse; width: 100%; }}
th {{ background: #222; padding: 8px; text-align: left; }}
td {{ padding: 6px; border-bottom: 1px solid #333; }}
tr:nth-child(even) {{ background: #1a1a1a; }}
</style></head><body>
<h1>Recon Risk Report</h1>
<p>Total open ports: {len(df)} | High-risk (≥5): {(df.risk>=5).sum()}</p>
{html}
</body></html>"""

out = pathlib.Path("risk_report.html")
out.write_text(template)
print(f"[+] Risk report → {out}  ({len(df)} services)")
print(df[df.risk >= 5][["ip","port","service","risk"]].to_string())
```

## Running the Full Pipeline

```
# 1. Expand scope
python3 cidr_expand.py 10.10.10.0/24 > targets.txt

# 2. Discover open ports
python3 connect_driver.py targets.txt --workers 500

# 3. Run nmap on discovered ports (feed from open.ndjson)
jq -r '[.ip,.port]|join(":")' open.ndjson | \
  xargs -I{} nmap -sV -sC -oX nmap_{}.xml {}

# 4. Parse XML results
for f in nmap_*.xml; do python3 parse_nmap.py "$f"; done

# 5. Deep-probe TLS/SSH/HTTP
python3 tls_probe.py 10.10.10.5 443
python3 ssh_probe.py 10.10.10.5 22

# 6. Generate risk report
python3 risk_report.py && open risk_report.html
```

## Resources

- Offensive Python (course material) — port scanning & service enumeration pipeline
- masscan — `github.com/robertdavidgraham/masscan`
- nmap — `nmap.org`
- `cryptography` Python library — TLS cert parsing
- `paramiko` — SSH transport in Python
- `httpx` — async HTTP client
- `pandas` — data analysis and HTML report generation
