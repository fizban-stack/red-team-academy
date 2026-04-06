---
layout: training-page
title: "Python OSINT Automation — Red Team Academy"
module: "Tool Development"
tags:
  - python
  - osint
  - recon
  - dns
  - shodan
  - censys
  - asyncio
  - information-gathering
page_key: "tooldev-python-osint-automation"
render_with_liquid: false
---

# Python OSINT Automation

## Overview

Automated OSINT gives you machine-readable intelligence before a single packet leaves your machine. This module builds a full Python-based information-gathering pipeline: passive DNS enumeration → WHOIS/ASN enrichment → Internet scanner queries (Shodan, Censys, ZoomEye) → email and breach correlation → file metadata extraction → unified SQLite database. Every stage is idempotent (safe to rerun), rate-limited, and crash-resumable.

Dependencies: `pip install aiodns dnspython shodan censys==2.* zoomeye ipwhois httpx aiofiles exifread rich tenacity`

## DNS & Subdomain Enumeration

### Passive Techniques

Before sending any packets, harvest subdomains from certificate transparency logs and search engines.

```
#!/usr/bin/env python3
"""
ct_harvest.py — Pull subdomains from crt.sh CT logs.
Usage: python3 ct_harvest.py example.com
Output: subs_ct.txt (one subdomain per line, deduped)
"""
import httpx, json, sys

def crt_sh(domain: str) -> set[str]:
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    r = httpx.get(url, timeout=30, follow_redirects=True)
    r.raise_for_status()
    names: set[str] = set()
    for entry in r.json():
        for name in entry["name_value"].split("\n"):
            name = name.strip().lstrip("*.")
            if name.endswith(domain):
                names.add(name)
    return names

if __name__ == "__main__":
    domain = sys.argv[1]
    subs = crt_sh(domain)
    out = "subs_ct.txt"
    with open(out, "w") as f:
        f.write("\n".join(sorted(subs)) + "\n")
    print(f"[+] crt.sh: {len(subs)} unique subdomains → {out}")
```

### Active Wordlist Brute-force (asyncio + aiodns)

Brute-force subdomains concurrently with wildcard detection to avoid false positives.

```
#!/usr/bin/env python3
"""
subdomain_brute.py — Async subdomain brute-force with wildcard suppression.
Usage: python3 subdomain_brute.py example.com wordlist.txt
"""
from __future__ import annotations
import asyncio, sys, pathlib
import aiodns

WORKERS = 500

async def resolve(resolver: aiodns.DNSResolver, name: str) -> str | None:
    try:
        result = await resolver.query(name, "A")
        return result[0].host
    except aiodns.error.DNSError:
        return None

async def detect_wildcard(resolver: aiodns.DNSResolver, domain: str) -> set[str]:
    """Return IPs that resolve for random subdomains (wildcard IPs)."""
    import secrets
    wildcard_ips: set[str] = set()
    for _ in range(3):
        probe = f"{secrets.token_hex(8)}.{domain}"
        ip = await resolve(resolver, probe)
        if ip:
            wildcard_ips.add(ip)
    return wildcard_ips

async def main(domain: str, wordlist: pathlib.Path):
    words = wordlist.read_text().splitlines()
    resolver = aiodns.DNSResolver()
    wildcard_ips = await detect_wildcard(resolver, domain)
    if wildcard_ips:
        print(f"[!] Wildcard detected → suppressing IPs: {wildcard_ips}")

    sem = asyncio.Semaphore(WORKERS)
    results: list[tuple[str, str]] = []

    async def check(word: str):
        name = f"{word.strip()}.{domain}"
        async with sem:
            ip = await resolve(resolver, name)
        if ip and ip not in wildcard_ips:
            results.append((name, ip))
            print(f"  [+] {name} → {ip}")

    await asyncio.gather(*(check(w) for w in words if w.strip()))
    with open("subs_brute.txt", "w") as f:
        for name, ip in sorted(results):
            f.write(f"{name},{ip}\n")
    print(f"[+] Brute-force: {len(results)} hits → subs_brute.txt")

if __name__ == "__main__":
    domain, wl = sys.argv[1], pathlib.Path(sys.argv[2])
    asyncio.run(main(domain, wl))
```

### Zone Transfer & SRV Sweep

```
#!/usr/bin/env python3
"""
zone_xfr.py — Attempt AXFR zone transfer on all NS records.
Usage: python3 zone_xfr.py example.com
"""
import dns.resolver, dns.zone, dns.query

def axfr(domain: str) -> list[str]:
    found: list[str] = []
    ns_records = dns.resolver.resolve(domain, "NS")
    for ns in ns_records:
        ns_host = str(ns.target).rstrip(".")
        try:
            z = dns.zone.from_xfr(dns.query.xfr(ns_host, domain, timeout=5))
            for name in z.nodes:
                found.append(f"{name}.{domain}")
            print(f"[!] AXFR succeeded on {ns_host}! {len(found)} records")
        except Exception as e:
            print(f"[-] AXFR failed on {ns_host}: {e}")
    return found

if __name__ == "__main__":
    import sys
    results = axfr(sys.argv[1])
    if results:
        print("\n".join(results))
```

## WHOIS / ASN / Geo-IP Enrichment

Convert discovered IPs into structured intelligence: organisation, ASN, CIDR block, country.

```
#!/usr/bin/env python3
"""
enrich_ips.py — WHOIS/ASN/Geo enrichment for an IP list.
Usage: python3 enrich_ips.py ips.txt
Output: enriched.csv

Dependencies: pip install ipwhois
"""
from __future__ import annotations
import csv, sys, time
from pathlib import Path
from ipwhois import IPWhois

FIELDS = ["ip", "asn", "asn_cidr", "asn_description", "country", "org"]

def lookup(ip: str) -> dict:
    try:
        obj = IPWhois(ip)
        res = obj.lookup_rdap(asn_methods=["whois"])
        return {
            "ip":              ip,
            "asn":             res.get("asn"),
            "asn_cidr":        res.get("asn_cidr"),
            "asn_description": res.get("asn_description"),
            "country":         res.get("asn_country_code"),
            "org":             (res.get("network") or {}).get("name"),
        }
    except Exception as e:
        return {"ip": ip, "asn": None, "asn_cidr": None,
                "asn_description": None, "country": None, "org": str(e)}

def main(ip_file: str):
    ips = Path(ip_file).read_text().splitlines()
    with open("enriched.csv", "w", newline="") as f:
        w = csv.DictWriter(f, FIELDS)
        w.writeheader()
        for ip in ips:
            ip = ip.strip()
            if not ip:
                continue
            row = lookup(ip)
            w.writerow(row)
            print(f"  {ip:20s}  ASN{row['asn']}  {row['org']}")
            time.sleep(0.3)      # RDAP rate-limit friendly

if __name__ == "__main__":
    main(sys.argv[1])
```

**Why this matters:** ASN pivoting — a single org name often reveals additional CIDR blocks. Feed new CIDRs back into the scanner to expand scope without noisy probes.

## Shodan / Censys / ZoomEye API Pulls

Query internet-wide scan databases with no packets leaving your machine.

### Setup

```
pip install shodan censys==2.* zoomeye rich tenacity

# Export API keys — never hard-code
export SHODAN_KEY="SHODAN-XXXXXXXXXXXXXXXXXXXXXXXX"
export CENSYS_ID="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
export CENSYS_SECRET="your_censys_secret"
export ZOOMEYE_KEY="your_zoomeye_key"
```

### Shodan Pull (streaming, idempotent)

```
#!/usr/bin/env python3
"""
shodan_pull.py — Stream Shodan results to NDJSON.
Writes {ip, port, transport, timestamp, org, banner, source} per line.

NDJSON advantages:
  • Append-friendly  (>> concatenate, no commas to fix)
  • jq / Splunk / Elastic ingest line-by-line
"""
from __future__ import annotations
import json, os, sys
from pathlib import Path
from typing import Iterator
import shodan
from tenacity import retry, stop_after_attempt, wait_exponential

SHODAN_KEY = os.getenv("SHODAN_KEY") or sys.exit("[-] Set SHODAN_KEY")
api = shodan.Shodan(SHODAN_KEY)

@retry(wait=wait_exponential(multiplier=2, min=2, max=30),
       stop=stop_after_attempt(4), reraise=True)
def run_query(q: str) -> Iterator[dict]:
    """search_cursor() bypasses the 10k soft-cap."""
    yield from api.search_cursor(q)

def normalise(b: dict) -> dict:
    return {
        "ip":        b["ip_str"],
        "port":      b["port"],
        "transport": b.get("transport", "tcp"),
        "timestamp": b.get("timestamp"),
        "org":       b.get("org"),
        "banner":    (b.get("data") or "").strip()[:8000],
        "source":    "shodan",
    }

def pull(query: str, out: Path):
    with out.open("a") as fh:
        for banner in run_query(query):
            fh.write(json.dumps(normalise(banner)) + "\n")
    print(f"[+] Shodan → {out}")

if __name__ == "__main__":
    pull('org:"Target Corp" port:443', Path("shodan.ndjson"))
```

### Censys Pull

```
#!/usr/bin/env python3
"""
censys_pull.py — Censys v2 host search to CSV.
Flattens the nested services[] array into one row per service.
"""
from __future__ import annotations
import csv, json, os, sys
from pathlib import Path
from typing import Iterator
from censys.search import CensysHosts
from tenacity import retry, wait_exponential, stop_after_attempt
from rich.progress import track

CID     = os.getenv("CENSYS_ID")
CSECRET = os.getenv("CENSYS_SECRET")
if not (CID and CSECRET):
    sys.exit("[-] Set CENSYS_ID and CENSYS_SECRET")

hosts = CensysHosts(api_id=CID, api_secret=CSECRET)

def norm(hit: dict) -> Iterator[dict]:
    base = {
        "ip":        hit["ip"],
        "timestamp": hit["updated_at"],
        "org":       hit.get("autonomous_system", {}).get("name"),
        "source":    "censys",
    }
    for svc in hit.get("services", []):
        yield {**base,
               "port":      svc["port"],
               "transport": svc["transport_protocol"],
               "banner":    (svc.get("banner") or "").strip()[:8000]}

def run(q: str, out: Path):
    fields = ["ip", "port", "transport", "timestamp", "org", "banner", "source"]
    total  = hosts.count(q)
    with out.open("w", newline="") as f:
        w = csv.DictWriter(f, fields)
        w.writeheader()
        for page in track(hosts.search(q, per_page=100),
                          total=total, description=q):
            for row in norm(page):
                w.writerow(row)
    print(f"[+] Censys CSV → {out}")

if __name__ == "__main__":
    run('services.service_name: "HTTP" AND location.country: "US"',
        Path("censys.csv"))
```

### Merging All Three Providers

```
import pandas as pd

dfs = [
    pd.read_csv("censys.csv"),
    pd.read_json("shodan.ndjson", lines=True),
    pd.read_json("zoomeye.ndjson", lines=True),
]
df = pd.concat(dfs, ignore_index=True)
df.drop_duplicates(["ip", "port"], inplace=True)
df.to_csv("internet_scanners.csv", index=False)
print(df.groupby("source").size())
```

### OPSEC Notes

| Platform | Rate limit | Stealth |
|---|---|---|
| Shodan | 1 credit = 1 banner | No packets to victim — noiseless |
| Censys | Free tier resets daily 00:00 UTC | 100 hosts per query |
| ZoomEye | 20 hosts per page, free keys ban fast | Enforce ≥1 s between requests |

Always throttle to one request/second on free tiers. Never hard-code keys.

## Email & Breach Correlation

Map real people behind a domain and cross-reference public breach data.

```
#!/usr/bin/env python3
"""
email_harvest.py — Regex-harvest email addresses from HTML/PDF/text files.
Then normalise and dedup for breach correlation.
Usage: python3 email_harvest.py /path/to/crawled/files/
"""
import re, sys
from pathlib import Path

EMAIL_RE = re.compile(
    r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
    re.IGNORECASE
)

def harvest(root: str) -> set[str]:
    emails: set[str] = set()
    for p in Path(root).rglob("*"):
        if p.is_file() and p.suffix.lower() in (".html", ".txt", ".md", ".json"):
            try:
                text = p.read_text(errors="ignore")
                for m in EMAIL_RE.finditer(text):
                    emails.add(m.group().lower())
            except Exception:
                pass
    return emails

if __name__ == "__main__":
    found = harvest(sys.argv[1])
    out = Path("email_raw.txt")
    out.write_text("\n".join(sorted(found)) + "\n")
    print(f"[+] Harvested {len(found)} unique emails → {out}")
```

Cross-check emails against the HaveIBeenPwned API (requires paid key) or local breach dumps:

```
#!/usr/bin/env python3
"""
breach_check.py — Check email list against HIBP API v3.
Requires: HIBP_KEY env var (paid key) or local dump match.
"""
import httpx, os, time
from pathlib import Path

KEY     = os.getenv("HIBP_KEY", "")
HEADERS = {"hibp-api-key": KEY, "User-Agent": "recon-script/1.0"}

def check_breach(email: str) -> list[str]:
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
    r = httpx.get(url, headers=HEADERS, timeout=10)
    if r.status_code == 200:
        return [b["Name"] for b in r.json()]
    if r.status_code == 404:
        return []
    raise RuntimeError(f"HIBP error {r.status_code}")

emails = Path("email_raw.txt").read_text().splitlines()
with open("email_breach.csv", "w") as out:
    out.write("email,breaches\n")
    for email in emails:
        try:
            breaches = check_breach(email)
            out.write(f"{email},{';'.join(breaches)}\n")
            if breaches:
                print(f"  [!] {email} → {', '.join(breaches)}")
        except Exception as e:
            print(f"  [?] {email}: {e}")
        time.sleep(1.6)    # HIBP rate limit: 1 req/1.5s
```

## File Metadata Extraction (EXIF Mining)

Office documents, PDFs, and images often contain usernames, software versions, GPS coordinates, and internal paths.

```
#!/usr/bin/env python3
"""
meta_mine.py — Extract EXIF / document metadata from files.
Dependencies: pip install exifread python-docx PyPDF2
Usage: python3 meta_mine.py /path/to/downloads/
"""
import json, sys
from pathlib import Path

def exif_meta(p: Path) -> dict:
    import exifread
    with p.open("rb") as f:
        tags = exifread.process_file(f, details=False)
    return {str(k): str(v) for k, v in tags.items()
            if k not in ("JPEGThumbnail", "TIFFThumbnail")}

def pdf_meta(p: Path) -> dict:
    from PyPDF2 import PdfReader
    r = PdfReader(str(p))
    info = r.metadata or {}
    return {k.lstrip("/"): str(v) for k, v in info.items()}

def docx_meta(p: Path) -> dict:
    from docx import Document
    doc = Document(str(p))
    core = doc.core_properties
    return {
        "author":   core.author,
        "created":  str(core.created),
        "modified": str(core.modified),
        "revision": core.revision,
    }

HANDLERS = {
    ".jpg": exif_meta, ".jpeg": exif_meta,
    ".pdf": pdf_meta,
    ".docx": docx_meta,
}

results = []
for p in Path(sys.argv[1]).rglob("*"):
    handler = HANDLERS.get(p.suffix.lower())
    if handler:
        try:
            meta = handler(p)
            if meta:
                results.append({"file": str(p), "meta": meta})
                print(f"  {p.name}: {list(meta.keys())}")
        except Exception:
            pass

Path("metadata.json").write_text(json.dumps(results, indent=2))
print(f"[+] {len(results)} files with metadata → metadata.json")
```

**Key fields to look for:** `Author`, `Creator`, `Software` (reveals internal tooling), `GPS*` (geographic location of mobile photos), `Windows Local Path` in PDFs (internal directory structure).

## Recon Database — Unified SQLite Store

All stages write to a single SQLite database for easy correlation.

```
import sqlite3

db = sqlite3.connect("recon.db")
db.executescript("""
CREATE TABLE IF NOT EXISTS subdomains (
    name TEXT PRIMARY KEY,
    ip   TEXT,
    source TEXT,    -- ct, brute, axfr
    ts   INTEGER DEFAULT (strftime('%s','now'))
);
CREATE TABLE IF NOT EXISTS asn_info (
    ip   TEXT PRIMARY KEY,
    asn  TEXT, cidr TEXT, org TEXT, country TEXT
);
CREATE TABLE IF NOT EXISTS inet_scanners (
    ip TEXT, port INT, transport TEXT,
    org TEXT, banner TEXT, source TEXT,
    ts  TEXT,
    PRIMARY KEY (ip, port, source)
);
CREATE TABLE IF NOT EXISTS emails (
    email TEXT PRIMARY KEY,
    breaches TEXT,
    domain TEXT
);
CREATE TABLE IF NOT EXISTS metadata (
    file TEXT PRIMARY KEY,
    author TEXT, software TEXT, gps TEXT, raw JSON
);
""")
```

## Resources

- Offensive Python (course material) — Python-based OSINT pipeline
- crt.sh — certificate transparency log search
- HaveIBeenPwned API — breach data correlation
- Shodan API docs — `shodan.io/api`
- Censys v2 API — `search.censys.io/api`
- `dnspython` — DNS toolkit for Python
- `aiodns` — async DNS resolver
- SecLists/Discovery/DNS — wordlists for subdomain brute-force
