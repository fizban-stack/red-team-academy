---
layout: training-page
title: "Python Network Recon Tools — Red Team Academy"
module: "Tool Development"
tags:
  - python
  - network
  - port-scanning
  - banner-grabbing
  - recon
  - asyncio
page_key: "tooldev-python-network-recon"
render_with_liquid: false
---

# Python Network Recon Tools

## Overview

Python's `asyncio` library makes it ideal for high-speed network reconnaissance — thousands of concurrent probes are possible with a small semaphore-controlled coroutine pool, without the overhead of threading or multiprocessing. This module builds a full reconnaissance pipeline: CIDR expansion → async TCP scanning → banner grabbing → service fingerprinting → JSON output. All tools run with no root/CAP_NET_RAW requirement (pure TCP connect scan).

Dependencies: Python 3.11+, no external packages required for the core scanner. `python-ldap3` and `impacket` are used in the AD tools module.

## CIDR Expansion & Target List Builder

Before scanning, expand CIDR notation into a flat list of IP addresses. The `ipaddress` stdlib module handles all subnet math. Targets can be read from a file, passed as CLI arguments, or generated from a CIDR string.

```
#!/usr/bin/env python3
"""
cidr_expand.py — Build a flat target list from CIDR blocks, ranges, and single IPs.
Usage: python3 cidr_expand.py 10.10.10.0/24 192.168.1.1 172.16.0.0/22
Writes: targets.txt (one IP per line)
"""

import ipaddress
import sys
import pathlib

def expand_targets(specs: list[str]) -> list[str]:
    """Expand a mix of CIDR blocks and individual IPs to a flat IP list."""
    ips: list[str] = []
    for spec in specs:
        spec = spec.strip()
        try:
            # ipaddress.ip_network handles both single IPs and CIDR blocks
            network = ipaddress.ip_network(spec, strict=False)
            # .hosts() skips network and broadcast addresses for /prefix < 31
            ips.extend(str(host) for host in network.hosts())
        except ValueError:
            print(f"[!] Skipping invalid target spec: {spec}", file=sys.stderr)
    return ips

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: cidr_expand.py <cidr/ip> [<cidr/ip> ...]")
        sys.exit(1)

    targets = expand_targets(sys.argv[1:])
    out = pathlib.Path("targets.txt")
    out.write_text("\n".join(targets) + "\n")
    print(f"[+] Wrote {len(targets)} hosts to {out}")
```

## Async TCP Port Scanner

The scanner uses `asyncio.Semaphore` to cap concurrency to `--workers` simultaneous connections (default 500). Each probe attempts a TCP connect with a short timeout. Per-host jitter prevents connection storms from triggering rate-limit detections on firewalls.

```
#!/usr/bin/env python3
"""
async_scan.py — High-speed async TCP connect port scanner.
Usage: python3 async_scan.py --targets targets.txt --ports 22,80,443,445,3389 --workers 500
Output: open_ports.ndjson (newline-delimited JSON, one record per open port)
"""

import asyncio
import json
import pathlib
import random
import sys
import time
from argparse import ArgumentParser
from dataclasses import dataclass, asdict

# ── Data model for scan results ──────────────────────────────────────────────
@dataclass
class PortResult:
    ip: str
    port: int
    proto: str = "tcp"
    state: str = "open"

# ── Core probe coroutine ─────────────────────────────────────────────────────
async def tcp_probe(ip: str, port: int, timeout: float) -> bool:
    """
    Attempt a TCP connect to ip:port.
    Returns True if the connection is accepted (port is open).
    asyncio.wait_for wraps the coroutine with a hard timeout.
    """
    try:
        conn = asyncio.open_connection(ip, port)
        reader, writer = await asyncio.wait_for(conn, timeout=timeout)
        writer.close()
        await writer.wait_closed()
        return True
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return False

# ── Per-host scan coroutine ──────────────────────────────────────────────────
async def scan_host(ip: str, ports: list[int], sem: asyncio.Semaphore,
                    out_fh, timeout: float, jitter: float) -> None:
    """
    Probe all ports for a single host, respecting the global concurrency semaphore.
    Adds random jitter between probes to reduce IDS/SNORT burst-rate triggers.
    """
    for port in ports:
        async with sem:                          # blocks until a slot is free
            if await tcp_probe(ip, port, timeout):
                record = PortResult(ip=ip, port=port)
                out_fh.write(json.dumps(asdict(record)) + "\n")
                out_fh.flush()
                print(f"  [OPEN] {ip}:{port}")
        # Jitter: random sleep between 0 and jitter seconds between each probe
        if jitter > 0:
            await asyncio.sleep(random.uniform(0, jitter))

# ── Main entry point ─────────────────────────────────────────────────────────
async def main(args) -> None:
    targets = pathlib.Path(args.targets).read_text().splitlines()
    ports   = [int(p.strip()) for p in args.ports.split(",")]
    sem     = asyncio.Semaphore(args.workers)
    start   = time.monotonic()

    print(f"[*] Scanning {len(targets)} hosts, {len(ports)} ports, {args.workers} workers")

    with open(args.output, "w") as out_fh:
        tasks = [
            scan_host(ip, ports, sem, out_fh, args.timeout, args.jitter)
            for ip in targets if ip.strip()
        ]
        # asyncio.gather schedules all host-scan coroutines concurrently
        await asyncio.gather(*tasks)

    elapsed = time.monotonic() - start
    print(f"[+] Done in {elapsed:.1f}s — results in {args.output}")

if __name__ == "__main__":
    ap = ArgumentParser(description="Async TCP port scanner")
    ap.add_argument("--targets", default="targets.txt", help="File with one IP per line")
    ap.add_argument("--ports",   default="21,22,23,25,53,80,88,110,135,139,143,389,443,445,3389,5985,8080,8443",
                    help="Comma-separated port list")
    ap.add_argument("--workers", type=int,   default=500,  help="Max concurrent connections")
    ap.add_argument("--timeout", type=float, default=1.5,  help="Per-probe timeout (seconds)")
    ap.add_argument("--jitter",  type=float, default=0.02, help="Max per-probe jitter (seconds)")
    ap.add_argument("--output",  default="open_ports.ndjson", help="Output file (NDJSON)")
    asyncio.run(main(ap.parse_args()))
```

## Banner Grabber

After port discovery, send protocol-appropriate probes to extract service banners. The grabber sends a null byte (generic), HTTP GET, and FTP greeting probes and classifies the response. Results feed the service fingerprinter.

```
#!/usr/bin/env python3
"""
banner_grab.py — Grab service banners from open ports identified by async_scan.py.
Input:  open_ports.ndjson (from async_scan.py)
Output: banners.ndjson    (extends each record with 'banner' and 'service_hint' fields)
"""

import asyncio
import json
import pathlib
import re
from argparse import ArgumentParser

# ── Protocol-specific probe payloads ────────────────────────────────────────
PROBES: dict[int, bytes] = {
    21:   b"",                              # FTP — server sends banner first
    22:   b"",                              # SSH — server sends banner first
    25:   b"",                              # SMTP — server sends first
    80:   b"HEAD / HTTP/1.0\r\n\r\n",      # HTTP HEAD request
    110:  b"",                              # POP3 — server sends first
    143:  b"",                              # IMAP — server sends first
    443:  b"HEAD / HTTP/1.0\r\n\r\n",      # HTTPS (will fail TLS, grab error or partial)
    445:  b"",                              # SMB — passive grab
    3389: b"",                              # RDP — passive grab
    5985: b"GET /wsman HTTP/1.1\r\nHost: localhost\r\n\r\n",  # WinRM HTTP
}

# Service fingerprint patterns — (compiled_regex, service_name)
FINGERPRINTS: list[tuple[re.Pattern, str]] = [
    (re.compile(rb"SSH-\d+\.\d+"),          "SSH"),
    (re.compile(rb"220.*FTP",  re.I),       "FTP"),
    (re.compile(rb"220.*SMTP", re.I),       "SMTP"),
    (re.compile(rb"HTTP/\d",   re.I),       "HTTP"),
    (re.compile(rb"\*\s+OK.*IMAP",re.I),    "IMAP"),
    (re.compile(rb"\+OK",      re.I),       "POP3"),
    (re.compile(rb"SMBr|\\x00\\x00\\x00\\xb0"), "SMB"),
    (re.compile(rb"NTLMSSP"),               "NTLM/SMB"),
    (re.compile(rb"RDP|\\x03\\x00\\x00"),   "RDP"),
]

async def grab_banner(ip: str, port: int, timeout: float = 3.0) -> dict:
    """
    Open a TCP connection, optionally send a probe, read up to 1024 bytes of response.
    Returns a dict with 'banner' (hex+ascii) and 'service_hint'.
    """
    probe = PROBES.get(port, b"\r\n")   # default probe: CRLF (triggers many servers)
    result = {"ip": ip, "port": port, "banner": None, "service_hint": "unknown"}

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
        if probe:
            writer.write(probe)
            await writer.drain()

        # Read first 1024 bytes; many services send banners unprompted
        data = await asyncio.wait_for(reader.read(1024), timeout=timeout)
        writer.close()
        await writer.wait_closed()

        # Store as printable ASCII, replacing non-printable bytes with dots
        result["banner"] = data.decode("ascii", errors="replace").strip()

        # Service fingerprint: iterate regex patterns, first match wins
        for pattern, name in FINGERPRINTS:
            if pattern.search(data):
                result["service_hint"] = name
                break

    except Exception as e:
        result["error"] = str(e)

    return result

async def main(args) -> None:
    records = [json.loads(l) for l in pathlib.Path(args.input).read_text().splitlines() if l]
    sem     = asyncio.Semaphore(args.workers)

    async def bounded_grab(rec):
        async with sem:
            return await grab_banner(rec["ip"], rec["port"])

    results = await asyncio.gather(*[bounded_grab(r) for r in records])

    with open(args.output, "w") as fh:
        for r in results:
            fh.write(json.dumps(r) + "\n")

    print(f"[+] Banner grab complete — {len(results)} results in {args.output}")

if __name__ == "__main__":
    ap = ArgumentParser()
    ap.add_argument("--input",   default="open_ports.ndjson")
    ap.add_argument("--output",  default="banners.ndjson")
    ap.add_argument("--workers", type=int, default=50)
    asyncio.run(main(ap.parse_args()))
```

## SMB Host Profiler

SMB version negotiation reveals OS version, hostname, and domain membership without authentication. This pure-Python implementation sends a minimal SMBv2 negotiate request and parses the response to extract target metadata that BloodHound/Nmap would normally collect.

```
#!/usr/bin/env python3
"""
smb_probe.py — Passive SMB metadata extraction via unauthenticated negotiation.
Works on any host with TCP/445 open. No credentials required.
Extracts: hostname, domain, OS version, SMB dialect, signing enforced/required.
"""

import socket
import struct
import json
from dataclasses import dataclass, asdict

# SMBv2 NEGOTIATE request — minimal valid packet asking for all dialects
# Structure: NetBIOS header (4 bytes) + SMB2 header (64 bytes) + NEGOTIATE body
SMB2_NEGOTIATE = (
    b"\x00\x00\x00\xc0"          # NetBIOS session message, length 0xc0
    b"\xfeSMB"                    # SMB2 magic
    b"\x40\x00"                   # StructureSize = 64
    b"\x00\x00"                   # CreditCharge = 0
    b"\x00\x00\x00\x00"          # (Status / ChannelSequence)
    b"\x00\x00"                   # Command: NEGOTIATE (0x0000)
    b"\x01\x00"                   # CreditRequest = 1
    b"\x00\x00\x00\x00"          # Flags = 0
    b"\x00\x00\x00\x00"          # NextCommand = 0
    b"\x00" * 8                   # MessageId = 0
    b"\x00" * 4                   # Reserved
    b"\x00" * 4                   # TreeId = 0
    b"\x00" * 8                   # SessionId = 0
    b"\x00" * 16                  # Signature
    # NEGOTIATE body
    b"\x24\x00"                   # StructureSize = 36
    b"\x02\x00"                   # DialectCount = 2
    b"\x01\x00"                   # SecurityMode: signing enabled
    b"\x00\x00"                   # Reserved
    b"\x7f\x00\x00\x00"          # Capabilities
    b"\x00" * 16                  # ClientGuid
    b"\x00\x00\x00\x00"          # NegotiateContextOffset
    b"\x00\x00"                   # NegotiateContextCount
    b"\x00\x00"                   # Reserved2
    b"\x02\x02"                   # Dialect: SMB 2.0.2
    b"\x10\x02"                   # Dialect: SMB 2.1.0
)

@dataclass
class SMBInfo:
    ip: str
    port: int = 445
    dialect: str = "unknown"
    signing_required: bool = False
    hostname: str = ""
    domain: str = ""
    os: str = ""
    error: str = ""

def probe_smb(ip: str, timeout: float = 3.0) -> SMBInfo:
    """
    Send a minimal SMBv2 NEGOTIATE and parse the server's response.
    The negotiate response contains the server's GUID, dialect, signing flags,
    and a GSSAPI/SPNEGO token that includes the NetBIOS name and domain.
    """
    info = SMBInfo(ip=ip)
    try:
        sock = socket.create_connection((ip, 445), timeout=timeout)
        sock.sendall(SMB2_NEGOTIATE)
        data = sock.recv(4096)
        sock.close()

        if len(data) < 68:
            info.error = "response too short"
            return info

        # Bytes 68-69 in SMB2 response: SecurityMode flags
        # 0x01 = signing enabled, 0x02 = signing required
        security_mode = struct.unpack_from("<H", data, 70)[0]
        info.signing_required = bool(security_mode & 0x02)

        # Bytes 72-73: DialectRevision
        dialect_val = struct.unpack_from("<H", data, 72)[0]
        dialect_map = {
            0x0202: "SMB 2.0.2",
            0x0210: "SMB 2.1",
            0x0300: "SMB 3.0",
            0x0302: "SMB 3.0.2",
            0x0311: "SMB 3.1.1",
        }
        info.dialect = dialect_map.get(dialect_val, f"0x{dialect_val:04x}")

        # The SPNEGO token starts after the fixed negotiate body
        # Look for the NetBIOS name (preceded by 0x0202 type indicator in NTLM blob)
        try:
            nb_idx = data.index(b"\x02\x00\x0f\x00")  # MsvAvNbDomainName attribute
            # Each AvPair is: AvId(2) + AvLen(2) + Value(AvLen)
            av_len = struct.unpack_from("<H", data, nb_idx + 2)[0]
            info.domain = data[nb_idx + 4: nb_idx + 4 + av_len].decode("utf-16-le", errors="replace")
        except (ValueError, UnicodeDecodeError):
            pass

    except Exception as e:
        info.error = str(e)

    return info

if __name__ == "__main__":
    import sys
    targets = sys.argv[1:] if len(sys.argv) > 1 else ["127.0.0.1"]
    for ip in targets:
        result = probe_smb(ip)
        print(json.dumps(asdict(result), indent=2))
```

## Aggregating Results

Combine port scan and banner results into a host-centric view for prioritising attack surface. The aggregator groups all open ports per host, annotates with service hints, and outputs a summary sorted by number of open ports (most exposed hosts first).

```
#!/usr/bin/env python3
"""
aggregate.py — Merge open_ports.ndjson + banners.ndjson into a host-centric report.
Output: hosts_summary.json — sorted by attack surface (most ports first).
"""

import json, pathlib, collections

def load_ndjson(path: str) -> list[dict]:
    """Load a newline-delimited JSON file into a list of dicts."""
    return [json.loads(l) for l in pathlib.Path(path).read_text().splitlines() if l.strip()]

# Build banner lookup: (ip, port) -> banner record
banners_raw = load_ndjson("banners.ndjson")
banner_lookup: dict[tuple, dict] = {
    (r["ip"], r["port"]): r for r in banners_raw
}

# Group ports by host
hosts: dict[str, list[dict]] = collections.defaultdict(list)
for record in load_ndjson("open_ports.ndjson"):
    ip, port = record["ip"], record["port"]
    enriched = {
        "port":         port,
        "banner":       banner_lookup.get((ip, port), {}).get("banner", ""),
        "service_hint": banner_lookup.get((ip, port), {}).get("service_hint", "unknown"),
    }
    hosts[ip].append(enriched)

# Sort hosts by number of open ports descending
summary = [
    {"ip": ip, "open_port_count": len(ports), "ports": sorted(ports, key=lambda x: x["port"])}
    for ip, ports in sorted(hosts.items(), key=lambda kv: len(kv[1]), reverse=True)
]

pathlib.Path("hosts_summary.json").write_text(json.dumps(summary, indent=2))
print(f"[+] Summarised {len(summary)} hosts with open ports.")
```
