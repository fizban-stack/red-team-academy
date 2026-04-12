#!/usr/bin/env python3
"""
android-recon.py — Automated Android device reconnaissance via ADB.
Extracts device info, installed apps, accounts, network config, and
identifies attack surface (debuggable apps, exported components, backup-enabled apps).

Usage:
    python3 android-recon.py [--device SERIAL] [--output DIR]

Part of: Red Team Academy — Android Tools
"""

import subprocess
import sys
import os
import json
import re
import argparse
from datetime import datetime
from pathlib import Path


def run_adb(cmd, device=None, timeout=30):
    """Execute an ADB command and return stdout."""
    prefix = ["adb"]
    if device:
        prefix += ["-s", device]
    full_cmd = prefix + cmd.split()
    try:
        result = subprocess.run(
            full_cmd, capture_output=True, text=True, timeout=timeout
        )
        return result.stdout.strip()
    except subprocess.TimeoutExpired:
        return "[TIMEOUT]"
    except Exception as e:
        return f"[ERROR] {e}"


def check_adb_connection(device=None):
    """Verify ADB is connected to a device."""
    output = run_adb("devices", device)
    lines = [l for l in output.splitlines() if "\tdevice" in l]
    if not lines:
        print("[-] No ADB device connected. Enable USB debugging and connect.")
        sys.exit(1)
    print(f"[+] Found {len(lines)} device(s)")
    return [l.split("\t")[0] for l in lines]


def get_device_info(device=None):
    """Gather comprehensive device information."""
    props = {
        "model": "ro.product.model",
        "manufacturer": "ro.product.manufacturer",
        "brand": "ro.product.brand",
        "android_version": "ro.build.version.release",
        "sdk_version": "ro.build.version.sdk",
        "security_patch": "ro.build.version.security_patch",
        "build_id": "ro.build.display.id",
        "fingerprint": "ro.build.fingerprint",
        "hardware": "ro.hardware",
        "board": "ro.product.board",
        "serial": "ro.serialno",
        "bootloader": "ro.bootloader",
        "baseband": "gsm.version.baseband",
        "selinux": "ro.build.selinux",
    }
    info = {}
    for key, prop in props.items():
        info[key] = run_adb(f"shell getprop {prop}", device)

    # SELinux enforcement
    info["selinux_enforce"] = run_adb("shell getenforce", device)

    # Kernel version
    info["kernel"] = run_adb("shell uname -r", device)

    # Encryption state
    info["encryption"] = run_adb(
        "shell getprop ro.crypto.state", device
    )

    # Root check
    su_check = run_adb("shell which su", device)
    info["root_binary"] = "found" if su_check and "not found" not in su_check else "not found"

    # USB debugging over network
    adb_port = run_adb("shell getprop service.adb.tcp.port", device)
    info["adb_tcp_port"] = adb_port if adb_port else "disabled"

    return info


def get_installed_apps(device=None):
    """List all installed third-party applications."""
    output = run_adb("shell pm list packages -3 -f", device)
    apps = []
    for line in output.splitlines():
        if line.startswith("package:"):
            parts = line[8:].rsplit("=", 1)
            if len(parts) == 2:
                apps.append({"path": parts[0], "package": parts[1]})
    return apps


def find_debuggable_apps(device=None):
    """Find apps with debuggable flag set (major vulnerability)."""
    output = run_adb("shell pm list packages -3", device)
    debuggable = []
    for line in output.splitlines():
        pkg = line.replace("package:", "").strip()
        if not pkg:
            continue
        dump = run_adb(f"shell dumpsys package {pkg}", device)
        # Check for DEBUGGABLE flag in pkgFlags
        if "DEBUGGABLE" in dump:
            debuggable.append(pkg)
    return debuggable


def find_backup_enabled_apps(device=None):
    """Find apps with allowBackup=true (data extractable via adb backup)."""
    output = run_adb("shell pm list packages -3", device)
    backup_enabled = []
    for line in output.splitlines():
        pkg = line.replace("package:", "").strip()
        if not pkg:
            continue
        dump = run_adb(f"shell dumpsys package {pkg}", device)
        if "ALLOW_BACKUP" in dump:
            backup_enabled.append(pkg)
    return backup_enabled


def get_exported_components(package, device=None):
    """Get exported components for a specific package."""
    dump = run_adb(f"shell dumpsys package {package}", device)
    components = {
        "activities": [],
        "services": [],
        "receivers": [],
        "providers": [],
    }
    current_section = None
    for line in dump.splitlines():
        line = line.strip()
        if "Activity Resolver Table:" in line:
            current_section = "activities"
        elif "Service Resolver Table:" in line:
            current_section = "services"
        elif "Receiver Resolver Table:" in line:
            current_section = "receivers"
        elif "Provider Resolver Table:" in line or "ContentProvider" in line:
            current_section = "providers"
        elif current_section and package in line:
            # Extract component name
            match = re.search(r'([a-zA-Z0-9_.]+/[a-zA-Z0-9_.]+)', line)
            if match:
                comp = match.group(1)
                if comp not in components[current_section]:
                    components[current_section].append(comp)
    return components


def get_network_info(device=None):
    """Gather network configuration and connections."""
    info = {}
    info["interfaces"] = run_adb("shell ip addr", device)
    info["routes"] = run_adb("shell ip route", device)
    info["dns"] = run_adb("shell getprop net.dns1", device)
    info["dns2"] = run_adb("shell getprop net.dns2", device)
    info["wifi_ssid"] = run_adb(
        "shell dumpsys wifi | grep 'mWifiInfo'", device
    )
    info["arp_table"] = run_adb("shell cat /proc/net/arp", device)
    info["connections"] = run_adb("shell netstat -tlnp 2>/dev/null", device)
    return info


def get_accounts(device=None):
    """List accounts registered on the device."""
    output = run_adb("shell dumpsys account", device)
    accounts = []
    for line in output.splitlines():
        line = line.strip()
        if line.startswith("Account {"):
            match = re.search(r'name=([^,]+), type=([^}]+)', line)
            if match:
                accounts.append({
                    "name": match.group(1),
                    "type": match.group(2),
                })
    return accounts


def check_interesting_files(device=None):
    """Check for world-readable or sensitive files."""
    targets = [
        "/sdcard/Download/",
        "/sdcard/DCIM/Camera/",
        "/sdcard/Documents/",
        "/data/misc/wifi/WifiConfigStore.xml",
        "/data/misc/wifi/wpa_supplicant.conf",
    ]
    found = {}
    for path in targets:
        output = run_adb(f"shell ls {path} 2>/dev/null", device)
        if output and "No such file" not in output and "Permission denied" not in output:
            files = [f for f in output.splitlines() if f.strip()]
            found[path] = len(files)
    return found


def generate_report(data, output_dir):
    """Generate a text and JSON report."""
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    # JSON report
    json_path = os.path.join(output_dir, f"android_recon_{timestamp}.json")
    with open(json_path, "w") as f:
        json.dump(data, f, indent=2, default=str)

    # Text report
    txt_path = os.path.join(output_dir, f"android_recon_{timestamp}.txt")
    with open(txt_path, "w") as f:
        f.write("=" * 70 + "\n")
        f.write("  ANDROID DEVICE RECONNAISSANCE REPORT\n")
        f.write(f"  Generated: {datetime.now().isoformat()}\n")
        f.write("=" * 70 + "\n\n")

        f.write("## DEVICE INFO\n")
        for k, v in data.get("device_info", {}).items():
            f.write(f"  {k}: {v}\n")

        f.write(f"\n## INSTALLED APPS ({len(data.get('apps', []))})\n")
        for app in data.get("apps", []):
            f.write(f"  {app['package']}\n")

        f.write(f"\n## DEBUGGABLE APPS (CRITICAL)\n")
        for app in data.get("debuggable_apps", []):
            f.write(f"  [!] {app}\n")

        f.write(f"\n## BACKUP-ENABLED APPS\n")
        for app in data.get("backup_enabled", []):
            f.write(f"  [*] {app}\n")

        f.write(f"\n## ACCOUNTS\n")
        for acc in data.get("accounts", []):
            f.write(f"  {acc['name']} ({acc['type']})\n")

        f.write(f"\n## NETWORK\n")
        net = data.get("network", {})
        f.write(f"  Wi-Fi: {net.get('wifi_ssid', 'N/A')}\n")
        f.write(f"  DNS: {net.get('dns', 'N/A')}\n")
        f.write(f"\n  ARP Table:\n{net.get('arp_table', 'N/A')}\n")

        f.write(f"\n## INTERESTING FILES\n")
        for path, count in data.get("files", {}).items():
            f.write(f"  {path}: {count} files\n")

        # Attack surface summary
        f.write("\n" + "=" * 70 + "\n")
        f.write("  ATTACK SURFACE SUMMARY\n")
        f.write("=" * 70 + "\n")
        info = data.get("device_info", {})
        if info.get("root_binary") == "found":
            f.write("  [CRITICAL] Device is rooted — full access possible\n")
        if info.get("selinux_enforce") == "Permissive":
            f.write("  [CRITICAL] SELinux is Permissive — no mandatory access control\n")
        if info.get("adb_tcp_port") not in ("disabled", ""):
            f.write(f"  [HIGH] ADB over network enabled on port {info['adb_tcp_port']}\n")
        if data.get("debuggable_apps"):
            f.write(f"  [HIGH] {len(data['debuggable_apps'])} debuggable apps found\n")
        if data.get("backup_enabled"):
            f.write(f"  [MEDIUM] {len(data['backup_enabled'])} apps allow backup extraction\n")

    print(f"\n[+] Reports saved:")
    print(f"    {txt_path}")
    print(f"    {json_path}")
    return txt_path, json_path


def main():
    parser = argparse.ArgumentParser(
        description="Android Device Reconnaissance via ADB"
    )
    parser.add_argument(
        "--device", "-d", help="Target device serial (from adb devices)"
    )
    parser.add_argument(
        "--output", "-o", default="./android_recon",
        help="Output directory (default: ./android_recon)"
    )
    parser.add_argument(
        "--quick", "-q", action="store_true",
        help="Quick scan (skip slow exported component enumeration)"
    )
    args = parser.parse_args()

    print("[*] Android Recon — Red Team Academy")
    print("[*] Checking ADB connection...")
    devices = check_adb_connection(args.device)
    target = args.device or devices[0]
    print(f"[+] Target device: {target}")

    data = {"target": target, "timestamp": datetime.now().isoformat()}

    print("[*] Gathering device information...")
    data["device_info"] = get_device_info(target)
    model = data["device_info"].get("model", "Unknown")
    version = data["device_info"].get("android_version", "Unknown")
    print(f"[+] Device: {model} (Android {version})")

    print("[*] Listing installed apps...")
    data["apps"] = get_installed_apps(target)
    print(f"[+] Found {len(data['apps'])} third-party apps")

    print("[*] Checking for debuggable apps...")
    data["debuggable_apps"] = find_debuggable_apps(target)
    if data["debuggable_apps"]:
        print(f"[!] FOUND {len(data['debuggable_apps'])} DEBUGGABLE APPS!")

    print("[*] Checking for backup-enabled apps...")
    data["backup_enabled"] = find_backup_enabled_apps(target)
    print(f"[+] {len(data['backup_enabled'])} apps allow backup")

    print("[*] Enumerating accounts...")
    data["accounts"] = get_accounts(target)
    print(f"[+] Found {len(data['accounts'])} accounts")

    print("[*] Gathering network info...")
    data["network"] = get_network_info(target)

    print("[*] Checking for interesting files...")
    data["files"] = check_interesting_files(target)

    generate_report(data, args.output)


if __name__ == "__main__":
    main()
