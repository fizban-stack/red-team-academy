#!/usr/bin/env python3
"""
apk-extractor.py — Extract, decompile, and scan APKs for secrets and vulnerabilities.
Wraps apktool, jadx, and custom secret scanning into a single pipeline.

Usage:
    python3 apk-extractor.py <apk_file> [--output DIR] [--secrets-only]
    python3 apk-extractor.py --pull <package_name> [--output DIR]

Part of: Red Team Academy — Android Tools
"""

import subprocess
import sys
import os
import re
import json
import argparse
import hashlib
from pathlib import Path
from datetime import datetime


# Secret patterns to scan for
SECRET_PATTERNS = {
    "AWS Access Key": r"AKIA[A-Z0-9]{16}",
    "AWS Secret Key": r"(?i)aws_secret_access_key\s*[=:]\s*[A-Za-z0-9/+=]{40}",
    "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
    "Google OAuth": r"[0-9]+-[a-z0-9_]{32}\.apps\.googleusercontent\.com",
    "Firebase URL": r"https://[a-z0-9-]+\.firebaseio\.com",
    "Firebase Config": r"google-services\.json|GoogleService-Info\.plist",
    "GitHub Token": r"gh[pousr]_[A-Za-z0-9_]{36,255}",
    "Stripe Secret": r"sk_live_[a-zA-Z0-9]{24,99}",
    "Stripe Publish": r"pk_live_[a-zA-Z0-9]{24,99}",
    "Slack Token": r"xox[baprs]-[0-9]{10,13}-[a-zA-Z0-9-]+",
    "Twilio SID": r"AC[a-f0-9]{32}",
    "SendGrid Key": r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}",
    "Mailgun Key": r"key-[a-zA-Z0-9]{32}",
    "JWT Token": r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
    "Private Key": r"-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----",
    "Basic Auth": r"(?i)basic\s+[A-Za-z0-9+/=]{20,}",
    "Bearer Token": r"(?i)bearer\s+[A-Za-z0-9_\-.~+/]+=*",
    "Password Field": r'(?i)(password|passwd|pwd)\s*[=:]\s*["\'][^"\']{4,}["\']',
    "API Key Generic": r'(?i)(api[_-]?key|apikey)\s*[=:]\s*["\'][A-Za-z0-9_\-]{16,}["\']',
    "Secret Generic": r'(?i)(secret|token)\s*[=:]\s*["\'][A-Za-z0-9_\-]{16,}["\']',
    "Hardcoded IP": r"\b(?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b",
    "Hardcoded URL": r'https?://[a-zA-Z0-9._/-]+\.(internal|local|corp|dev|staging)',
}

# Vulnerability patterns in code
VULN_PATTERNS = {
    "Debuggable": r'android:debuggable="true"',
    "Backup Enabled": r'android:allowBackup="true"',
    "Cleartext Traffic": r'android:usesCleartextTraffic="true"',
    "WebView JS Enabled": r"setJavaScriptEnabled\(true\)",
    "WebView File Access": r"setAllowFileAccess\(true\)",
    "WebView File URL Access": r"setAllowFileAccessFromFileURLs\(true\)",
    "WebView Universal Access": r"setAllowUniversalAccessFromFileURLs\(true\)",
    "JavaScript Interface": r"addJavascriptInterface",
    "Exported Component": r'android:exported="true"',
    "SQL Raw Query": r"rawQuery\s*\(",
    "Exec Command": r"Runtime\.getRuntime\(\)\.exec\(",
    "Log Sensitive": r'Log\.[divwe]\s*\(\s*"[^"]*(?:password|token|key|secret)',
    "Hardcoded Crypto Key": r'SecretKeySpec\s*\(\s*"',
    "Weak Crypto": r"DES|RC4|MD5|SHA1(?![\d])|ECB",
    "World Readable": r"MODE_WORLD_READABLE|MODE_WORLD_WRITEABLE",
    "Clipboard Usage": r"ClipboardManager|setPrimaryClip",
    "Custom Scheme": r'android:scheme="(?!https?|tel|mailto)',
}


def check_tool(name):
    """Check if a required tool is installed."""
    result = subprocess.run(
        ["which", name], capture_output=True, text=True
    )
    return result.returncode == 0


def pull_apk(package, device=None):
    """Pull an APK from a connected device."""
    prefix = ["adb"]
    if device:
        prefix += ["-s", device]

    # Get APK path
    result = subprocess.run(
        prefix + ["shell", "pm", "path", package],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        print(f"[-] Package {package} not found on device")
        sys.exit(1)

    apk_path = result.stdout.strip().replace("package:", "")
    local_path = f"{package}.apk"

    print(f"[*] Pulling {apk_path}...")
    subprocess.run(prefix + ["pull", apk_path, local_path], check=True)
    return local_path


def get_apk_info(apk_path):
    """Get basic APK information."""
    info = {
        "file": apk_path,
        "size": os.path.getsize(apk_path),
        "sha256": hashlib.sha256(Path(apk_path).read_bytes()).hexdigest(),
    }

    if check_tool("aapt"):
        result = subprocess.run(
            ["aapt", "dump", "badging", apk_path],
            capture_output=True, text=True,
        )
        output = result.stdout
        match = re.search(r"package: name='([^']+)'", output)
        if match:
            info["package"] = match.group(1)
        match = re.search(r"versionName='([^']+)'", output)
        if match:
            info["version"] = match.group(1)
        match = re.search(r"sdkVersion:'(\d+)'", output)
        if match:
            info["min_sdk"] = match.group(1)
        match = re.search(r"targetSdkVersion:'(\d+)'", output)
        if match:
            info["target_sdk"] = match.group(1)

        # Extract permissions
        perms = re.findall(r"uses-permission: name='([^']+)'", output)
        info["permissions"] = perms

    return info


def decompile_apktool(apk_path, output_dir):
    """Decompile APK with apktool (smali + resources)."""
    if not check_tool("apktool"):
        print("[-] apktool not found — skipping resource decompilation")
        return None

    dest = os.path.join(output_dir, "apktool_out")
    print(f"[*] Decompiling with apktool → {dest}")
    subprocess.run(
        ["apktool", "d", apk_path, "-o", dest, "-f"],
        capture_output=True, text=True,
    )
    return dest


def decompile_jadx(apk_path, output_dir):
    """Decompile APK with jadx (Java source)."""
    if not check_tool("jadx"):
        print("[-] jadx not found — skipping Java decompilation")
        return None

    dest = os.path.join(output_dir, "jadx_out")
    print(f"[*] Decompiling with jadx → {dest}")
    subprocess.run(
        ["jadx", "-d", dest, "--deobf", apk_path],
        capture_output=True, text=True,
    )
    return dest


def scan_directory(scan_dir, patterns, label):
    """Scan a directory for regex patterns."""
    findings = []
    if not scan_dir or not os.path.isdir(scan_dir):
        return findings

    for root, dirs, files in os.walk(scan_dir):
        # Skip binary/resource directories
        skip_dirs = {".git", "node_modules", "original", "smali_classes2"}
        dirs[:] = [d for d in dirs if d not in skip_dirs]

        for fname in files:
            # Only scan text-like files
            if fname.endswith(('.png', '.jpg', '.gif', '.webp', '.dex',
                              '.so', '.ogg', '.mp3', '.ttf', '.otf')):
                continue

            fpath = os.path.join(root, fname)
            try:
                with open(fpath, "r", errors="ignore") as f:
                    content = f.read()
                    for name, pattern in patterns.items():
                        matches = re.finditer(pattern, content)
                        for match in matches:
                            # Get line number
                            line_num = content[:match.start()].count('\n') + 1
                            # Truncate match for display
                            matched = match.group(0)[:100]
                            rel_path = os.path.relpath(fpath, scan_dir)
                            findings.append({
                                "type": label,
                                "name": name,
                                "file": rel_path,
                                "line": line_num,
                                "match": matched,
                            })
            except (OSError, UnicodeDecodeError):
                continue

    return findings


def analyze_manifest(apktool_dir):
    """Deep analysis of AndroidManifest.xml."""
    manifest_path = os.path.join(apktool_dir, "AndroidManifest.xml")
    if not os.path.exists(manifest_path):
        return {}

    with open(manifest_path, "r") as f:
        content = f.read()

    analysis = {
        "exported_activities": [],
        "exported_services": [],
        "exported_receivers": [],
        "exported_providers": [],
        "deep_links": [],
        "custom_permissions": [],
        "dangerous_permissions": [],
    }

    # Find exported components
    component_pattern = r'<(activity|service|receiver|provider)[^>]*android:name="([^"]+)"[^>]*android:exported="true"'
    for match in re.finditer(component_pattern, content):
        comp_type = match.group(1) + "s"
        key = f"exported_{comp_type}"
        if key in analysis:
            analysis[key].append(match.group(2))

    # Find deep link schemes
    scheme_pattern = r'android:scheme="([^"]+)"'
    for match in re.finditer(scheme_pattern, content):
        analysis["deep_links"].append(match.group(1))

    # Dangerous permissions
    dangerous = [
        "READ_CONTACTS", "WRITE_CONTACTS", "READ_SMS", "SEND_SMS",
        "READ_CALL_LOG", "CAMERA", "RECORD_AUDIO", "ACCESS_FINE_LOCATION",
        "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE",
    ]
    for perm in dangerous:
        if perm in content:
            analysis["dangerous_permissions"].append(perm)

    return analysis


def generate_report(apk_info, manifest_analysis, secrets, vulns, output_dir):
    """Generate comprehensive analysis report."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    pkg_name = apk_info.get("package", "unknown")

    # JSON report
    report_data = {
        "apk_info": apk_info,
        "manifest": manifest_analysis,
        "secrets": secrets,
        "vulnerabilities": vulns,
        "scan_time": datetime.now().isoformat(),
    }
    json_path = os.path.join(output_dir, f"apk_scan_{pkg_name}_{timestamp}.json")
    with open(json_path, "w") as f:
        json.dump(report_data, f, indent=2, default=str)

    # Text report
    txt_path = os.path.join(output_dir, f"apk_scan_{pkg_name}_{timestamp}.txt")
    with open(txt_path, "w") as f:
        f.write("=" * 70 + "\n")
        f.write("  APK SECURITY ANALYSIS REPORT\n")
        f.write(f"  Package: {pkg_name}\n")
        f.write(f"  Generated: {datetime.now().isoformat()}\n")
        f.write("=" * 70 + "\n\n")

        f.write("## APK INFO\n")
        for k, v in apk_info.items():
            if k != "permissions":
                f.write(f"  {k}: {v}\n")

        f.write(f"\n## PERMISSIONS ({len(apk_info.get('permissions', []))})\n")
        for perm in apk_info.get("permissions", []):
            f.write(f"  {perm}\n")

        f.write(f"\n## MANIFEST ANALYSIS\n")
        if manifest_analysis:
            for key, items in manifest_analysis.items():
                if items:
                    f.write(f"\n  {key}:\n")
                    for item in items:
                        f.write(f"    - {item}\n")

        f.write(f"\n## SECRETS FOUND ({len(secrets)})\n")
        for s in secrets:
            f.write(f"\n  [{s['name']}]\n")
            f.write(f"    File: {s['file']}:{s['line']}\n")
            f.write(f"    Match: {s['match']}\n")

        f.write(f"\n## VULNERABILITIES ({len(vulns)})\n")
        for v in vulns:
            f.write(f"\n  [{v['name']}]\n")
            f.write(f"    File: {v['file']}:{v['line']}\n")
            f.write(f"    Match: {v['match']}\n")

        # Summary
        f.write("\n" + "=" * 70 + "\n")
        f.write("  RISK SUMMARY\n")
        f.write("=" * 70 + "\n")
        if secrets:
            f.write(f"  [CRITICAL] {len(secrets)} hardcoded secrets found\n")
        if any(v["name"] == "Debuggable" for v in vulns):
            f.write("  [CRITICAL] App is debuggable in production\n")
        if any(v["name"] == "WebView JS Enabled" for v in vulns):
            f.write("  [HIGH] WebView with JavaScript enabled\n")
        if any(v["name"] == "JavaScript Interface" for v in vulns):
            f.write("  [HIGH] JavaScript bridge exposed\n")
        if manifest_analysis.get("exported_activities"):
            count = len(manifest_analysis["exported_activities"])
            f.write(f"  [MEDIUM] {count} exported activities\n")

    print(f"\n[+] Reports saved:")
    print(f"    {txt_path}")
    print(f"    {json_path}")


def main():
    parser = argparse.ArgumentParser(
        description="APK Security Scanner — Extract, decompile, and scan"
    )
    parser.add_argument("apk", nargs="?", help="Path to APK file")
    parser.add_argument("--pull", help="Pull APK from device by package name")
    parser.add_argument("--device", help="ADB device serial")
    parser.add_argument(
        "--output", "-o", default="./apk_analysis",
        help="Output directory"
    )
    parser.add_argument(
        "--secrets-only", action="store_true",
        help="Only scan for secrets (skip decompilation if already done)"
    )
    args = parser.parse_args()

    if not args.apk and not args.pull:
        parser.print_help()
        sys.exit(1)

    print("[*] APK Extractor — Red Team Academy\n")

    # Get APK
    if args.pull:
        apk_path = pull_apk(args.pull, args.device)
    else:
        apk_path = args.apk

    if not os.path.exists(apk_path):
        print(f"[-] File not found: {apk_path}")
        sys.exit(1)

    os.makedirs(args.output, exist_ok=True)

    # APK info
    print("[*] Analyzing APK metadata...")
    apk_info = get_apk_info(apk_path)
    print(f"[+] Package: {apk_info.get('package', 'unknown')}")
    print(f"[+] Version: {apk_info.get('version', 'unknown')}")
    print(f"[+] SHA256: {apk_info.get('sha256', 'unknown')[:16]}...")
    print(f"[+] Permissions: {len(apk_info.get('permissions', []))}")

    # Decompile
    apktool_dir = decompile_apktool(apk_path, args.output)
    jadx_dir = decompile_jadx(apk_path, args.output)

    # Manifest analysis
    manifest_analysis = {}
    if apktool_dir:
        print("[*] Analyzing AndroidManifest.xml...")
        manifest_analysis = analyze_manifest(apktool_dir)

    # Scan for secrets and vulns
    print("[*] Scanning for secrets...")
    secrets = []
    if jadx_dir:
        secrets += scan_directory(jadx_dir, SECRET_PATTERNS, "secret")
    if apktool_dir:
        secrets += scan_directory(apktool_dir, SECRET_PATTERNS, "secret")

    # Deduplicate
    seen = set()
    unique_secrets = []
    for s in secrets:
        key = (s["name"], s["match"])
        if key not in seen:
            seen.add(key)
            unique_secrets.append(s)
    secrets = unique_secrets

    print(f"[+] Found {len(secrets)} potential secrets")

    print("[*] Scanning for vulnerabilities...")
    vulns = []
    if jadx_dir:
        vulns += scan_directory(jadx_dir, VULN_PATTERNS, "vulnerability")
    if apktool_dir:
        vulns += scan_directory(apktool_dir, VULN_PATTERNS, "vulnerability")

    # Deduplicate vulns
    seen = set()
    unique_vulns = []
    for v in vulns:
        key = (v["name"], v["file"], v["line"])
        if key not in seen:
            seen.add(key)
            unique_vulns.append(v)
    vulns = unique_vulns

    print(f"[+] Found {len(vulns)} potential vulnerabilities")

    # Report
    generate_report(apk_info, manifest_analysis, secrets, vulns, args.output)


if __name__ == "__main__":
    main()
