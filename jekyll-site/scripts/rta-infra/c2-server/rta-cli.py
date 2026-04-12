#!/usr/bin/env python3
"""
rta-cli — Operator CLI for rta-c2.

Authorized red team use only. Runs directly against the sqlite database
on the team server over SSH/WireGuard. Does not touch the HTTP listener.

Usage:
    rta-cli list
    rta-cli tasks <implant_id>
    rta-cli task  <implant_id> <command...>
    rta-cli out   <task_id>
    rta-cli note  <implant_id> <text...>
"""

import os
import sqlite3
import sys
import time
from pathlib import Path

DB_PATH = Path(os.environ.get("RTA_C2_DB", "/var/lib/rta-c2/c2.db"))
OPERATOR = os.environ.get("RTA_OPERATOR", os.environ.get("USER", "unknown"))


def conn() -> sqlite3.Connection:
    c = sqlite3.connect(DB_PATH, isolation_level=None)
    c.row_factory = sqlite3.Row
    return c


def fmt_age(ts: int) -> str:
    if not ts:
        return "-"
    delta = int(time.time()) - ts
    if delta < 60:
        return f"{delta}s"
    if delta < 3600:
        return f"{delta // 60}m"
    if delta < 86400:
        return f"{delta // 3600}h"
    return f"{delta // 86400}d"


def cmd_list():
    c = conn()
    rows = c.execute(
        "SELECT id, hostname, username, os, ip, last_seen FROM implants ORDER BY last_seen DESC"
    ).fetchall()
    if not rows:
        print("no implants registered")
        return
    print(f"{'ID':<14}{'HOST':<20}{'USER':<16}{'OS':<10}{'IP':<18}LAST")
    for r in rows:
        print(
            f"{r['id']:<14}{(r['hostname'] or '')[:19]:<20}"
            f"{(r['username'] or '')[:15]:<16}{(r['os'] or '')[:9]:<10}"
            f"{(r['ip'] or '')[:17]:<18}{fmt_age(r['last_seen'])}"
        )


def cmd_tasks(iid: str):
    c = conn()
    rows = c.execute(
        """SELECT id, command, sent_at, completed_at, operator
           FROM tasks WHERE implant_id = ? ORDER BY id DESC LIMIT 40""",
        (iid,),
    ).fetchall()
    if not rows:
        print(f"no tasks for {iid}")
        return
    print(f"{'TID':<6}{'STATUS':<12}{'OP':<12}COMMAND")
    for r in rows:
        status = "done" if r["completed_at"] else ("sent" if r["sent_at"] else "queued")
        print(f"{r['id']:<6}{status:<12}{(r['operator'] or '-'):<12}{r['command']}")


def cmd_task(iid: str, command: str):
    now = int(time.time())
    c = conn()
    cur = c.execute(
        """INSERT INTO tasks(implant_id, command, created_at, operator)
           VALUES (?, ?, ?, ?)""",
        (iid, command, now, OPERATOR),
    )
    print(f"queued tid={cur.lastrowid} for {iid}: {command}")


def cmd_out(tid: str):
    c = conn()
    row = c.execute(
        "SELECT implant_id, command, result, completed_at FROM tasks WHERE id = ?",
        (int(tid),),
    ).fetchone()
    if not row:
        print(f"no task {tid}")
        return
    if not row["completed_at"]:
        print(f"tid={tid} not yet returned")
        return
    print(f"# implant={row['implant_id']}  command={row['command']}")
    print(row["result"] or "")


def cmd_note(iid: str, text: str):
    c = conn()
    c.execute("UPDATE implants SET notes = ? WHERE id = ?", (text, iid))
    print(f"note set on {iid}")


def main():
    if len(sys.argv) < 2:
        print(__doc__.strip())
        sys.exit(1)
    verb = sys.argv[1]
    args = sys.argv[2:]
    try:
        if verb == "list":
            cmd_list()
        elif verb == "tasks" and args:
            cmd_tasks(args[0])
        elif verb == "task" and len(args) >= 2:
            cmd_task(args[0], " ".join(args[1:]))
        elif verb == "out" and args:
            cmd_out(args[0])
        elif verb == "note" and len(args) >= 2:
            cmd_note(args[0], " ".join(args[1:]))
        else:
            print(__doc__.strip())
            sys.exit(2)
    except sqlite3.OperationalError as exc:
        print(f"database error: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
