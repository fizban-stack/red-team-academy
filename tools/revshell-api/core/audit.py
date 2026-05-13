"""
Append-only JSONL audit log for generated payloads.

Disabled when `AUDIT_LOG` env is unset. When enabled, every payload-producing
endpoint logs a structured record so client engagements have a verifiable trail.

Record schema:
    {
        "ts":             ISO-8601 UTC timestamp,
        "engagement_id":  client-supplied tag (from X-Engagement-ID header),
        "route":          API path,
        "module":         logical category (shell, persist, lateral, ...),
        "technique":      technique key inside the module,
        "params":         dict of request fields (lhost is preserved; secrets redacted),
        "payload_sha256": SHA-256 of the produced command/payload (not the payload itself),
        "client_ip":      source IP if proxied/headers expose it, else FastAPI client.host,
    }
"""
import hashlib
import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path

from .settings import SETTINGS

_REDACTED_KEYS = {"password", "passwd", "secret", "token", "api_token", "hash_nt"}
_lock = threading.Lock()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def _redact(params: dict) -> dict:
    if not isinstance(params, dict):
        return {"_value": str(params)}
    out: dict = {}
    for k, v in params.items():
        if k in _REDACTED_KEYS and v:
            out[k] = "***redacted***"
        elif isinstance(v, dict):
            out[k] = _redact(v)
        else:
            out[k] = v
    return out


def enabled() -> bool:
    return bool(SETTINGS.audit_log_path)


def log_event(
    route: str,
    module: str,
    technique: str,
    params: dict,
    payload: str,
    engagement_id: str | None = None,
    client_ip: str | None = None,
) -> None:
    """Append a single JSONL record. No-op when audit log is disabled."""
    path = SETTINGS.audit_log_path
    if not path:
        return
    record = {
        "ts": _now(),
        "engagement_id": engagement_id,
        "route": route,
        "module": module,
        "technique": technique,
        "params": _redact(params),
        "payload_sha256": _hash(payload),
        "client_ip": client_ip,
    }
    line = json.dumps(record, default=str) + "\n"
    log_path = Path(path)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with _lock:
        with log_path.open("a") as f:
            f.write(line)


def iter_records():
    """Yield decoded records from the audit log. Returns empty when disabled."""
    path = SETTINGS.audit_log_path
    if not path or not os.path.exists(path):
        return
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def render_markdown_report(engagement_id: str | None = None) -> str:
    """Produce a markdown summary suitable for client deliverables."""
    records = list(iter_records())
    if engagement_id:
        records = [r for r in records if r.get("engagement_id") == engagement_id]

    if not records:
        return "# Engagement report\n\n_No matching audit records._\n"

    first_ts = records[0]["ts"]
    last_ts = records[-1]["ts"]

    by_module: dict[str, int] = {}
    by_technique: dict[str, int] = {}
    for r in records:
        by_module[r["module"]] = by_module.get(r["module"], 0) + 1
        key = f"{r['module']}.{r['technique']}"
        by_technique[key] = by_technique.get(key, 0) + 1

    lines: list[str] = []
    lines.append(f"# Engagement report — {engagement_id or 'all engagements'}")
    lines.append("")
    lines.append(f"- **Total payloads generated:** {len(records)}")
    lines.append(f"- **Window:** {first_ts} → {last_ts}")
    lines.append("")
    lines.append("## By module")
    for module, count in sorted(by_module.items(), key=lambda kv: -kv[1]):
        lines.append(f"- `{module}` — {count}")
    lines.append("")
    lines.append("## By technique")
    for tech, count in sorted(by_technique.items(), key=lambda kv: -kv[1]):
        lines.append(f"- `{tech}` — {count}")
    lines.append("")
    lines.append("## Recent events")
    lines.append("")
    lines.append("| Timestamp | Module | Technique | Payload SHA-256 (prefix) |")
    lines.append("|-----------|--------|-----------|--------------------------|")
    for r in records[-20:]:
        lines.append(
            f"| {r['ts']} | {r['module']} | {r['technique']} | `{r['payload_sha256'][:16]}…` |"
        )
    return "\n".join(lines) + "\n"
