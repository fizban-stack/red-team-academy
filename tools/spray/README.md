# spray

Credential spray orchestrator for authorized red team engagements.

> Unauthorized use against systems you do not own is illegal. Only run against
> targets you have explicit written permission to test.

---

## Quick start

```bash
pip install -r requirements.txt

# O365 spray
python spray.py \
    --userlist users.txt \
    --passlist passes.txt \
    --target o365 \
    --engagement-id ACME-2026-Q2

# OWA
python spray.py --userlist users.txt --password 'Spring2026!' \
    --target owa --owa-url https://mail.acme.com

# ADFS
python spray.py --userlist users.txt --password 'Spring2026!' \
    --target adfs --adfs-url https://adfs.acme.com

# Citrix (auto-detects StoreFront vs NetScaler)
python spray.py --userlist users.txt --password 'Spring2026!' \
    --target citrix --citrix-url https://citrix.acme.com

# Palo Alto GlobalProtect VPN
python spray.py --userlist users.txt --password 'Spring2026!' \
    --target globalprotect --gp-url https://vpn.acme.com

# Generic form-based login (success on HTTP 302)
python spray.py --userlist users.txt --password 'Spring2026!' \
    --target https://portal.example.com/login --success-code 302
```

---

## Built-in targets

| Target | Description |
|---|---|
| `o365` | Microsoft OAuth2 ROPC flow against `login.microsoftonline.com`. Detects MFA-required (creds valid). |
| `owa` | Exchange OWA `/owa/auth.owa` form POST. |
| `adfs` | ADFS `idpinitiatedsignon.aspx` with `__VIEWSTATE` token handling. |
| `citrix` | StoreFront PostCredentialsAuth or NetScaler Gateway `/cgi/login` (auto-detect). |
| `globalprotect` | Palo Alto GlobalProtect portal `/global-protect/login.esp`. |
| _(URL)_ | Any URL — generic POST with `username`/`password` form fields. |

---

## Opsec features

| Flag | Description |
|---|---|
| `--proxy URL` | Route all requests through HTTP/SOCKS proxy (e.g. `socks5h://127.0.0.1:9050` for Tor). |
| `--user-agents PATH\|STRING` | Rotate user-agents from a file (one per line) or use a literal UA. Defaults to a pool of recent browser UAs. |
| `--xff-rotate` | Attach a random public IPv4 `X-Forwarded-For` header to every request. Useful when the target's WAF / SIEM correlates by client IP and you've already broken egress IP via `--proxy`. |
| `--header KEY:VALUE` | Add a custom header on every request. Repeatable. Example: `--header 'X-Forwarded-Host: portal.acme.com' --header 'X-Original-URL: /admin'`. |
| `--insecure` | Disable TLS verification for self-signed lab targets. |
| `--delay` / `--jitter` | Base + random sleep between attempts. |
| `--lockout-threshold` | Skip account after N lockout responses (default 3). |
| `--max-attempts` | Hard cap on total attempts (time-boxed engagements). |
| `--resume` | Skip pairs already attempted (state in `.spray_state.json`). |

State is persisted automatically on `Ctrl+C` / `SIGTERM` so you can stop and resume cleanly.

---

## Output

- `valid_creds.txt` — newline-separated `username:password` for hits.
- `.spray_log.jsonl` — JSONL log: timestamp, username, password, status, notes, engagement_id.
- `.spray_state.json` — resume state.

---

## Engagement tagging

Tag every log entry with the engagement identifier so deliverables are
auto-groupable:

```bash
python spray.py --engagement-id ACME-2026-Q2 ...
# .spray_log.jsonl rows include: "engagement_id": "ACME-2026-Q2"
```

---

## Docker

```bash
# From the tools/ root:
docker compose run --rm spray \
    --userlist /app/data/users.txt \
    --passlist /app/data/passes.txt \
    --target o365 \
    --engagement-id ACME-2026-Q2 \
    --output /app/data/valid.txt
```

Mount your wordlists under `./data/` and read from `/app/data/` inside the
container.

---

## Tests

```bash
pip install pytest
python -m pytest tests/
```
