---
layout: training-page
title: "Red Team Engagement Infrastructure — Red Team Academy"
module: "C2 Frameworks"
tags:
  - infrastructure
  - c2
  - redirectors
  - opsec
  - architecture
  - deployment
page_key: "c2-frameworks-engagement-infrastructure"
render_with_liquid: false
---

# Red Team Engagement Infrastructure

This page is the master blueprint for the infrastructure you stand up before a red team engagement starts. Every other page in this module — team server buildout, custom C2, phishing, redirectors, implants — plugs into the topology described here. Read this first.

The goal is a disposable, compartmentalised, burnable environment where every component does one job, nothing touches your real identity, and you can lose any single node without losing the engagement.

---

## Design Principles

1. **Compartmentalisation.** Every function — phishing, payload hosting, short-haul C2, long-haul C2, exfil — lives on a separate VPS behind a separate domain with separate credentials. A burned phishing server does not expose the C2.
2. **Disposability.** All servers are provisioned from scripts and configuration. If a node is burned, you destroy it, spin up a replacement from the same scripts under a new domain, and keep operating.
3. **Redirection.** Operators never connect directly to team servers. Redirectors (Nginx, Apache, socat, or CDN-fronted) sit in front of every callback. Defenders block the redirector, not your C2.
4. **Legitimacy.** Domains are categorised, aged, and TLS-certified before use. Expired drop domains from domain brokers are cheaper than building reputation from scratch.
5. **Isolation of operator traffic.** Operators connect to team servers over a dedicated VPN (WireGuard). No operator ever touches a redirector directly. Logs never show operator IPs.
6. **Tiered callback cadence.** Fast beacons for interactive work, slow beacons for persistence. Losing the fast tier does not lose the target — see [C2 Tiered Architecture](/c2-frameworks/c2-tiered-architecture/).
7. **Clean logs.** Every component logs to a central syslog. Every action is attributable to an operator. Post-engagement reporting depends on this.

---

## Full Topology

```
                                    ┌──────────────────┐
                                    │   Operators      │
                                    │  (laptops)       │
                                    └─────────┬────────┘
                                              │ WireGuard
                                              │ 51820/udp
                                              ▼
                                    ┌──────────────────┐
                                    │   Jump Host      │
                                    │  jumpbox.op.lan  │
                                    │  (bastion VPN)   │
                                    └─────────┬────────┘
                                              │
              ┌───────────────────────────────┼───────────────────────────────┐
              │                               │                               │
              ▼                               ▼                               ▼
   ┌──────────────────┐           ┌──────────────────┐           ┌──────────────────┐
   │  Team Server A   │           │  Team Server B   │           │  Phishing Server │
   │  Short-haul C2   │           │  Long-haul C2    │           │  GoPhish + SMTP  │
   │  Sliver / Mythic │           │  Custom HTTPS    │           │  Evilginx        │
   │  10.8.0.10       │           │  10.8.0.11       │           │  10.8.0.12       │
   └─────────┬────────┘           └─────────┬────────┘           └─────────┬────────┘
             │                              │                              │
             │ HTTPS (443)                  │ HTTPS (443)                  │ SMTP (25/587)
             │ WireGuard tunnel             │ WireGuard tunnel             │ HTTPS (443)
             ▼                              ▼                              ▼
   ┌──────────────────┐           ┌──────────────────┐           ┌──────────────────┐
   │  Redirector 1    │           │  Redirector 2    │           │  Redirector 3    │
   │  nginx reverse   │           │  nginx reverse   │           │  nginx mail+web  │
   │  cdn.example.com │           │  api.example.io  │           │  mail.example.co │
   └─────────┬────────┘           └─────────┬────────┘           └─────────┬────────┘
             │                              │                              │
             │                              │                              │
             ▼                              ▼                              ▼
   ┌──────────────────────────────────────────────────────────────────────────────┐
   │                          Target Environment                                   │
   │   [Beaconing implants on compromised hosts — HTTPS callback to redirectors]   │
   └──────────────────────────────────────────────────────────────────────────────┘
```

Everything above the redirector tier is invisible to the target. Everything below is burnable. The defender sees only redirector IPs and domain names.

---

## The Nodes

### Jump Host / Bastion
A single hardened box running WireGuard. Operators VPN in here. From here they SSH (key-only, no password) to team servers on the private network. The jump host never touches the internet for anything except WireGuard and updates.

**Provision:** 1 vCPU / 1 GB RAM VPS. Debian 12 minimal. UFW: only allow 51820/udp inbound from the internet, 22/tcp only from the WireGuard subnet.

### Team Server A — Short-Haul C2
Interactive C2 for active operations. Fast beacons (30s–2m). Runs Sliver, Mythic, or your custom server. Exposes listeners on localhost only; the redirector forwards traffic into it over the WireGuard mesh.

**Provision:** 2 vCPU / 4 GB RAM. Debian 12. No public ports.

### Team Server B — Long-Haul C2
Backup persistence channel. Slow beacons (6h–24h). Different framework from Team Server A — never use the same C2 family on both tiers, a detection that burns one should not burn both.

**Provision:** 1 vCPU / 2 GB RAM. Debian 12. No public ports.

### Phishing Server
SMTP relay + landing pages + credential harvester. Usually GoPhish for campaign tracking, Postfix for outbound, and either a static HTML clone or Evilginx for AiTM. DKIM, SPF, and DMARC configured on the sending domain.

**Provision:** 2 vCPU / 2 GB RAM. Debian 12. Ports 25/587/465/80/443 behind a redirector.

### Redirectors
Nginx boxes that terminate TLS and proxy traffic to team servers over the WireGuard mesh. Cheap, disposable, multiple per team server. Each redirector has its own domain, its own cert, its own categorisation. If a redirector gets blocked, spin up a new one in 10 minutes.

**Provision:** 1 vCPU / 1 GB RAM. Debian 12. Ports 80/443 open. WireGuard peer of the team server it fronts.

### Payload Staging
A dedicated host for serving first-stage payloads during initial access. Short-lived — usually up for a single campaign, down the moment the target clicks. Keeps stager URLs out of your long-lived C2 logs.

**Provision:** 1 vCPU / 1 GB RAM. Debian 12. Teardown after use.

### Log Aggregator
Central syslog / Loki / Graylog. Every node ships operator commands, beacon traffic, redirector access logs. This is your post-engagement evidence bundle. Put it on its own VPS, not shared with any operational node.

**Provision:** 2 vCPU / 4 GB RAM. Debian 12. WireGuard only.

---

## Domain Strategy

- **Buy aged domains** from `expireddomains.net`, `domcop`, or a broker. Look for 2+ years of prior ownership, a clean Wayback history, and at least one category on the major web filter databases (Symantec, McAfee, Palo Alto). Never use a freshly registered domain for anything that touches the target — it will be flagged.
- **One domain per function.** Phishing sender, phishing landing, short-haul C2, long-haul C2, payload hosting — each gets its own domain. If one gets burned, the others survive.
- **Match the pretext.** The sender domain should look like the pretext — `it-support-<company>.com`, `secureportal-<company>.net`. The C2 domain should look like infrastructure — `cdn-static-assets.com`, `api-telemetry.net`.
- **Categorise before use.** Submit each domain to the major web filter vendors for categorisation (Business/Finance, Computing/Internet, Health — never Uncategorised). Categorisation takes 24–72 hours; build this into the pre-engagement timeline.
- **TLS for everything.** Let's Encrypt for all redirectors. Modern EDR flags plaintext HTTP callbacks. A self-signed cert is worse than plaintext.

---

## Build Timeline

A realistic engagement infrastructure timeline from signed contract to go-live is 10–14 days.

| Day   | Activity                                                                 |
|-------|--------------------------------------------------------------------------|
| -14   | Purchase aged domains (5–10 of them), submit for categorisation         |
| -12   | Provision VPS fleet: jump host, 2 team servers, 3 redirectors, phishing |
| -11   | Deploy WireGuard mesh across all nodes                                  |
| -10   | Install C2 frameworks on team servers; configure listeners              |
| -9    | Deploy Nginx on redirectors; issue Let's Encrypt certs                  |
| -8    | Wire redirectors to team servers; smoke-test callback                   |
| -7    | Stand up phishing server; configure Postfix + DKIM + SPF + DMARC        |
| -6    | Build and test payloads against the agreed-on EDR stack                 |
| -5    | Stage payloads on the payload host                                      |
| -4    | Dry-run full attack chain from phishing email to C2 session             |
| -3    | Log aggregation live; operators confirm actions are captured            |
| -2    | Final OPSEC review; rotate any test-phase identifiers                   |
| -1    | Freeze infrastructure — no more changes                                 |
| 0     | Engagement begins                                                       |

---

## Automated Build-Out

The scripts under `scripts/rta-infra/` automate every step of this buildout. See the following pages for the details:

- [Team Server Build-Out](/c2-frameworks/teamserver-buildout/) — automated team server provisioning and hardening.
- [Custom HTTPS C2 Server](/c2-frameworks/custom-c2-server/) — full Python C2 with encrypted tasking and a working listener.
- [Custom Go Implant](/tool-dev/custom-go-implant/) — compiled implant with sleep obfuscation, string encryption, and direct syscall stubs.
- [Phishing Infrastructure](/c2-frameworks/phishing-infrastructure/) — GoPhish + Postfix + DKIM deployment.
- [Nginx HTTPS Redirectors](/c2-frameworks/redirectors/) — production redirector configs (existing page).

The top-level wrapper is `scripts/rta-infra/deploy-all.sh`, which takes a YAML inventory of VPS IPs and roles, pushes WireGuard keys, installs the right software on each node, and smoke-tests the full chain end-to-end.

---

## Teardown

At the end of the engagement:

1. Export all logs from the log aggregator to encrypted offline storage.
2. Wipe shells: `sessions -k`, `exit`, disconnect all implants.
3. Destroy every VPS (actually destroy, not just stop — snapshots leak data).
4. Revoke the Let's Encrypt certificates.
5. Park the domains (do not release them — they can be re-used in the next engagement after a cool-down).
6. Rotate WireGuard keys.
7. Retain only the logs and the report.

The golden rule: nothing from engagement N should be reusable as-is in engagement N+1. Fresh domains, fresh keys, fresh VPS, fresh payloads.

---

## Resources

- Red Team Infrastructure Wiki — `github.com/bluscreenofjeff/Red-Team-Infrastructure-Wiki`
- Cobalt Strike "Safe Redirector" — `blog.cobaltstrike.com/2014/01/14/cloud-based-redirectors-for-distributed-hacking/`
- Raphael Mudge's tiered infra talk — `vimeo.com/117233588`
- Byt3bl33d3r — `byt3bl33d3r.github.io/red-team-infrastructure-automation.html`
- Terraform red team infra — `github.com/rmikehodges/DeadCanary`
- Expired domain hunting — `expireddomains.net`, `domcop.com`
- Scripts on this site: `jekyll-site/scripts/rta-infra/`
- Related: [C2 Tiered Architecture](/c2-frameworks/c2-tiered-architecture/), [C2 Redirectors](/c2-frameworks/redirectors/), [C2 OPSEC](/c2-frameworks/c2-opsec/)
