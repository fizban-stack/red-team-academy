---
layout: training-page
title: "Red Team Infrastructure Engineering Overview — Red Team Academy"
module: "Infrastructure Engineering"
tags:
  - infrastructure
  - c2
  - opsec
  - redirectors
page_key: "infrastructure-overview"
render_with_liquid: false
---

# Red Team Infrastructure Engineering Overview

Red team infrastructure is the backbone of every successful engagement. Poorly designed infrastructure burns operators, exposes C2 servers, and leaves a trail that defenders and threat intelligence vendors will use to attribute and block future operations. Professional infrastructure engineering is as critical as the offensive tooling it supports.

## Why Infrastructure Matters

The failure chain when infrastructure is weak:

1. Operator sends Cobalt Strike beacon from VPS
2. Defender notices unusual outbound connection
3. Defender pivots on destination IP — Shodan/Censys shows same IP was a Cobalt Strike team server last month (certificate fingerprint match)
4. IP block issued, IOC shared to threat intel community
5. All future engagements using same IP or cert are pre-burned
6. Attribution: security firm identified from VPS registration data

Infrastructure prevents this chain at every step.

Key goals:
- **Attribution avoidance**: no direct path from beacon traffic to C2 server
- **Resilience**: single burned IP does not kill the engagement
- **Operational security**: investigators cannot pivot from observed traffic to operator identity
- **Compartmentalization**: burning one tier does not expose other tiers

## Infrastructure Tiers

```
OPERATOR (VPN to workstation)
         |
         | HTTPS management
         v
TIER 3 — C2 SERVER
  Cobalt Strike / Sliver / Havoc
  Never touches victim directly
  Only accessible via Tier 1 to Tier 2
         |
         | Internal only
         v
TIER 2 — INFRASTRUCTURE
  Mail servers, payload hosting, log aggregation
         |
         | Forwarded traffic only
         v
TIER 1 — REDIRECTORS
  Apache/Nginx/Caddy with mod_rewrite or proxy rules
  IP that appears in victim network logs
  Expendable — replaceable in minutes
         |
         | HTTPS beacon traffic
         v
VICTIM NETWORK
```

### Tier 1 — Redirectors

- First hop after victim's outbound connection
- Appears in all victim-side network logs
- Contains no sensitive data — disposable
- Filters traffic: only forwards valid C2 beacon requests
- Drops scanners, Shodan, researcher traffic → returns 200 OK with innocuous content

### Tier 2 — Infrastructure

- Payload hosting (HTTPS served files)
- Phishing mail servers
- Log collection and aggregation
- C2 profile configuration storage
- Connects only to Tier 3, never directly to victim

### Tier 3 — C2 Server

- Contains team server, listener configuration, operator sessions
- IP is NEVER disclosed in any victim-facing traffic
- Access: operator VPN to management port only
- Firewall: whitelist management from operator IPs only
- Never directly accessible from internet on C2 ports

## Segmentation Principle

The golden rule: NOTHING touches the C2 server directly.

Every connection passes through: Victim → Redirector → C2

```bash
# Firewall rules on C2 server (UFW example)

# Allow only from known redirector IPs
ufw allow from [REDIRECTOR1_IP] to any port 443
ufw allow from [REDIRECTOR2_IP] to any port 443

# Allow operator VPN management only
ufw allow from [OPERATOR_VPN_IP] to any port 50050   # Cobalt Strike team server
ufw allow from [OPERATOR_VPN_IP] to any port 22      # SSH management
ufw allow from [OPERATOR_VPN_IP] to any port 31337   # Sliver multiplayer

# Deny everything else
ufw default deny incoming
ufw enable

# Verify
ufw status numbered
```

## Domain Strategy

### Domain Aging

Aged domains (registered 1+ years ago with clean history) perform better across all reputation engines. New domains are automatically suspect in email security gateways, EDR cloud lookups, and proxy categorization.

```
Acquisition strategy:
  1. Check expireddomains.net or domcop.com for expired domains with age
  2. Filter for: age > 1 year, no blacklist hits, reasonable category
  3. Verify history: Wayback Machine (no spam/malware content)
  4. Verify current reputation: VirusTotal, Cisco Talos, IBM X-Force, URLscan.io
  5. Purchase with privacy protection via anonymous-friendly registrar

Domain vetting checklist:
  [ ] Age > 12 months
  [ ] VirusTotal: 0 detections
  [ ] Cisco Talos: "unknown" or clean category
  [ ] IBM X-Force: clean
  [ ] Wayback Machine: no spam/adult/malware content
  [ ] Not on Spamhaus ZEN or DBL blocklists
  [ ] WHOIS privacy available
```

### Domain Categories

| Category | Use Case | Notes |
|----------|---------|-------|
| Business services | C2 callbacks | Blends with business traffic |
| Technology / CDN | Payload hosting | Software update traffic pattern |
| News/Media | Phishing pretext | Lure-appropriate domain |
| Healthcare | Phishing pretext | Use only with explicit authorization |

### Typosquatting Patterns for Initial Access

```
Target domain: microsoft.com
Effective typosquats:
  microssoft.com           (doubled letter)
  m1crosoft.com            (digit substitution — 1 for i)
  microsoft-update.com     (hyphen + keyword)
  microsoftonline.net      (TLD swap — .net vs .com)
  micosoft.com             (transposition)
  microsoft365.net         (product name + TLD)
  
Target domain: targetcorp.com
Phishing-adjacent:
  targetcorp-it-helpdesk.com
  targetcorp-portal.net
  login-targetcorp.com
  targetcorp-remote.com
  targetcorpvpn.com
```

### Infrastructure vs. Phishing Domain Separation

```
CRITICAL OPERATIONAL RULE:
  Phishing domains (appear in emails):
    - Target-aware names (target company name, vendor names)
    - Disposable — will be burned when phish is reported
    - NEVER used for C2 callbacks
    - Example: microsoft-sharepoint-alert.com

  C2 domains (appear in beacon traffic only):
    - Generic, innocuous names (technology/business category)
    - Long-lived — protect these
    - NEVER appear in phishing emails
    - Example: updateservice-cdn.net

Cross-contamination is the biggest infrastructure mistake.
If phish domain and C2 domain are linked, burning the phish burns the C2.
```

## Cloud vs. VPS

| Factor | Cloud (AWS/Azure/GCP) | Anonymous VPS (IncogNet/BitLaunch) |
|--------|----------------------|--------------------------------|
| IP Reputation | High — rarely pre-blocked | Mixed — some ranges blocked |
| Attribution | Cloud provider only | VPS provider (anonymous if crypto) |
| Takedown risk | Fast — cloud abuse teams | Slower abuse response |
| Cost | Metered, can be expensive | Fixed monthly rate |
| Anonymity | Requires real billing | Accepts Monero/crypto |
| Best use | Redirectors (reputation) | C2 servers (anonymity) |

## Infrastructure Lifecycle

```
Phase 1: Acquisition
  [ ] Purchase VPS under throwaway identity (crypto payment or prepaid)
  [ ] Register domains with privacy via anonymous registrar
  [ ] Configure DNS (NS records, A records for redirectors)
  [ ] Obtain TLS certificates (Let's Encrypt — note: CT logged)

Phase 2: Setup
  [ ] Configure redirectors (Apache/Nginx/Caddy with filter rules)
  [ ] Deploy and harden C2 server
  [ ] Configure team server with malleable C2 profile or Sliver config
  [ ] Test full chain: beacon to redirector to C2 to operator console
  [ ] Configure firewall rules on all tiers
  [ ] Verify: no C2 IP leaks from redirector responses

Phase 3: Operation
  [ ] Monitor infrastructure health (listener status, redirector logs)
  [ ] Rotate redirector IPs if burned (keep C2 IP constant)
  [ ] Monitor CT logs for C2 domains
  [ ] Review redirector access logs for scanner and researcher activity

Phase 4: Teardown
  [ ] Remove all beacons and implants from victim environment
  [ ] Destroy VPS instances (provider wipe and destroy function)
  [ ] Archive engagement logs to encrypted storage
  [ ] Let expire or delete all domain registrations
  [ ] Rotate all SSH keys used during engagement
  [ ] Wipe operator workstation engagement partition
```

## Attribution Vectors

### IP Geolocation and ASN Patterns

Defenders observe: same ASN consistently used across engagements, same IP range reused, consistent geolocation.

Mitigations: vary VPS provider and geographic region per engagement, use CDN fronting (traffic appears from CDN IP), route through Tier 1 redirectors.

### TLS Certificate Fingerprinting (JA3/JA4)

```
C2 frameworks have distinctive TLS client fingerprints:
  Cobalt Strike: well-known JA3 hashes, widely blocklisted
  Metasploit: also fingerprinted extensively
  Sliver: varies by build configuration but has known patterns

Mitigations:
  - Malleable C2 profiles: change cipher suites, extension order
  - CDN routing: CDN terminates TLS — CDN JA3 appears, not yours
  - Custom Sliver/Havoc builds with modified TLS configuration
  
JA4 (updated fingerprint format, 2023):
  - More granular than JA3
  - Includes: TLS version, cipher count, extension types, ALPN
  - Harder to evade but malleable profiles still effective
```

### Certificate Transparency Monitoring

All Let's Encrypt certificates are logged to public CT logs. Defenders watch CT logs for target-adjacent domain certificates.

```bash
# Monitor your own domains in CT logs
curl -s "https://crt.sh/?q=%.yourdomain.com&output=json" | \
  jq -r '.[].name_value' | sort -u

# Check when cert was issued vs. when engagement started
# If cert appears before expected defender review — may be too soon

# RSS feed for your domain in crt.sh
# https://crt.sh/atom?q=%.yourdomain.com
```

## Tooling: Infrastructure as Code

### Terraform for Automated Deployment

```hcl
# terraform/redirectors.tf

provider "digitalocean" {
  token = var.do_token
}

variable "regions" {
  default = ["nyc3", "lon1", "sgp1"]
}

resource "digitalocean_droplet" "redirector" {
  count  = 2
  name   = "redir-${count.index}"
  region = var.regions[count.index]
  size   = "s-1vcpu-1gb"
  image  = "ubuntu-22-04-x64"
  
  ssh_keys  = [var.ssh_fingerprint]
  user_data = templatefile("setup_redirector.sh", {
    c2_ip   = var.c2_ip
    c2_port = 443
  })
  
  tags = ["redirector", "engagement-${var.engagement_id}"]
}

output "redirector_ips" {
  value = digitalocean_droplet.redirector[*].ipv4_address
}
```

### Ansible for Redirector Configuration

```yaml
# ansible/redirector.yml
- hosts: redirectors
  become: yes
  vars:
    c2_backend: "{{ hostvars['c2']['ansible_host'] }}"
  tasks:
    - name: Install Apache and modules
      apt:
        name: [apache2, libapache2-mod-rewrite, libapache2-mod-headers]
        state: present

    - name: Enable required modules
      apache2_module:
        name: "{{ item }}"
        state: present
      loop: [rewrite, proxy, proxy_http, ssl, headers]
      notify: Restart Apache

    - name: Deploy redirector vhost
      template:
        src: templates/redirector.conf.j2
        dest: /etc/apache2/sites-enabled/000-default.conf
      notify: Restart Apache

    - name: Remove default Apache page
      file:
        path: /var/www/html/index.html
        state: absent

    - name: Deploy cover page
      copy:
        content: "<html><body>Service Unavailable</body></html>"
        dest: /var/www/html/index.html

    - name: Harden server banner
      lineinfile:
        path: /etc/apache2/conf-enabled/security.conf
        regexp: '^ServerTokens'
        line: 'ServerTokens Prod'
      notify: Restart Apache

  handlers:
    - name: Restart Apache
      service:
        name: apache2
        state: restarted
```

## Recommended Reading and Tools

| Resource | Type | URL/Location |
|----------|------|-------------|
| Cobalt Strike Infrastructure Blog | Blog series | cobaltstrike.com/blog |
| Red Team Infrastructure Wiki | GitHub | github.com/bluscreenofjeff/Red-Team-Infrastructure-Wiki |
| Malleable C2 Profiles | GitHub | github.com/BC-SECURITY/Malleable-C2-Profiles |
| Terraform DigitalOcean Provider | Docs | registry.terraform.io/providers/digitalocean |
| Ansible | Docs | docs.ansible.com |
| Shodan CLI | Tool | shodan.io/cli |
| Certspotter | CT Monitoring | certspotter.com |
| Censys | Internet scanning | censys.io |
