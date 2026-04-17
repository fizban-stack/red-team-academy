---
layout: training-page
title: "Anonymous Infrastructure Acquisition — Red Team Academy"
module: "Infrastructure Engineering"
tags:
  - infrastructure
  - opsec
  - anonymity
  - vps
  - domains
page_key: "infrastructure-anonymous-infra"
render_with_liquid: false
---

# Anonymous Infrastructure Acquisition

Attribution of red team infrastructure begins at registration. Real names in WHOIS records, traceable payment methods, and reused SSH keys can all connect infrastructure to an operator or firm — a problem during sophisticated engagements where defenders may conduct external attribution.

## VPS Providers That Accept Cryptocurrency

### Tier 1: Full Anonymous VPS (Crypto + No KYC)

| Provider | Accepts | Notes |
|----------|---------|-------|
| IncogNet | Monero, Bitcoin, others | Strong privacy policy, offshore jurisdiction |
| 1984 Hosting | Bitcoin | Iceland-based, privacy-focused |
| Flokinet | Monero, Bitcoin | Iceland/Romania, no DMCA cooperation |
| PRQ.se | Bitcoin | Sweden, historical privacy provider |
| BitLaunch | Bitcoin, Ethereum | Reseller of DigitalOcean/Vultr VMs with crypto payment |

### Tier 2: Crypto-Accepting with Real Infrastructure

| Provider | Accepts | Notes |
|----------|---------|-------|
| Vultr | Bitcoin | Major provider; still requires email |
| Linode/Akamai | Bitcoin | Good IP reputation, requires email |
| OVH | Bitcoin | Large European provider |
| Hetzner | Bitcoin | Good price/performance, European |

```
Choosing between tiers:
  Tier 1: Use for C2 servers — maximum anonymity, IP less likely pre-blocked
  Tier 2: Use for redirectors — better IP reputation in corporate allow lists,
          slightly less anonymous but IPs not associated with "bulletproof" hosting

Note: BitLaunch uses DigitalOcean/Vultr infrastructure under the hood,
so IP ranges are "clean" (no bulletproof association) while payment is crypto.
```

### VPS Selection Criteria

```
Evaluate:
  [ ] Accepts Monero or Bitcoin (not just PayPal)
  [ ] No mandatory KYC (no photo ID requirement)
  [ ] Privacy policy: does not log or retain payment records
  [ ] Jurisdiction: outside US/UK/EU cooperative surveillance networks
  [ ] IP reputation: not pre-listed in commercial threat intel databases
  [ ] Abuse policy: reasonable response time (3+ days before action)
  [ ] SSH key authentication supported (not password-only)
  [ ] Ability to provision via API (Terraform compatible)
```

## Domain Registrars with Privacy

### Anonymous-Friendly Registrars

| Registrar | Privacy | Accepts Crypto | Notes |
|-----------|---------|----------------|-------|
| Njalla | Full — Njalla owns the domain | Bitcoin, Monero | Domain registered in Njalla's name; they lease to you |
| Porkbun | WHOIS privacy included free | No | US registrar; privacy is standard |
| Namecheap | WHOIS Guard free | Bitcoin | US-based; US jurisdiction |
| Epik | Privacy included | Bitcoin, XMR | Privacy-focused, offshore options |
| OrangeWebsite | Privacy | Bitcoin, Monero | Iceland registrar |

### Njalla — Maximum Anonymity

```
Njalla model:
  - Njalla registers the domain in their name
  - You manage DNS through their panel
  - Legal requests go to Njalla (Sweden), not operator
  - Requires no personal information from customer
  - Accepts Monero, Bitcoin, credit card through privacy proxy

Limitation:
  - You do not technically "own" the domain — Njalla does
  - In theory, Njalla could transfer domain against your wishes
  - Acceptable risk for engagement infrastructure

Setup:
  1. Create account at njal.la with throwaway email (Proton or SimpleLogin)
  2. Pay for domain with Monero via XMR payment
  3. Register domain through their interface
  4. Configure DNS records in Njalla panel
  5. Use domain for engagement duration, do not renew after
```

### WHOIS Privacy Verification

```bash
# Always verify WHOIS privacy is active before using domain
whois yourdomain.com | grep -E "Registrant|Organization|Email|Name|Phone"

# Expected output with active privacy:
# Registrant Name: Privacy Service
# Registrant Organization: Domains By Proxy, LLC
# Registrant Email: ****@domainsbyproxy.com

# Red flags (privacy NOT active):
# Registrant Name: John Smith
# Registrant Email: john@realcompany.com

# Check ARIN WHOIS for IP attribution
whois [VPS_IP] | grep -E "OrgName|netname|country|abuse"
```

## Payment Methods

### Monero (XMR) — Preferred for On-Chain Privacy

```
Why Monero over Bitcoin:
  - Monero uses: RingCT (amounts hidden), Stealth Addresses (receiver hidden),
    Ring Signatures (sender hidden)
  - Bitcoin: transparent ledger — all transactions visible to anyone
  - Bitcoin forensics firms (Chainalysis, CipherTrace) can trace BTC transactions
  - Monero is opaque by default — no tracing possible even with chain analysis

Acquiring Monero anonymously:
  1. LocalMonero.co — peer-to-peer XMR exchange, cash or in-person trades
  2. Bisq — decentralized exchange, no KYC, XMR/BTC pairs
  3. ATM: some crypto ATMs accept cash and return XMR directly (rare)
  4. Mining: solo mine XMR on spare CPU hardware (RandomX algorithm)

Using Monero for payments:
  1. Install Monero GUI wallet or use CLI (monero-wallet-cli)
  2. Create new wallet per engagement (never reuse wallets)
  3. Send XMR directly from wallet to VPS/registrar payment address
  4. Wallet creates new receive address for each transaction (stealth)

# Monero CLI wallet — generate new wallet
monero-wallet-cli --generate-new-wallet engagementX-wallet
# Follow prompts — save seed phrase in encrypted notes
```

### Prepaid Visa / Gift Cards for Fiat Payments

```
When crypto not accepted:
  - Purchase prepaid Visa gift card with cash from retail store
  - Do not activate with real personal information (use pretext name)
  - Activation via throwaway phone number (VoIP or prepaid SIM)
  - Use for: domain registration, VPS signup, SSL certificates

Purchase process:
  1. Buy card with cash at grocery store, pharmacy, or convenience store
  2. Activate online using throwaway personal information
  3. Use immediately — preloaded cards expire and some require real activation

Risk: Retail store camera footage shows purchaser
      Merchant may request zip code verification (use random valid zip)
```

## Operational Security During Signup

### Browsing Anonymity

```bash
# Option 1: Tor Browser for all registration activity
# Download: torproject.org
# Use Tor for:
#   - Email account creation
#   - VPS account registration
#   - Domain registration
#   - Any web-based infrastructure configuration

# Option 2: Mullvad VPN (paid with XMR, no account email required)
# Download: mullvad.net
# Payment: Enter account number directly, pay XMR
# No email required — account is just a number

# Option 3: VPN + Tor (belt and suspenders)
#   VPN first → Tor second
#   Protects against Tor exit node monitoring
#   VPN provider sees Tor traffic; Tor sees VPN IP

# DO NOT use:
#   - Your home IP address
#   - Your work IP address
#   - Your personal VPN (traceable to you)
#   - The same VPN account used for personal browsing
```

### Throwaway Email for Registration

```
Options:
  ProtonMail — end-to-end encrypted, created over Tor, no phone required
  SimpleLogin — email alias service, disposable addresses
  Guerrilla Mail — no registration, fully temporary
  Tempmail.com — disposable, no registration

ProtonMail over Tor:
  1. Open Tor Browser
  2. Navigate to proton.me
  3. Create account (may require CAPTCHA, no phone required)
  4. Use for: VPS registration, domain registration, Let's Encrypt

Email naming convention:
  - No personal name in email
  - Matches pretext company name if using business pretext
  - Example: support@[pretext-company].com (hosted at ProtonMail)
```

## SSH Access Patterns

### Ed25519 Keys Only

```bash
# Generate Ed25519 key for new engagement
ssh-keygen -t ed25519 -C "engagement-[ID]" -f ~/.ssh/engagement_[ID]_ed25519

# Public key to add to VPS at provisioning time
cat ~/.ssh/engagement_[ID]_ed25519.pub

# Never reuse keys between engagements (key fingerprint is traceable)
# Generate fresh keys for every new engagement

# SSH config for infrastructure management
# ~/.ssh/config
Host redir1
    HostName [REDIRECTOR1_IP]
    User root
    IdentityFile ~/.ssh/engagement_[ID]_ed25519
    Port 22
    ProxyJump jumper   # Route SSH through jump host for management

Host c2server
    HostName [C2_IP]
    User root
    IdentityFile ~/.ssh/engagement_[ID]_ed25519
    Port 22
    ProxyJump jumper

Host jumper
    HostName [JUMPBOX_IP]
    User ubuntu
    IdentityFile ~/.ssh/engagement_[ID]_ed25519
    Port 2222    # Non-standard port
```

### Non-Standard SSH Port

```bash
# Change SSH port on all infrastructure
sed -i 's/#Port 22/Port 2222/' /etc/ssh/sshd_config
systemctl restart sshd

# Verify new port
ss -tlnp | grep 2222

# Update UFW rules
ufw delete allow 22/tcp
ufw allow from [OPERATOR_VPN_IP] to any port 2222
```

### Port Knocking (Optional)

```bash
# Install knockd for port knocking on C2 management
apt install knockd

# /etc/knockd.conf
[options]
    UseSyslog
    logfile = /var/log/knockd.log

[openSSH]
    sequence    = 7000,8000,9000
    seq_timeout = 10
    tcpflags    = syn
    command     = /sbin/iptables -A INPUT -s %IP% -p tcp --dport 2222 -j ACCEPT

[closeSSH]
    sequence    = 9000,8000,7000
    seq_timeout = 10
    tcpflags    = syn
    command     = /sbin/iptables -D INPUT -s %IP% -p tcp --dport 2222 -j ACCEPT

# Knock sequence from operator machine:
knock [SERVER_IP] 7000 8000 9000 -d 100
ssh -p 2222 root@[SERVER_IP]
knock [SERVER_IP] 9000 8000 7000 -d 100  # Close port after done
```

## Avoiding Attribution

### Do Not Reuse SSH Keys

```
Each engagement: fresh Ed25519 key pair
Compromise of one engagement does not expose others

Defender attribution via SSH key:
  - Shodan scans SSH banners and host keys
  - If same host key appears on multiple IPs: correlation possible
  - Regenerate host keys on each fresh VPS:
    ssh-keygen -A   # Regenerates all host keys

# On fresh VPS provision:
# Delete default host keys, generate new ones
rm /etc/ssh/ssh_host_*
ssh-keygen -A
systemctl restart sshd
```

### Rotate IPs Between Engagements

```
Never reuse infrastructure between engagements:
  - Defenders check threat intel for previously observed C2 IPs
  - Historical Shodan data retains certificate fingerprints
  - Censys indexes TLS certificate history by IP

Teardown checklist between engagements:
  [ ] Destroy VPS instances (use provider's "destroy droplet" function)
  [ ] Do NOT just stop the instance — destroy completely
  [ ] Verify IP is released back to provider pool
  [ ] Delete all created API keys and tokens
  [ ] Delete throwaway email account (or abandon — ProtonMail has no personal info)
  [ ] Let domain expire or delete (do not reuse domains)
  [ ] Rotate local SSH keys
  [ ] Clear engagement-related browser history from throwaway profile
```

### Infrastructure Teardown Procedure

```bash
# Day of teardown:
# Step 1: Remove all implants from victim environment first
# (confirmed by engagement manager)

# Step 2: Archive engagement logs
tar czf engagement_[ID]_logs.tar.gz /var/log/apache2/ /var/log/nginx/
gpg --symmetric --cipher-algo AES256 engagement_[ID]_logs.tar.gz
# Store encrypted archive
rm -f engagement_[ID]_logs.tar.gz

# Step 3: Wipe VPS disk (some providers support this)
# OR: simply destroy the instance (provider wipes on destroy)

# Step 4: Via provider API — destroy droplet
curl -X DELETE "https://api.digitalocean.com/v2/droplets/[DROPLET_ID]" \
  -H "Authorization: Bearer [API_TOKEN]"

# Step 5: Verify IP is released (no longer responding)
ping -c 3 [FORMER_C2_IP]
# Expected: no response

# Step 6: Delete domain registrations
# Njalla: delete domain in panel
# Other registrar: delete or let expire

# Step 7: Revoke API tokens
# Provider dashboard → API → Revoke token

# Step 8: Delete throwaway accounts (or abandon ProtonMail)
```

## Domain Fronting Acquisition via Free Cloudflare

```bash
# Create throwaway Cloudflare account (no payment required for Workers free tier)

# Preparation:
#   - Open Tor Browser
#   - Create ProtonMail account (over Tor)
#   - Use ProtonMail email for Cloudflare account
#   - No credit card required for free tier

# Cloudflare Workers free tier limits:
#   - 100,000 requests/day
#   - 10ms CPU time per request
#   - Sufficient for C2 beacon traffic (beacons are small, infrequent)

# Worker deployment (via Wrangler CLI)
npm install -g wrangler
wrangler login   # Opens browser to Cloudflare auth
wrangler init my-worker
wrangler deploy

# Teardown:
#   - Delete worker in Cloudflare dashboard
#   - Abandon throwaway Cloudflare account
#   - No payment info to trace
```

## OPSEC Audit Before Operations Begin

```
Pre-engagement infrastructure OPSEC checklist:

Identity:
  [ ] VPS registered under throwaway identity (not real name)
  [ ] Domain registered under throwaway identity or via Njalla
  [ ] All accounts created over Tor or Mullvad VPN
  [ ] Throwaway email used (ProtonMail or similar)
  [ ] Payment via Monero or untraceable prepaid card

SSH and Access:
  [ ] Fresh Ed25519 key pair generated for this engagement
  [ ] Default VPS host keys regenerated
  [ ] SSH port changed from 22 to non-standard
  [ ] UFW configured: only operator VPN IP can SSH to infrastructure
  [ ] No SSH password authentication (key-only)
  [ ] Management access only from operator VPN

Operational:
  [ ] C2 server IP not exposed in any victim-facing connection
  [ ] Redirector → C2 firewall rules verified
  [ ] No C2 IP in Apache/Nginx config files accessible to web
  [ ] Domain submitted for categorization and verified
  [ ] TLS certificates obtained and valid
  [ ] Beacon tested through full tier chain before engagement start
  [ ] Teardown procedure documented and rehearsed
```
