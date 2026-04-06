---
layout: training-page
title: "Maltego OSINT — Red Team Academy"
module: "Reconnaissance"
tags:
  - maltego
  - osint
  - dark-web
  - telegram
  - recon
page_key: "recon-maltego-osint"
render_with_liquid: false
---

# Maltego OSINT

Maltego is a graphical link analysis platform that visualizes relationships between entities — domains, IPs, people, email addresses, social accounts, and more. Custom transforms extend Maltego to query any data source, including dark web search engines, Telegram, and Tor-hosted sites. This page covers Maltego fundamentals, the HermitPurple custom transform set for dark web OSINT, and building effective investigation graphs.

## Maltego Fundamentals

```
# Installation:
# Download from: maltego.com/downloads/
# Community (free): limited transforms, 12 entities per graph
# Pro: full transforms, unlimited entities

# Key concepts:
# Entity    — a data point (Domain, IP, EmailAddress, Person, etc.)
# Transform  — a function that takes one entity and returns related entities
# Graph     — visual canvas showing entities and connections
# Machine   — automated sequence of transforms

# Entity types relevant to red teams:
# maltego.Domain        → domain names
# maltego.DNSName       → DNS records
# maltego.IPv4Address   → IP addresses
# maltego.EmailAddress  → email addresses
# maltego.Person        → people (name, photo)
# maltego.Phrase        → free-form text (useful for crypto wallets, etc.)
# maltego.URL           → web URLs
```

## HermitPurple — Dark Web Transforms

HermitPurple-Maltegoce provides custom Maltego transforms for dark web intelligence gathering, including Ahmia search, Tor domain extraction, Telegram group discovery, and reverse image search.

### Install HermitPurple

```
git clone https://github.com/CyberSecurityUP/HermitPurple-Maltegoce
cd HermitPurple-Maltegoce
pip3 install -r requirements.txt

# Start the local transform server:
python3 project.py

# Then in Maltego: add local transform server pointing to localhost
# Settings → Transform servers → Add → http://localhost:8080/
```

### AhmiaDomainExtractor

Takes a search term (Phrase entity) and queries Ahmia (Tor search engine) to extract .onion domains matching the query. Useful for discovering hidden services related to a target organization or keyword.

```
# Usage in Maltego:
# 1. Add a Phrase entity with your search term (e.g., "target company name")
# 2. Run transform: AhmiaDomainExtractor
# 3. Returns: maltego.Domain entities for each discovered .onion domain

# What it does:
# → Sends HTTP request to https://ahmia.fi/search/?q=SEARCH_TERM
# → Parses the results page for .onion domain references
# → Returns unique domains as Maltego entities

# Equivalent manual query:
curl -s "https://ahmia.fi/search/?q=company+name" | \
  grep -oE "[a-z0-9]{16,56}\.onion" | sort -u
```

### ExtractDataDomainTor

Takes a .onion domain and extracts emails, cryptocurrency wallet addresses (BTC, ETH, Monero, ZCash), and other contact information. Routes requests through Tor (SOCKS5 127.0.0.1:9050).

```
# Requires: Tor service running (sudo systemctl start tor)

# Usage in Maltego:
# 1. Add a Domain entity containing a .onion address
# 2. Run transform: ExtractDataDomainTor
# 3. Returns:
#    - maltego.EmailAddress entities for found emails
#    - maltego.Phrase entities for crypto wallet addresses

# Crypto wallet patterns it detects:
# Ethereum: 0x + 40 hex chars
# Bitcoin (P2PKH): starts with 1 or 3
# Bitcoin (Bech32): starts with bc1
# Monero: starts with 4, 95 chars
# ZCash: starts with t1

# Manual equivalent via Tor:
proxychains4 curl -s http://TARGET.onion | \
  grep -oE "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-z]{2,}" | sort -u
```

### ExtractDataDomain

Same as ExtractDataDomainTor but for clearnet domains — extracts emails and crypto wallets from regular HTTP/HTTPS sites.

```
# Usage in Maltego:
# 1. Add a Domain entity (e.g., targetcompany.com)
# 2. Run transform: ExtractDataDomain
# 3. Returns: email addresses and crypto wallets found on the domain

# Useful for:
# - Finding staff email addresses for phishing
# - Identifying corporate crypto wallets
# - Extracting contact information
```

### TelegramGroupLister

Searches for Telegram groups matching a filter phrase using TelegramExplorer. Useful for finding threat actor channels, data leak groups, or groups related to a target organization.

```
# Requires: TelegramExplorer configured (telegram.config)
# Installation: pip3 install TEx
# Configuration: https://telegramexplorer.readthedocs.io/

# Usage in Maltego:
# 1. Add a Phrase entity with your filter keyword
# 2. Run transform: TelegramGroupLister
# 3. Returns: Telegram group IDs and usernames matching the filter

# Manual equivalent:
# Search on https://tgstat.com or https://telegago.com

# Use cases for red team:
# - Find data leak channels selling access to a target
# - Monitor threat actor groups discussing a target company
# - Identify initial access broker advertisements
```

### ReverseImageSearch

Takes an image URL (or photo entity) and performs reverse image search to find where else it appears. Useful for tracking personas, finding social media profiles from profile photos, and OSINT on individuals.

## Maltego Investigation Workflows

### Infrastructure Mapping

```
# Start with a Domain entity → expand via built-in transforms:

# DNS transforms:
# Domain → DNS Name (all DNS records)
# DNS Name → IP Address
# IP Address → Autonomous System (BGP/AS info)
# IP Address → Location

# Certificate transparency:
# Domain → SSL Certificate Subject Alt Names → More Domains
# (discovers subdomains via crt.sh)

# Reverse IP:
# IP Address → Domains on IP (Bing search pivot)

# WHOIS:
# Domain → Registrant email → More domains (same registrant)
```

### Person OSINT

```
# Start with a Person or Email entity:

# Email → Have I Been Pwned breach data
# Email → Gravatar (profile photo)
# Email → Associated domains (registration data)

# Person → LinkedIn profile
# Person → Twitter/social accounts
# Photo → Reverse image search (TinEye, Google Images)

# Phone number transforms:
# Phone → Location (country code)
# Phone → Carrier
```

### Dark Web Investigation Graph

```
# Workflow for dark web target research:

# 1. Start: Phrase entity = "target company name"
# 2. Run: AhmiaDomainExtractor → get .onion domains
# 3. For each .onion domain:
#    → ExtractDataDomainTor → get emails + wallets
#    → Manual screenshot via gowitness
# 4. Email entities → reverse WHOIS → more domains
# 5. Wallet addresses → blockchain explorer → transaction history

# Visualizing the attack surface:
# Color coding: red = confirmed threat actor, orange = suspected, green = target infra
# Layout: organic/hierarchical to show relationships clearly
```

## Custom Transform Development

```
# Build your own Maltego transforms with maltego-trx:
pip3 install maltego-trx

# Transform template:
from maltego_trx.maltego import MaltegoMsg, MaltegoTransform
from maltego_trx.transform import DiscoverableTransform

class MyTransform(DiscoverableTransform):
    @classmethod
    def create_entities(cls, request: MaltegoMsg, response: MaltegoTransform):
        input_value = request.Value  # The input entity's value

        # Query your data source
        results = query_api(input_value)

        # Add result entities
        for result in results:
            entity = response.addEntity('maltego.Domain', result)
            entity.addProperty('source', 'Source', value='MyAPI')

# Register and serve:
from maltego_trx.registry import Registry
from maltego_trx.server import serve_transform_classes
Registry.register_transform(MyTransform)
serve_transform_classes(9001)  # Serve on port 9001
```

## Transform Sources for Red Teams

```
# Free / community transforms:
# Shodan: shodan.io → Maltego Shodan transforms
# VirusTotal: virustotal.com → Maltego VT transforms
# HaveIBeenPwned: hibp transforms
# URLScan.io: urlscan transforms
# Censys: censys.io → Maltego transforms

# Built into Maltego Community:
# DNS lookups (nslookup-based)
# Reverse DNS
# WHOIS records
# IP geolocation
# Social media search (limited)

# Install transform packs:
# Maltego → Transform Hub → search by category
# Categories: DNS, IP, Social Media, OSINT, Threat Intel
```

## Resources

- HermitPurple-Maltegoce — `github.com/CyberSecurityUP/HermitPurple-Maltegoce`
- Maltego — `maltego.com`
- maltego-trx (Python SDK) — `github.com/paterva/maltego-trx`
- TelegramExplorer — `telegramexplorer.readthedocs.io`
- Ahmia (Tor search) — `ahmia.fi`
- Related: [Dark Web OSINT](/recon/dark-web-osint/)
- Related: [Passive Recon (OSINT)](/recon/passive-recon/)
