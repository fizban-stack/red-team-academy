---
layout: training-page
title: "Dark Web OSINT — Red Team Academy"
module: "Reconnaissance"
tags:
  - dark-web
  - osint
  - tor
  - onion
  - capncook
  - threat-intelligence
page_key: "recon-dark-web-osint"
render_with_liquid: false
---

# Dark Web OSINT

The dark web (Tor .onion network) hosts a wealth of intelligence relevant to red teams and threat researchers: data breach dumps, threat actor infrastructure, vulnerability marketplaces, and exposed credentials. This page covers tooling and methodology for conducting dark web OSINT using Tor as an anonymizing layer.

## Setup: Tor Routing

```
# Install Tor:
sudo apt install tor

# Start the Tor service:
sudo systemctl start tor
sudo systemctl enable tor

# Tor SOCKS5 proxy runs on 127.0.0.1:9050 by default

# Install proxychains4 to route tools through Tor:
sudo apt install proxychains4

# Edit proxychains config (verify socks5 entry):
# /etc/proxychains4.conf — should contain:
# socks5 127.0.0.1 9050

# Test connectivity through Tor:
proxychains4 curl -s https://check.torproject.org/api/ip
```

## Dark Web Search Engines

These .onion search engines index hidden services. Use them to discover infrastructure, leaked data, and threat actor presence related to a target organization.

```
# Access dark web search engines via Tor Browser or proxychains + curl:
# Ahmia (clearnet-accessible Tor search):
# http://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion
# Also accessible at https://ahmia.fi (clearnet mirror)

# Torch:
# http://torchqsxkllrj2eqaitp5xvcgfeg3g5dr3hr2wnuvnj76bbxkxfiwxqd.onion

# Haystak:
# http://haystak5njsmn2hqkewecpaxetahtwhsbsa64jom2k22z5afxhnpxfid.onion

# DarkSearch (API-accessible):
# http://darkschn4iw2hxvpv2vy2uoxwkvs2padb56t3h4wqztre6upoc5qwgid.onion

# Tor66 (Tor-indexed search):
# http://tor66sewebgixwhcqfnp5inzp5x5uohhdy3kvtnyfxc2e5mxiuh34iid.onion

# Search syntax (Ahmia/Torch):
proxychains4 curl -s "https://ahmia.fi/search/?q=company+name+dump" | \
  grep -oE 'http[s]?://[^"]+' | head -20
```

## capNcook — Dark Web Recon Framework

capNcook is a Python Flask web application that provides a browser-based interface for dark web reconnaissance over Tor. It unifies multiple dark web search engines, performs WHOIS lookups on onion domains, captures screenshots, and runs directory fuzzing — all routed through Tor circuits.

### Install

```
# Dependencies:
sudo apt install tor whois proxychains4 chromium jq

# Python dependencies:
git clone https://github.com/hoodietramp/capNcook
cd capNcook
pip3 install -r requirements.txt

# External tools (for full functionality):
# gowitness — screenshot capture
go install github.com/sensepost/gowitness@latest

# FeroxBuster — directory enumeration
sudo apt install feroxbuster
```

### Running

```
# Start Tor service first:
sudo systemctl start tor

# Launch with Flask:
flask run
# or:
python3 app.py

# Access the web interface at http://127.0.0.1:5000
```

### Feature Modules

```
# capNcook interface modules:

# 1. SEARCH PAGE
#    - Enter keyword, select dark web search engine
#    - Indexes onion domains matching the keyword
#    - Unifies results from multiple Tor search engines

# 2. ONION CHECK
#    - Checks .onion domain status (active/inactive)
#    - Grabs site title, description, HTTP status code
#    - Filters live vs. dead onion services

# 3. RECON (TorWHOIS)
#    - Performs WHOIS lookups on onion domains
#    - Pulls registration info where available

# 4. HEADERS
#    - Captures HTTP response headers for .onion sites
#    - Takes screenshots via gowitness
#    - Headers reveal: X-Powered-By, Server, framework fingerprints

# 5. ENUMERATION (Dir Fuzzing)
#    - Runs FeroxBuster against onion domains
#    - Uses bundled wordlist.txt
#    - Finds subdirectories and files on hidden services
```

### Manual Tor-Routed Recon

```
# Check onion site status:
proxychains4 curl -sI http://TARGET.onion

# Grab headers from onion site:
proxychains4 curl -s -I http://TARGET.onion \
  | grep -E "Server:|X-Powered-By:|Content-Type:|Set-Cookie:"

# Directory brute force via Tor:
proxychains4 feroxbuster -u http://TARGET.onion \
  -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  -t 5 --timeout 30

# Screenshot onion site:
proxychains4 gowitness scan single --url http://TARGET.onion

# Crawl links from an onion page:
proxychains4 curl -s http://TARGET.onion \
  | grep -oE 'href="[^"]*"' | sed 's/href="//;s/"//'

# Download files via Tor (robust):
proxychains4 wget \
  --tries=0 --retry-connrefused \
  --continue --timeout=90 \
  --random-wait \
  http://TARGET.onion/file.zip
```

## OPSEC: Tor Circuit Management

```
# Rebuild Tor circuit (new identity/IP):
# In Tor Browser: "New Identity" button
# Via command line:
echo -e "AUTHENTICATE \"\"\r\nSIGNAL NEWNYM\r\nQUIT" | \
  nc 127.0.0.1 9051

# Check current Tor exit node:
proxychains4 curl -s https://check.torproject.org/api/ip | python3 -m json.tool

# Use stem (Python Tor control library) for circuit automation:
pip3 install stem

python3 -c "
from stem import Signal
from stem.control import Controller
with Controller.from_port(port=9051) as c:
    c.authenticate()
    c.signal(Signal.NEWNYM)
    print('New Tor circuit established')
"

# Monitor Tor circuit nodes:
# Tor identifies entry/guard, middle, and exit nodes
# capNcook's circuit rebuild feature handles this automatically
```

## High-Speed Tor Downloads (Multi-Threading)

```
# For downloading large files from .onion sites at speed,
# use the aria2-onion-downloader Docker image which load-balances
# across multiple Tor services:

docker run -d \
  -p 8080:80 \
  -p 6800:6800 \
  sn0b4ll/aria2-onion-downloader

# Creates up to 99 Tor services, fragments downloads across them
# Access aria2ng web UI at http://127.0.0.1:8080
```

## Searching for Target Intelligence

```
# Twitter/X search for dark web content about a target:
# (url:onion) "company name"
# "company name" AND (url:onion -filter:retweets)

# Google dorks to find onion site references:
# intext:.onion site:anonfiles.com
# "company name" intext:.onion

# Shodan filters for Tor-related infrastructure:
# ssl:".onion"
# ".onion"

# Search for data breach mentions:
# Ahmia: site:ahmia.fi "company name" password
# Or directly: proxychains4 curl "http://ahmia.fi/search/?q=company+breach"

# Pastebin/Ghostbin leak search:
# target OR dump OR combo OR password OR leak AND
# (url:pastebin.com OR url:ghostbin.co)
```

## Resources

- capNcook — `github.com/hoodietramp/capNcook`
- Ahmia (Tor search, clearnet) — `ahmia.fi`
- deepdarkCTI sources — `github.com/fastfire/deepdarkCTI`
- gowitness (screenshots) — `github.com/sensepost/gowitness`
- stem (Tor control library) — `stem.torproject.org`
- aria2-onion-downloader — `github.com/sn0b4ll/aria2-onion-downloader`
