---
layout: training-page
title: "SecLists Wordlist Selection Guide — Red Team Academy"
module: "Recon"
tags:
  - seclists
  - wordlists
  - fuzzing
  - directory-busting
  - subdomain-enum
  - api-discovery
page_key: "recon-wordlist-guide"
render_with_liquid: false
---

# SecLists Wordlist Selection Guide

## Overview

SecLists is the definitive wordlist collection for offensive security. Choosing the wrong list wastes time; choosing the right one finds vulnerabilities other testers miss. This guide maps every major SecLists directory to the right engagement scenario, with tool commands and size/speed tradeoffs.

Standard install paths:

```
# Kali / ParrotOS:
/usr/share/seclists/

# Manual clone:
git clone https://github.com/danielmiessler/SecLists /opt/seclists
export SL=/opt/seclists

# Quick alias (add to ~/.zshrc):
alias sl='/usr/share/seclists'
```

## Wordlist Selection Philosophy

```
# Speed vs Coverage tradeoff:
#   Fast scan (CTF / time-boxed test) → small/medium lists, common.txt
#   Thorough test (pentest, bug bounty) → large/raft lists + tech-specific
#   Stealth / rate-limited target     → small lists, slow rate, avoid huge lists
#
# Always know your stack before picking a list:
#   Detected PHP?   → add PHP-specific lists
#   IIS / .NET?     → add ASP.NET and IIS-specific lists
#   API endpoint?   → api-endpoints.txt, not directory lists
#
# Chain lists for best results:
#   Round 1: common.txt  (quick wins, ~4,750 words, < 1 min)
#   Round 2: raft-medium-words.txt  (~63k words)
#   Round 3: tech-specific + raft-large  (if time allows)
```

## Directory & Path Bruteforce

The `Discovery/Web-Content/` directory is the core of web recon. The RAFT lists are derived from real-world crawls and consistently outperform DirBuster-era lists for modern targets.

### List Hierarchy — Which to Use When

| List | Lines | Speed | Best For |
| --- | --- | --- | --- |
| common.txt | 4,750 | ~30s | Quick wins, CTF, initial scan |
| quickhits.txt | 2,567 | ~20s | Sensitive paths (.git, .env, backup files) |
| big.txt | 20,481 | ~2m | General purpose medium scan |
| raft-small-words.txt | 43,007 | ~5m | RAFT-crawled words, small set |
| raft-medium-words.txt | 63,088 | ~7m | Standard pentest wordlist (recommended) |
| raft-large-words.txt | 119,600 | ~15m | Comprehensive, bug bounty |
| DirBuster-2007_directory-list-2.3-medium.txt | 220,559 | ~30m | Old but broad, PHP/Apache era |
| combined_directories.txt | 128,627 | ~20m | Combined multi-source directory list |

### Feroxbuster (Recommended)

```
# Fast initial scan:
feroxbuster -u https://target.com \
  -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  -x php,html,txt,js,json \
  -t 50 -k --auto-tune

# Thorough scan with raft-medium:
feroxbuster -u https://target.com \
  -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt \
  -x php,html,txt,bak,old,zip,json,xml,config \
  -t 100 -k --depth 3 \
  --filter-status 404,400

# Recursive with tech-specific extensions:
feroxbuster -u https://target.com \
  -w /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt \
  -x asp,aspx,config,bak \
  --depth 4 --auto-tune -k

# Sensitive path scan first (quickhits):
feroxbuster -u https://target.com \
  -w /usr/share/seclists/Discovery/Web-Content/quickhits.txt \
  -k --no-recursion -t 30
```

### ffuf

```
# Directory bruteforce:
ffuf -u https://target.com/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt \
  -mc 200,301,302,307,401,403 \
  -fs 0 -t 50 -c

# File fuzzing with extensions:
ffuf -u https://target.com/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt \
  -mc 200,301 -t 50

# Virtual host / subdomain bruteforce:
ffuf -u https://target.com/ \
  -H "Host: FUZZ.target.com" \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -fs [baseline_size]
```

### gobuster

```
# Directory mode:
gobuster dir -u https://target.com \
  -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  -x php,html,txt -t 50 -k

# DNS mode (subdomain bruteforce):
gobuster dns -d target.com \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt \
  -t 50 --timeout 3s
```

### Tech-Specific Directory Lists

```
# /usr/share/seclists/Discovery/Web-Content/

# WordPress:
ffuf -u https://target.com/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/CMS/wordpress.fuzz.txt
# Also: wp-plugins.fuzz.txt, wp-themes.fuzz.txt

# Drupal:
ffuf -u https://target.com/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/CMS/Drupal.txt

# Joomla:
ffuf -u https://target.com/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/CMS/joomla-plugins.fuzz.txt

# SharePoint:
ffuf -u https://target.com/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/CMS/Sharepoint.txt

# ASP.NET / IIS:
ffuf -u https://target.com/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/Programming-Language-Specific/ASP.NET/ \
  -x aspx,ashx,asmx,config

# Tomcat / JBoss / Java:
ffuf -u https://target.com/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/Web-Servers/Apache-Tomcat.txt
# Also: JBoss.txt, Glassfish-Sun-Microsystems.txt
```

### Sensitive File Patterns

```
# quickhits.txt catches many of these, but manual additions:
.git/HEAD
.git/config
.env
.env.local
.env.production
.DS_Store
.htaccess
.htpasswd
config.php
config.yml
config.json
database.yml
settings.py
wp-config.php
application.properties
web.config
backup.zip
backup.tar.gz
backup.sql
db.sql
dump.sql
*.bak
*.old
*.orig
~
Thumbs.db

# Use extensions list for backup file discovery:
ffuf -u https://target.com/indexFUZZ \
  -w /usr/share/seclists/Fuzzing/extensions-Bo0oM.txt \
  -mc 200
```

## DNS / Subdomain Enumeration

The `Discovery/DNS/` directory contains the best subdomain wordlists. The top-1million lists are derived from certificate transparency, DNS records, and other passive sources.

### List Hierarchy

| List | Lines | Speed (shuffledns) | Best For |
| --- | --- | --- | --- |
| subdomains-top1million-5000.txt | 5,000 | ~10s | Quick scan, common subdomains |
| subdomains-top1million-20000.txt | 20,000 | ~30s | Standard subdomain enum |
| subdomains-top1million-110000.txt | 110,000 | ~3m | Thorough bug bounty scan |
| dns-Jhaddix.txt | 2,171,687 | ~45m | Comprehensive, all known subdomains |
| n0kovo_subdomains.txt | varies | varies | Alternative large list |
| fierce-hostlist.txt | varies | fast | Fierce tool default |

### Tool Commands

```
# amass — most comprehensive (passive + active):
amass enum -passive -d target.com -o subdomains.txt
amass enum -active -brute -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt \
  -d target.com -r 8.8.8.8,1.1.1.1

# subfinder — fast passive:
subfinder -d target.com -all -o subdomains.txt

# shuffledns — fastest active bruteforce (resolves + deduplicates):
shuffledns -d target.com \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt \
  -r resolvers.txt -o subdomains.txt
# Get resolvers: https://github.com/trickest/resolvers

# dnsx — resolve and filter live:
dnsx -l subdomains.txt -a -cname -resp -o live.txt

# puredns — high-speed with wildcard detection:
puredns bruteforce /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt \
  target.com -r resolvers.txt

# gobuster DNS:
gobuster dns -d target.com \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt \
  -t 50 -r 8.8.8.8

# fierce:
fierce --domain target.com \
  --wordlist /usr/share/seclists/Discovery/DNS/fierce-hostlist.txt
```

### DNS Service Enumeration

```
# /usr/share/seclists/Discovery/DNS/services-names.txt
# Useful for: discovering service-named subdomains (mail, vpn, jira, gitlab...)

# TLDs list for permutation:
# /usr/share/seclists/Discovery/DNS/tlds.txt

# Combined wordlists workflow:
cat /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt \
    /usr/share/seclists/Discovery/DNS/shubs-subdomains.txt \
    /usr/share/seclists/Discovery/DNS/deepmagic.com-prefixes-top50000.txt \
  | sort -u > combined_subs.txt
shuffledns -d target.com -w combined_subs.txt -r resolvers.txt
```

## API Endpoint Discovery

API enumeration requires different wordlists from web directory scanning. The `Discovery/Web-Content/api/` lists are built from real API paths seen in the wild.

### List Selection

| List | Lines | Best For |
| --- | --- | --- |
| api/api-endpoints.txt | 285 | Common REST API paths, fast detection |
| api/api-seen-in-wild.txt | 7,615 | Paths actually found in real APIs |
| api/actions.txt / objects.txt | ~200 each | REST resource/verb bruteforce |
| common-api-endpoints-mazen160.txt | 174 | mazen160's curated API paths |
| graphql.txt | varies | GraphQL endpoint paths |
| burp-parameter-names.txt | 6,453 | Parameter name fuzzing (Burp ParamMiner) |

### Commands

```
# REST API endpoint discovery:
ffuf -u https://api.target.com/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/api/api-seen-in-wild.txt \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -mc 200,201,204,400,401,405 -v

# Versioned API (v1, v2, v3):
ffuf -u https://target.com/api/VERSION/ENDPOINT \
  -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt:ENDPOINT \
  -w versions.txt:VERSION \  # [v1, v2, v3, v4]
  -mode clusterbomb

# REST verb + object bruteforce:
# Combine actions.txt (GET,POST,PUT,DELETE actions) with objects.txt:
ffuf -u https://api.target.com/v1/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/api/objects.txt \
  -X GET -mc 200,201,401,403

# GraphQL endpoint discovery:
ffuf -u https://target.com/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/graphql.txt \
  -mc 200,400

# Parameter discovery with ParamMiner wordlist:
ffuf -u "https://target.com/api/user?FUZZ=test" \
  -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
  -fw [baseline_word_count]

# HashiCorp Vault / Consul API:
ffuf -u https://vault.target.com/v1/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/hashicorp-vault.txt

# OAuth / OIDC scope fuzzing:
ffuf -u https://auth.target.com/oauth/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/oauth-oidc-scopes.txt
```

## Web Server & Infrastructure Fingerprinting

```
# /usr/share/seclists/Discovery/Web-Content/Web-Servers/
# Apache, IIS, Tomcat, JBoss, Nginx, Glassfish, Oracle iPlanet

# Identify server then target specific list:
curl -I https://target.com | grep -i "server:"

# Apache-specific paths:
ffuf -u https://target.com/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/Web-Servers/Apache.txt

# IIS-specific:
ffuf -u https://target.com/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/Web-Servers/IIS.txt \
  -x aspx,asp,config

# Tomcat manager / admin:
ffuf -u https://target.com/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/Web-Servers/Apache-Tomcat.txt

# Infrastructure / port scanning:
# /usr/share/seclists/Discovery/Infrastructure/
nmap -p $(cat /usr/share/seclists/Discovery/Infrastructure/nmap-ports-top1000.txt | tr '\n' ',') target.com
# common-http-ports.txt, Ports-1-To-65535.txt, common-router-ips.txt
```

## SNMP Community String Enumeration

```
# /usr/share/seclists/Discovery/SNMP/
ls /usr/share/seclists/Discovery/SNMP/
# snmp.txt — common community strings

# onesixtyone (fast SNMP scanner):
onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp.txt -i hosts.txt

# snmpwalk after finding valid community:
snmpwalk -v2c -c public target.com

# nmap SNMP scripts:
nmap -sU -p 161 --script snmp-brute \
  --script-args snmp-brute.communitiesdb=/usr/share/seclists/Discovery/SNMP/snmp.txt target.com
```

## File System & Backup Discovery

```
# /usr/share/seclists/Discovery/File-System/
ls /usr/share/seclists/Discovery/File-System/

# Linux file list (for LFI path enumeration):
# /usr/share/seclists/Fuzzing/LFI/LFI-etc-files-of-all-linux-packages.txt
# → massive list of /etc/ paths from Debian/Ubuntu packages

# DS_Store wordlist (extract file tree from leaked .DS_Store):
# /usr/share/seclists/Discovery/Web-Content/dsstorewordlist.txt
# Use ds_store_exp.py to parse .DS_Store files

# Web extensions for file extension fuzzing:
ffuf -u https://target.com/indexFUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/web-extensions.txt
# web-extensions-big.txt — larger extension list
```

## Robots.txt Disallowed Paths

```
# /usr/share/seclists/Discovery/Web-Content/trickest-robots-disallowed-wordlists/
# Wordlists built from disallowed paths collected across millions of robots.txt files
# High-value: these paths were explicitly hidden, making them interesting targets

ffuf -u https://target.com/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/trickest-robots-disallowed-wordlists/top-10000.txt \
  -mc 200,301,302,401,403 -v
```

## Recommended Recon Workflow

```
# Phase 1 — Passive (no active requests to target):
subfinder -d target.com | tee subs_passive.txt
amass enum -passive -d target.com >> subs_passive.txt
cat subs_passive.txt | sort -u > subs_all.txt

# Phase 2 — Active subdomain bruteforce:
shuffledns -d target.com \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt \
  -r resolvers.txt >> subs_all.txt
dnsx -l subs_all.txt -a -resp -o live_subs.txt

# Phase 3 — Web content discovery on each live subdomain:
cat live_subs.txt | while read sub; do
  feroxbuster -u "https://$sub" \
    -w /usr/share/seclists/Discovery/Web-Content/common.txt \
    -x php,html,js,json,txt,bak \
    -t 50 -k -o "results/$sub.txt" 2>/dev/null
done

# Phase 4 — API discovery on API endpoints:
ffuf -u "https://api.target.com/v1/FUZZ" \
  -w /usr/share/seclists/Discovery/Web-Content/api/api-seen-in-wild.txt \
  -H "Authorization: Bearer TOKEN" -mc 200,201,400,401,403

# Phase 5 — Sensitive file scan:
feroxbuster -u https://target.com \
  -w /usr/share/seclists/Discovery/Web-Content/quickhits.txt \
  -k --no-recursion -t 30
```
