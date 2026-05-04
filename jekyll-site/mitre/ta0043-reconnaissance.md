---
layout: training-page
title: "TA0043 — Reconnaissance — Red Team Academy"
module: "MITRE ATT&CK Tactics"
tags:
  - mitre
  - att&ck
  - reconnaissance
  - osint
  - scanning
page_key: "mitre-ta0043"
render_with_liquid: false
---

# TA0043 — Reconnaissance

Reconnaissance is the pre-attack phase where adversaries gather information to plan and support future operations. Techniques span both passive (OSINT, open database queries) and active (port scanning, vulnerability probing) methods. Unlike most tactics, reconnaissance happens **before** initial access and leaves little to no footprint inside the target network.

ATT&CK lists 10 parent techniques under TA0043, many with sub-techniques covering specific collection channels.

## Key Techniques

| T-ID | Technique | Sub-technique | Notes |
|------|-----------|---------------|-------|
| T1595 | Active Scanning | T1595.001 IP Blocks | Mass ping sweeps, ICMP probing |
| T1595 | Active Scanning | T1595.002 Vulnerability Scanning | Nessus, OpenVAS, Nuclei |
| T1595 | Active Scanning | T1595.003 Wordlist Scanning | Directory brute, subdomain brute |
| T1592 | Gather Victim Host Info | T1592.001 Hardware | OS fingerprinting, banner grabbing |
| T1592 | Gather Victim Host Info | T1592.002 Software | Service version enumeration |
| T1592 | Gather Victim Host Info | T1592.004 Client Configurations | Browser UA, email client headers |
| T1589 | Gather Victim Identity Info | T1589.001 Credentials | Breach dumps, credential leaks |
| T1589 | Gather Victim Identity Info | T1589.002 Email Addresses | LinkedIn, hunter.io, theHarvester |
| T1589 | Gather Victim Identity Info | T1589.003 Employee Names | LinkedIn scraping, org charts |
| T1590 | Gather Victim Network Info | T1590.001 Domain Properties | WHOIS, registrar data |
| T1590 | Gather Victim Network Info | T1590.002 DNS | Zone transfer attempts, DNS enum |
| T1590 | Gather Victim Network Info | T1590.004 Network Topology | Traceroute, BGP lookups |
| T1591 | Gather Victim Org Info | T1591.001 Physical Locations | Google Maps, LinkedIn offices |
| T1591 | Gather Victim Org Info | T1591.002 Business Relationships | Subsidiary mapping, M&A data |
| T1598 | Phishing for Information | T1598.001 Spearphishing Service | LinkedIn InMail, Slack, Discord |
| T1598 | Phishing for Information | T1598.003 Spearphishing Link | Fake login pages for credential recon |
| T1596 | Search Open Technical Databases | T1596.001 DNS/Passive DNS | SecurityTrails, DNSDB |
| T1596 | Search Open Technical Databases | T1596.002 WHOIS | ARIN, RIPE lookups |
| T1596 | Search Open Technical Databases | T1596.005 Scan Databases | Shodan, Censys, FOFA |
| T1593 | Search Open Websites/Domains | T1593.001 Social Media | LinkedIn, Twitter/X, GitHub |
| T1593 | Search Open Websites/Domains | T1593.002 Search Engines | Google dorks, Bing, Yandex |
| T1594 | Search Victim-Owned Websites | — | JS files, comments, meta tags |

## Red Team Tooling

### Active Scanning

```
# Masscan — fast TCP SYN scan across a /16
masscan -p1-65535 10.0.0.0/16 --rate=10000 -oJ masscan_out.json

# Nmap — service/version + OS detection on masscan results
nmap -sV -sC -O -iL masscan_hosts.txt -oA nmap_full

# Nuclei — vulnerability scanning with community templates
nuclei -u https://target.com -t cves/ -t exposures/ -t misconfigurations/ -o nuclei_results.txt

# Nmap NSE — SMB/LDAP enumeration
nmap --script=smb-enum-users,smb-enum-shares,ldap-rootdse -p 445,389 10.0.0.0/24
```

### Subdomain & DNS Enumeration

```
# Amass — comprehensive subdomain enumeration
amass enum -d target.com -o amass_subdomains.txt

# Subfinder — passive subdomain discovery
subfinder -d target.com -o subfinder_out.txt

# DNSx — resolve + filter alive subdomains
cat amass_subdomains.txt | dnsx -resp -a -aaaa -cname -o dnsx_resolved.txt

# Httpx — probe for live HTTP services
cat dnsx_resolved.txt | httpx -status-code -title -tech-detect -o httpx_live.txt
```

### Identity & OSINT

```
# theHarvester — email, subdomain, employee gathering
theHarvester -d target.com -b google,linkedin,hunter,dnsdumpster -l 500 -f harvest_out

# Shodan CLI — internet-connected asset search
shodan search "org:\"Target Corp\"" --fields ip_str,port,org,hostnames
shodan host 104.18.0.0

# Google Dorks
site:target.com filetype:pdf
site:target.com inurl:admin
site:github.com "target.com" password OR secret OR api_key
"@target.com" filetype:xls OR filetype:xlsx

# LinkedIn (manual) — employee enumeration for phishing target selection
# Use LinkedIn Sales Navigator or scraping tools for org chart mapping
```

### Credential Leak Hunting

```
# DeHashed / haveibeenpwned API (requires key)
curl "https://haveibeenpwned.com/api/v3/breachedaccount/user@target.com" \
  -H "hibp-api-key: YOUR_KEY"

# GitLeaks — scan public GitHub repos for secrets
gitleaks detect --source . --report-format json --report-path leaks.json

# Trufflehog — credential scanning in git history
trufflehog github --org=TargetOrg --only-verified
```

## Detection Notes

- **Active scanning leaves logs**: firewall deny logs, IDS alerts on rapid port sweeps, Shodan queries are passive from the defender's perspective but scanning from attacker IP may show in NetFlow
- **Phishing for info**: unusual email patterns (password reset requests from external parties), LinkedIn connection spikes before known incidents
- **GitHub recon**: if target monitors GitHub for credential leaks (GitGuardian, TruffleHog Actions), scanning repos may alert defenders
- **DNS zone transfer attempts**: logged by most DNS servers — AXFR refusals can indicate active recon
- **SSL cert transparency**: adversaries monitoring certs.sh for new certificates is passive and undetectable by the target

## Related Academy Pages

- [Passive Recon (OSINT)](/recon/passive-recon/)
- [Active Recon (Scanning)](/recon/active-recon/)
- [Subdomain Enumeration](/recon/subdomain-enum/)
- [Email OSINT](/recon/email-osint/)
- [Web Reconnaissance](/recon/web-recon/)
- [Infrastructure Mapping](/recon/infrastructure-mapping/)
- [Dark Web OSINT](/recon/dark-web-osint/)

## Resources

- [TA0043 — MITRE ATT&CK Reconnaissance](https://attack.mitre.org/tactics/TA0043/)
- [T1595 — Active Scanning](https://attack.mitre.org/techniques/T1595/)
- [T1596 — Search Open Technical Databases](https://attack.mitre.org/techniques/T1596/)
- [Shodan.io](https://shodan.io)
