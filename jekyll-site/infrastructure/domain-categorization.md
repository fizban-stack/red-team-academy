---
layout: training-page
title: "Domain Strategy & Categorization — Red Team Academy"
module: "Infrastructure Engineering"
tags:
  - infrastructure
  - domain
  - categorization
  - opsec
  - phishing
page_key: "infrastructure-domain-categorization"
render_with_liquid: false
---

# Domain Strategy & Categorization

Domain categorization is the reputation scoring system that web filtering proxies, EDR cloud lookups, and email security gateways use to classify internet destinations. A domain in the wrong category — or with no category at all — triggers inspection or block events that burn infrastructure and alert defenders.

## Why Categorization Matters

```
Network traffic flow with web filtering:

  Beacon → Proxy (Zscaler/Palo Alto/Bluecoat) → Categorization check → Allow/Block/Inspect

Category database lookup occurs at:
  - Web proxy (Zscaler, Bluecoat, Websense, Cisco Umbrella)
  - DNS filtering (Cisco Umbrella DNS, Palo Alto DNS Security)
  - EDR network inspection (CrowdStrike, SentinelOne cloud lookup)
  - SIEM enrichment (adds category context to DNS/flow logs)

Impact of "Unknown" or "Uncategorized" category:
  - Many enterprise proxies default to: Block or Inspect unclassified domains
  - EDR products flag uncategorized domains as suspicious
  - Security operations teams investigate uncategorized domains in alerts
  
Target category for C2 domains:
  "Technology", "Business & Economy", "Software/Technology", "CDN/Hosting"
  These categories get minimal additional scrutiny
```

## Major Categorization Services

| Service | Used By | URL to Check |
|---------|---------|-------------|
| Blue Coat/Symantec WebPulse | Broadcom ProxySG, BlueCoat | sitereview.symantec.com |
| Cisco Talos | Cisco Umbrella, Cisco Secure | talosintelligence.com/reputation_center |
| Fortiguard | Fortinet FortiGate | fortiguard.com/webfilter |
| Palo Alto URL Filtering | PAN-OS, Cortex | urlfiltering.paloaltonetworks.com |
| Trend Micro | Trend Micro products | siteadvisor.trendmicro.com |
| McAfee MAPS | McAfee Web Gateway | trustedsource.org |
| IBM X-Force | IBM QRadar, enterprise | exchange.xforce.ibmcloud.com |
| Barracuda | Barracuda products | barracudacentral.org |
| Proofpoint | Proofpoint TAP | ipcheck.proofpoint.com |

```bash
# Check categorization across multiple services
# Manual: visit each URL above and enter domain

# Automated: use vpncheck or custom script
for domain in yourdomain.com; do
  echo "Checking $domain..."
  curl -s "https://talosintelligence.com/documents/ip-reputation?ip=$domain" | \
    python3 -c "import sys, json; d=json.load(sys.stdin); print(d.get('category','Unknown'))"
done

# VirusTotal check
curl -s "https://www.virustotal.com/api/v3/domains/$domain" \
  -H "x-apikey: [YOUR_VT_API_KEY]" | \
  jq '.data.attributes.categories'
```

## Getting a Domain Categorized

### Hosting Legitimate Content

New domains are uncategorized. The fastest path to categorization is hosting real content and driving traffic.

```
Minimum viable categorization content:
  1. Static website that looks like a technology company or CDN service
  2. Privacy policy page (signals legitimate business operation)
  3. Contact or about page with fake company information
  4. Blog posts or technical articles (2-5 posts)
  5. Sitemap.xml and robots.txt (signals proper webmaster)

Template structure:
  /index.html         (company homepage)
  /about.html         (about page)
  /services.html      (services)
  /blog/post1.html    (technical blog post)
  /privacy.html       (privacy policy)
  /sitemap.xml
  /robots.txt

Content: Generic technology company language, plausible domain name
  matching the business type, relevant keywords for category
```

### Submitting to Categorization Databases

After hosting content, submit for categorization:

```
Submission process (manual):

Blue Coat/Symantec:
  1. Navigate to sitereview.symantec.com
  2. Enter domain
  3. If uncategorized: click "Categorize this site"
  4. Select appropriate category (Technology, Software/Technology)
  5. Provide supporting justification

Cisco Talos:
  1. Navigate to talosintelligence.com/reputation_center
  2. Enter domain
  3. If needed: submit feedback for recategorization
  4. No formal submission process — relies on crawlers + feedback

Fortiguard:
  1. Navigate to fortiguard.com/webfilter
  2. Enter URL, view category
  3. Submit re-categorization request at fortiguard.com/feedback

Palo Alto URL Filtering:
  1. Navigate to urlfiltering.paloaltonetworks.com
  2. Enter URL, check category
  3. Request recategorization via form (requires selecting correct category)

Timeline: 2-7 business days for most submissions
```

### Organic Traffic Generation

```bash
# Use legitimate traffic to trigger crawler visits and build reputation
# (Simulates real-world web traffic patterns)

# Simple Python script to generate organic-looking traffic
python3 << 'EOF'
import requests
import time
import random

domain = "yourdomain.com"
pages = ["/", "/about", "/services", "/blog/post1", "/privacy"]
headers_list = [
    {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
    {"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"},
    {"User-Agent": "Googlebot/2.1 (+http://www.google.com/bot.html)"}
]

for day in range(7):
    for visit in range(random.randint(5, 15)):
        page = random.choice(pages)
        headers = random.choice(headers_list)
        try:
            r = requests.get(f"https://{domain}{page}", headers=headers, timeout=5)
            print(f"GET {page}: {r.status_code}")
        except:
            pass
        time.sleep(random.uniform(30, 120))
    print(f"Day {day+1} complete")
    time.sleep(86400)
EOF
```

## Buying Pre-Categorized Expired Domains

The fastest path to a categorized domain is purchasing one that already has history and categorization.

### Finding Expired Domains

```bash
# expireddomains.net — largest database of expired domains
# Filter: age > 1 year, TLD .com/.net, no blacklist hits

# Tools for domain analysis
# domaintools.com — historical WHOIS, categorization history
# dnslytics.com — DNS history, hosting history
# whoxy.com — WHOIS history

# Process:
# 1. Search expireddomains.net with filters:
#    - Domain age: 5+ years (older = better reputation)
#    - Backlinks: some backlinks (shows real use)
#    - TLD: .com preference
#    - Not on blacklists

# 2. Export CSV and analyze in bulk
# expireddomains.net exports up to 250 domains at a time

# 3. Analyze each domain before purchase
```

### Domain Vetting Pipeline

```bash
#!/bin/bash
# domain-vet.sh — automated domain vetting

DOMAIN=$1

echo "=== Vetting $DOMAIN ==="

# 1. Check VirusTotal
VT_RESULT=$(curl -s "https://www.virustotal.com/api/v3/domains/$DOMAIN" \
  -H "x-apikey: $VT_API_KEY" | jq -r '.data.attributes.last_analysis_stats | 
  "malicious:\(.malicious) suspicious:\(.suspicious)"')
echo "VirusTotal: $VT_RESULT"

# 2. Check Cisco Talos (manual lookup needed)
echo "Talos: https://talosintelligence.com/reputation_center/lookup?search=$DOMAIN"

# 3. Check Spamhaus DBL (domain blocklist)
SPAMHAUS=$(host -t A "$DOMAIN.dbl.spamhaus.org" 2>&1)
if echo "$SPAMHAUS" | grep -q "NXDOMAIN"; then
  echo "Spamhaus DBL: CLEAN"
else
  echo "Spamhaus DBL: FLAGGED - $SPAMHAUS"
fi

# 4. Check Wayback Machine for history
echo "Wayback: https://web.archive.org/web/*/$DOMAIN"

# 5. Check DNS history (requires dnslytics API or manual)
echo "DNS History: https://dnslytics.com/domain/$DOMAIN"

# 6. Whois for registration history
whois "$DOMAIN" | grep -E "Creation|Registrar|Registry"
```

### Red Flags in Domain History

```
Disqualify a domain if:
  [ ] Domain appears on VirusTotal with ANY malicious detections
  [ ] Wayback Machine shows: spam, scam, phishing, adult, malware content
  [ ] WHOIS shows: domain expired < 30 days ago (may have active monitoring)
  [ ] Spamhaus DBL: any listing
  [ ] DNS history shows: wildcard (*) A records (spam hosting indicator)
  [ ] Associated IPs appear in threat intel feeds
  [ ] Domain was used for cryptocurrency scams or pump-and-dump
  [ ] Domain was parked with spam-adjacent registrar for many years
  
Positive indicators:
  [ ] Domain used by real business for 5+ years
  [ ] Has legitimate backlinks (blog posts, news articles)
  [ ] Category: Technology, Software, Business
  [ ] Clean WHOIS history with professional registrar
  [ ] Wayback shows: real company website, product pages, blog
```

## Checking Categorization Before Purchase

```bash
# Check domain across all major categorization services before buying
check_categorization() {
  DOMAIN=$1
  
  echo "Checking $DOMAIN across categorization services..."
  
  # Blue Coat (requires browser): sitereview.symantec.com
  # Fortiguard
  curl -s "https://www.fortiguard.com/api/v2/urlfilter?url=$DOMAIN" | \
    python3 -c "import sys,json; d=json.load(sys.stdin); print(f'Fortiguard: {d.get(\"category_name\",\"Unknown\")}')"
  
  # McAfee SmartFilter
  echo "McAfee: https://www.trustedsource.org/sources/index.pl?url=$DOMAIN"
  
  # Sucuri SiteCheck (free security check)
  curl -s "https://sitecheck.sucuri.net/results/$DOMAIN/" | \
    grep -o '"status":"[^"]*"' | head -3
}

check_categorization yourdomain.com
```

## Domain Fronting Domains

```
High-reputation CDN domains suitable for fronting (via Cloudflare Workers):
  - *.workers.dev (Cloudflare-operated, extremely high trust)
  - *.azurefd.net (Azure Front Door, Microsoft trust)
  - *.cloudfront.net (AWS CloudFront, Amazon trust)
  - *.fastly.net (Fastly CDN)

These domains:
  - Are pre-categorized as "Technology/CDN"
  - Are on allow lists in most enterprise proxies
  - Do not require any categorization work by operator
  - Trade-off: less control, shared with legitimate users
```

## Typosquatting and Phishing Domain Strategy

### Domain Generation for Phishing

```python
# Generate typosquat variations for phishing pretext domains
def generate_typosquats(target_domain):
    base = target_domain.split('.')[0]
    tld = '.' + target_domain.split('.')[1]
    
    variations = []
    
    # Doubled letter
    for i, c in enumerate(base):
        variations.append(base[:i] + c + c + base[i+1:] + tld)
    
    # Missing letter
    for i in range(len(base)):
        variations.append(base[:i] + base[i+1:] + tld)
    
    # Transposition
    for i in range(len(base)-1):
        t = list(base)
        t[i], t[i+1] = t[i+1], t[i]
        variations.append(''.join(t) + tld)
    
    # Digit substitution (common letters)
    subs = {'o': '0', 'i': '1', 'l': '1', 'e': '3', 'a': '4'}
    for orig, digit in subs.items():
        if orig in base:
            variations.append(base.replace(orig, digit) + tld)
    
    # Hyphen additions
    keywords = ['-login', '-portal', '-helpdesk', '-remote', '-vpn']
    for kw in keywords:
        variations.append(base + kw + tld)
    
    # TLD swaps
    for new_tld in ['.net', '.org', '.co', '.io']:
        if new_tld != tld:
            variations.append(base + new_tld)
    
    return list(set(variations))

# Example
targets = generate_typosquats('microsoft.com')
print(f"Generated {len(targets)} variations")
```

### Separating Infrastructure and Phishing Domains

```
DOMAIN INVENTORY STRUCTURE:

Engagement: [CLIENT] — [DATE]

PHISHING DOMAINS (expendable, client-facing):
  microsoft-update-portal.com
    Purpose: Initial access phishing email
    Category: Uncategorized (fresh domain — accept risk)
    TLS: Let's Encrypt
    Status: Active during phishing phase only

  sharepoint-auth.net
    Purpose: Credential harvest landing page
    Category: Technology (submitted to Fortiguard)
    TLS: Let's Encrypt
    Status: Active during phishing phase only

C2 CALLBACK DOMAINS (long-lived, protected):
  cdn-update-service.com
    Purpose: HTTPS beacon callback
    Category: Technology/CDN (aged domain, 2019)
    TLS: Let's Encrypt
    Backend: Redirector 1
    Status: Protected — do NOT link to phishing

  static-content-api.net
    Purpose: DNS C2 backup
    Category: Technology
    NS: Custom authoritative DNS on VPS
    Status: Protected

OPERATIONAL RULE:
  If phishing domain is burned, C2 domains are unaffected.
  The two domain sets must NEVER cross-reference each other.
```

## Certificate Transparency Monitoring

```bash
# Monitor CT logs for your own domains (know what defenders see)
# crt.sh provides RSS and JSON API

# Check current certs for domain
curl -s "https://crt.sh/?q=%.yourdomain.com&output=json" | \
  jq -r '.[] | "\(.not_before) \(.name_value)"' | sort

# Monitor for NEW certs (indicates someone may be spoofing your domain)
# Set up monitoring with certspotter
curl -s "https://certspotter.com/api/v1/issuances?domain=yourdomain.com&expand=dns_names" | \
  jq -r '.[] | "\(.not_before) \(.dns_names[])"'

# RSS feed subscription
# Add to RSS reader: https://crt.sh/atom?q=%.yourdomain.com

# If defender registers domain adjacent to yours (defensive registration)
# Check for: yourdomain.com-cert-monitor or similar
```

## Categorization Maintenance

```
Ongoing categorization tasks during engagement:

Weekly:
  [ ] Verify C2 domains remain in expected categories
  [ ] Check VirusTotal for new detections (daily scans from VT crawlers)
  [ ] Review Cisco Talos category for each C2 domain
  [ ] Monitor CT logs for unexpected certificates on your domains

On detection signal:
  [ ] Domain reported by target security team? → Expect re-categorization to malicious
  [ ] Check VirusTotal for new detections on that domain
  [ ] Rotate to backup C2 domain if categorization compromised

Post-engagement:
  [ ] Note which domains survived with clean categorization
  [ ] Document which domains were burned and when
  [ ] Archive vetting records for each domain used
  [ ] Decision: renew clean domains for future engagements vs. let expire
```
