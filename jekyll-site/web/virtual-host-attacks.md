---
layout: training-page
title: "Virtual Host Attacks — Red Team Academy"
module: "Web Hacking"
tags:
  - virtual-hosts
  - vhost-enumeration
  - host-header
  - waf-bypass
  - reconnaissance
page_key: "web-virtual-host-attacks"
render_with_liquid: false
---

# Virtual Host Attacks

Virtual Hosting allows a single web server (and IP address) to serve multiple distinct websites by examining the HTTP `Host` header on each request. Hidden virtual hosts may expose administration panels, internal APIs, staging environments, or development instances that are not publicly linked but are accessible by manipulating the `Host` header. This technique also enables bypassing CDNs and WAFs by discovering the true origin IP of a target.

## Tools

- **gobuster vhost** — Fast virtual host enumeration using wordlists — `github.com/OJ/gobuster`
- **VHostScan** — Virtual host scanner with catch-all detection and alias support — `github.com/codingo/VHostScan`
- **VhostFinder** — Identifies virtual hosts via similarity comparison — `github.com/wdahlenburg/VhostFinder`
- **hakoriginfinder** — Discovers origin hosts behind reverse proxies to bypass WAFs — `github.com/hakluke/hakoriginfinder`

## How Virtual Hosting Works

Every HTTP/1.1 request includes a `Host` header that tells the server which domain the client is requesting:

```
GET / HTTP/1.1
Host: example.com
```

The web server matches this header against its virtual host configuration and serves the appropriate content. Apache configuration example:

```
<VirtualHost *:80>
    ServerName site-a.com
    DocumentRoot /var/www/a
</VirtualHost>

<VirtualHost *:80>
    ServerName site-b.com
    DocumentRoot /var/www/b
</VirtualHost>
```

A request with `Host: site-b.com` to the same IP returns entirely different content — possibly with different security controls, authentication requirements, or exposed functionality.

## Virtual Host Enumeration

### gobuster vhost

```
# Enumerate virtual hosts using a wordlist
gobuster vhost -u https://example.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt

# Include non-standard ports
gobuster vhost -u http://10.10.10.10:8080 -w /usr/share/wordlists/vhosts.txt

# Append domain to each wordlist entry
gobuster vhost -u http://10.10.10.10 -w subdomains.txt --append-domain
```

### VHostScan

```
python3 VHostScan.py -t 10.10.10.10 -oN output.txt -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
```

### Manual Host Header Manipulation

```
# Test for admin vhost
curl -H "Host: admin.example.com" http://10.10.10.10/

# Test for internal API
curl -H "Host: api.internal.example.com" http://10.10.10.10/

# Test for staging environment
curl -H "Host: staging.example.com" http://10.10.10.10/

# Test for dev environment
curl -H "Host: dev.example.com" http://10.10.10.10/
```

## Fingerprinting Virtual Hosts

Indicators that you have hit a different virtual host:

- Different HTML title tags, meta descriptions, or application names
- Different HTTP response body size (`Content-Length`)
- Different HTTP status codes (200 vs. 301, 403, etc.)
- Custom error pages with different branding
- Redirect chains pointing to different domains
- TLS certificates with Subject Alternative Names listing other domains

Check the TLS certificate for SANs — these reveal all domains the server is configured to serve:

```
openssl s_client -connect 10.10.10.10:443 2>/dev/null | openssl x509 -noout -text | grep -A 5 "Subject Alternative Name"
```

## WAF / CDN Origin Discovery

When a target is behind a CDN (Cloudflare, Akamai, etc.) or WAF, the CDN IP is exposed but the real origin server IP is hidden. Discovering the origin IP allows direct access, bypassing WAF rules.

### Using hakoriginfinder

```
# Scan an IP range for the origin server
prips 93.184.216.0/24 | hakoriginfinder -h https://example.com:443/foo

# Or scan a specific CIDR
prips 10.0.0.0/24 | hakoriginfinder -h https://target.com/
```

### DNS History Technique

Leverage historical DNS records to find old IP addresses before the target moved behind a CDN. Then test whether those IPs still respond with the original application:

1. Query DNS history services (SecurityTrails, Shodan, PassiveTotal) for old A records
2. Test the old IPs directly with the original domain in the Host header
3. If the IP responds with the application, the origin is exposed

```
# Query Shodan for historical DNS
shodan search "hostname:target.com" --fields ip_str,hostnames

# Test a potential origin IP
curl -H "Host: target.com" https://203.0.113.50/ -k --resolve "target.com:443:203.0.113.50"
```

## Common Hidden Vhosts to Test

- `admin.` — administration panel
- `dev.` / `development.` — development environment
- `staging.` / `stage.` — staging environment
- `test.` — test environment
- `api.` / `api-internal.` — internal API
- `internal.` / `intranet.` — internal applications
- `vpn.` / `remote.` — VPN/remote access
- `mail.` / `webmail.` — mail server interface
- `monitor.` / `metrics.` — monitoring dashboards
- `git.` / `gitlab.` / `jenkins.` — developer tooling

## Resources

- gobuster — `github.com/OJ/gobuster`
- VHostScan — `github.com/codingo/VHostScan`
- hakoriginfinder — `github.com/hakluke/hakoriginfinder`
- Virtual Hosting — A Well Forgotten Enumeration Technique — Wyatt Dahlenburg
- Gobuster for directory, DNS and virtual hosts bruteforcing — erev0s.com
