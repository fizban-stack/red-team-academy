---
layout: training-page
title: "Lab Setup & Environment — Red Team Academy"
module: "Fundamentals"
tags:
  - setup
  - lab
  - kali
  - goad
page_key: "fundamentals-lab-setup"
render_with_liquid: false
---

# Lab Setup & Environment

![Lab topology: Kali attacker, Windows 10 domain client, Windows Server DC, Metasploitable, and C2 server all connected on host-only 192.168.56.0/24 network](/images/fundamentals/lab-topology.svg)  
*// lab topology — local red team environment with host-only network*

## Hardware Requirements

A local red team lab is compute-heavy. The more RAM, the better — GOAD alone needs 24GB for the full lab.

| Component | Minimum | Recommended |
| --- | --- | --- |
| RAM | 16 GB | 32–64 GB (GOAD needs 24 GB alone) |
| CPU | 4-core w/ VT-x/AMD-V | 8+ cores (i7/Ryzen 7 or better) |
| Storage | 500 GB SSD | 1–2 TB NVMe SSD |
| Network | Single NIC | Dual NIC (host + isolated lab) |

## Hypervisor Selection

Choose one primary hypervisor and stay consistent — mixing creates networking complexity.

- **VMware Workstation Pro** — Best networking options, snapshot stability, most compatible with enterprise targets. Requires license (~$200). GOAD officially supports VMware.
- **VirtualBox** — Free, cross-platform, good enough for most labs. Slightly less stable than VMware for complex multi-VM setups. GOAD supports VirtualBox.
- **Hyper-V** — Built into Windows Pro/Enterprise. Works well but has quirks with NAT networking. Not recommended for GOAD.
- **Proxmox VE** — Bare-metal hypervisor, best for dedicated lab servers. Free, KVM-based. Excellent if you have a dedicated machine.

## Network Topology

Isolate your lab from your production network. Lab VMs should *never* have direct internet access unless you specifically intend it.

```
# Recommended lab network design:

[Host Machine]
    |
    ├── Host-only Network: 192.168.56.0/24  ← Isolated lab traffic
    │       ├── Kali Linux (attacker)       192.168.56.10
    │       ├── GOAD VMs                    192.168.56.100–150
    │       └── Metasploitable              192.168.56.200
    │
    └── NAT Network (via host)              ← Internet access for Kali only
            └── Kali Linux

# VirtualBox: create Host-Only adapter in File → Host Network Manager
# VMware: use VMnet1 (Host-Only) for lab, VMnet8 (NAT) for internet
```

## Kali Linux Setup

Kali is the standard attacker platform. Download the official VM image — don't install from ISO unless you prefer a minimal setup.

```
# Download Kali VM from https://www.kali.org/get-kali/#kali-virtual-machines
# Import the .ova/.vmx file into your hypervisor
# Default credentials: kali / kali

# First boot — essential setup:
sudo apt update && sudo apt full-upgrade -y

# Change default password
passwd

# Install additional tools not in default Kali:
sudo apt install -y gobuster feroxbuster \
  crackmapexec evil-winrm impacket-scripts ligolo-ng \
  seclists wordlists netexec

# BloodHound Community Edition (CE) — replaces old neo4j + electron app:
# CE uses Docker; the old `apt install bloodhound` gives the legacy version
curl -L https://ghst.ly/getbhce | docker compose -f - up
# Access at http://localhost:8080 — admin password in container stdout on first run
# SharpHound data collector: https://github.com/BloodHoundAD/SharpHound/releases

# Or use the Kali metapackages:
sudo apt install kali-tools-post-exploitation
sudo apt install kali-tools-exploitation

# Configure your terminal (optional but useful):
sudo apt install -y tmux zsh
sh -c "$(curl -fsSL https://raw.github.com/ohmyzsh/ohmyzsh/master/tools/install.sh)"
```

### Essential Kali Tools by Category

| Category | Tools |
| --- | --- |
| Scanning | nmap, masscan, rustscan |
| Web | burpsuite, gobuster, feroxbuster, ffuf, sqlmap, nikto |
| AD Attacks | crackmapexec, evil-winrm, impacket, bloodhound, enum4linux-ng |
| Exploitation | metasploit, msfvenom, searchsploit |
| Post-Exploit | linpeas, winpeas, pspy, chisel, ligolo-ng |
| Password | hashcat, john, hydra, medusa |
| OSINT | theharvester, recon-ng, maltego (CE) |

## Metasploitable 2 Setup

Metasploitable 2 is a deliberately vulnerable Ubuntu Linux VM. It's the classic exploitation training target.

```
# Download from SourceForge (official):
# https://sourceforge.net/projects/metasploitable/

# It ships as a VMware .vmdk — import into VirtualBox:
# 1. Create new VM: Linux / Ubuntu 32-bit
# 2. Use existing disk: browse to Metasploitable.vmdk
# 3. Network: Host-Only (192.168.56.0/24)
# 4. Boot and verify:
#    Default credentials: msfadmin / msfadmin

# From Kali, verify connectivity:
ping 192.168.56.200
nmap -sV 192.168.56.200

# Metasploitable 2 services include:
# FTP (21), SSH (22), Telnet (23), SMTP (25), HTTP (80),
# SMB (139/445), MySQL (3306), PostgreSQL (5432), VNC (5900),
# IRC (6667), and many more intentionally vulnerable services
```

## Game of Active Directory (GOAD) Setup

GOAD is a multi-VM Active Directory lab maintained by Orange Cyberdefense. It creates a realistic, intentionally misconfigured Windows domain environment for practicing AD attack chains.

### GOAD Architecture

GOAD v2 deploys 5 Windows Server VMs across 3 domains in 2 forests:

```
# GOAD Domain Structure (5 VMs across 2 forests):
#
# Forest 1: SEVENKINGDOMS.LOCAL
#   ├── DC01 kingslanding   — Domain Controller   192.168.56.11  (WS2019)
#   ├── DC02 winterfell     — Child DC             192.168.56.10  (WS2019, north.sevenkingdoms.local)
#   └── SRV02 castelblack  — Member server        192.168.56.22  (WS2019, IIS/MSSQL/SMB)
#
# Forest 2: ESSOS.LOCAL
#   ├── DC03 meereen        — Domain Controller   192.168.56.12  (WS2016)
#   └── SRV03 braavos       — Member server       192.168.56.23  (WS2016, MSSQL/SMB)
#
# Notable intentional vulnerabilities:
#   hodor          — password = "hodor" (password spray target)
#   jon.snow       — SPN set, kerberoastable
#   TARGARYEN users — Kerberos pre-auth disabled (AS-REP roastable)
#   castelblack    — Unconstrained delegation enabled
#   LANNISTER group — ACE abuse: ForceChangePassword, GenericWrite
```

### GOAD Prerequisites

```
# Install on Linux host (Ubuntu/Debian recommended):
sudo apt update
sudo apt install -y git virtualbox python3 python3-venv \
  sshpass lftp rsync openssh-client

# Install Vagrant from HashiCorp official repo (not apt — old version):
wget -O- https://apt.releases.hashicorp.com/gpg | sudo gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/hashicorp.list
sudo apt update && sudo apt install vagrant

# Install required Vagrant plugins:
vagrant plugin install vagrant-reload vagrant-vbguest winrm winrm-fs winrm-elevated
```

### Installing GOAD v2

```
# Clone the GOAD repository:
git clone https://github.com/Orange-Cyberdefense/GOAD.git
cd GOAD

# For VirtualBox (default):
cd ad/GOAD/providers/virtualbox
vagrant up
# This downloads ~5 Windows Server ISOs and takes 1-2 hours
# Requires ~24 GB RAM, ~80 GB disk

# For VMware:
cd ad/GOAD/providers/vmware
vagrant up

# After VMs boot, run Ansible provisioning:
cd ../../..
./goad.sh -t install -l GOAD -p virtualbox -m local

# Verify all VMs are running:
vagrant status

# Test connectivity from Kali:
crackmapexec smb 192.168.56.0/24
```

### GOAD-Light (Lower Hardware Requirements)

```
# GOAD-Light is a 2-VM subset — requires only ~10 GB RAM
cd ad/GOAD-Light/providers/virtualbox
vagrant up

# Architecture: 1 DC + 1 member server
# DC01: 192.168.56.10 (DC01.GOAD.LOCAL)
# SRV01: 192.168.56.22
```

## Snapshot Strategy

Always snapshot your VMs before running attacks — it takes 30 seconds and saves hours of reinstallation.

```
# VirtualBox snapshots (GUI or CLI):
VBoxManage snapshot "Metasploitable2" take "clean-state" --description "Before any attacks"
VBoxManage snapshot "Metasploitable2" restore "clean-state"

# VMware: use the Snapshot Manager (VM → Snapshot → Take Snapshot)

# Recommended snapshot points:
# 1. "clean-install"   — immediately after OS install, before any config
# 2. "lab-ready"       — after network config, tools installed, tested
# 3. "pre-attack"      — before each practice session (easy reset)
```

## Additional Vulnerable Lab Resources

- **DVWA** — Damn Vulnerable Web Application. PHP/MySQL web app for OWASP Top 10 practice. `docker run -d -p 80:80 vulnerables/web-dvwa`
- **VulnHub** — Free downloadable vulnerable VMs. [https://www.vulnhub.com](https://www.vulnhub.com)
- **HackTheBox** — Cloud-hosted lab VMs. Monthly subscription. Best for CTF-style practice.
- **TryHackMe** — Guided learning paths, browser-based labs. Best for beginners and structured curriculum.
- **PentesterLab** — Web and binary exploitation focused. Excellent for web app security.
