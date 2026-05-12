---
layout: training-page
title: "Living Off the Land — Red Team Academy"
module: "Living Off the Land"
tags:
  - lotl
  - lolbins
  - gtfobins
  - living-off-the-land
  - defense-evasion
page_key: "lotl-index"
render_with_liquid: false
---

# Living Off the Land

Living Off the Land (LOTL) is a red team philosophy: achieve objectives using only binaries, scripts, and libraries that are already present on the target operating system. No custom tools, no dropped executables, no signatures to detect.

MITRE ATT&CK: **T1218** — Signed Binary Proxy Execution | **T1059** — Command and Scripting Interpreter

---

## Why Living Off the Land?

Modern EDR platforms excel at detecting known-bad signatures, behaviors, and process lineages. Custom tools — Cobalt Strike beacons, Mimikatz, custom implants — have well-known indicators. LOTL techniques operate in the **gray zone**:

- **Signed binaries** — Microsoft-signed or OS-vendor-signed executables bypass application allowlisting (AppLocker, WDAC)
- **Reduced footprint** — Nothing is written to disk; execution is in-memory through trusted processes
- **Blends with noise** — `certutil.exe`, `wmic.exe`, `osascript` all generate legitimate traffic in normal environments
- **Lower detection rates** — AV/EDR vendors can't block legitimate OS tools without breaking functionality

> The trade-off: LOTL techniques are increasingly detected as blue teams mature. Understanding the detection surface for each technique is as important as knowing the technique itself.

---

## OS Guides

Each guide is organized by **red team objective** — what you're trying to accomplish — rather than alphabetically by binary. Real-world use case scenarios are embedded throughout.

### Windows LOTL

The richest LOTL ecosystem. Windows ships hundreds of signed binaries that can be abused for execution, download, persistence, credential access, and lateral movement. The LOLBAS project catalogs 300+ abusable binaries.

Key categories:
- **Execution**: mshta, regsvr32, rundll32, wmic XSL, msbuild, installutil, odbcconf
- **Download**: certutil, bitsadmin, finger, desktopimgdownldr, mpcmdrun
- **Persistence**: schtasks, wmic subscriptions, sc.exe, winrm, reg.exe run keys
- **Credential Access**: comsvcs.dll MiniDump, reg SAM export, ntdsutil, diskshadow
- **Lateral Movement**: wmic /node:, winrs, net use + schtasks

→ **[Windows Living Off the Land Guide](/living-off-the-land/windows-lotl/)**

---

### Linux LOTL

Linux LOTL is dominated by **GTFOBins** — a curated list of Unix binaries that can be used to bypass local security restrictions. Every Linux system is a LOTL goldmine: bash, python, perl, awk, find, and dozens of other standard utilities have documented escalation paths.

Key categories:
- **Shell Escape**: bash, python, perl, awk, vim, less, find, xargs, env
- **SUID Abuse**: find, cp, bash, vim, nmap (old), python, perl
- **Sudo Misconfig**: vi, nano, python, tar, zip, curl, apt, docker, systemctl
- **Capabilities**: cap_setuid, cap_net_raw, cap_dac_override, cap_sys_admin
- **Exfiltration**: curl, wget, nc, openssl s_client, python http, DNS via dig

→ **[Linux Living Off the Land Guide](/living-off-the-land/linux-lotl/)**

---

### macOS LOTL

macOS presents a unique challenge: Apple's security model (SIP, TCC, Gatekeeper, AMFI) restricts many traditional techniques, but the OS ships powerful scripting runtimes — AppleScript, JXA, Python, Perl, Ruby — and a rich set of management CLI tools that enable sophisticated LOTL operations when used correctly.

Key categories:
- **Execution/Escalation**: osascript (AppleScript), bash, python3, perl, ruby
- **Persistence**: LaunchAgents, LaunchDaemons, LoginItems via launchctl/plutil
- **Credential Access**: security CLI, keychain dumping, browser credential stores
- **TCC Bypass**: FDA proxy via existing apps, sqlite3 TCC.db queries
- **Exfiltration**: curl, screencapture, pbpaste, mdfind for target discovery

→ **[macOS Living Off the Land Guide](/living-off-the-land/macos-lotl/)**

---

## MITRE ATT&CK Coverage

| Technique | ID | Covered In |
|-----------|-----|-----------|
| Signed Binary Proxy Execution | T1218 | Windows |
| System Binary Proxy Execution (macOS) | T1218 | macOS |
| Command and Scripting Interpreter: Unix Shell | T1059.004 | Linux |
| Command and Scripting Interpreter: AppleScript | T1059.002 | macOS |
| Command and Scripting Interpreter: Windows Cmd | T1059.003 | Windows |
| Ingress Tool Transfer | T1105 | All |
| Scheduled Task/Job | T1053 | Windows, Linux |
| Create or Modify System Process: Launch Agent | T1543.001 | macOS |
| Setuid and Setgid | T1548.001 | Linux |
| Bypass User Account Control | T1548.002 | Windows |
| OS Credential Dumping: LSASS Memory | T1003.001 | Windows |
| OS Credential Dumping: /etc/passwd | T1003.008 | Linux |
| Keychain | T1555.001 | macOS |
| Exfiltration Over C2 Channel | T1041 | All |

---

## Reference Projects

| Project | URL | OS |
|---------|-----|-----|
| LOLBAS | lolbas-project.github.io | Windows |
| GTFOBins | gtfobins.github.io | Linux/Unix |
| LOOBins | loobins.io | macOS |
| WADCOMS | wadcoms.github.io | Windows/AD |
| HijackLibs | hijacklibs.net | Windows DLL hijacking |

---

## Detection Engineering Notes

> Red teamers studying this section should understand the **detection surface** of each technique. Mature blue teams monitor:
>
> - **Command-line arguments** on signed binaries (certutil -urlcache, regsvr32 /i:http://)
> - **Parent-child process relationships** (e.g., Word spawning mshta)
> - **Network connections from unexpected processes** (certutil, msiexec making HTTP calls)
> - **WMI subscriptions** (EventFilter, EventConsumer, FilterToConsumerBinding instances)
> - **Scheduled task creation** from non-standard parent processes
> - **LSASS access** from processes that aren't LSASS dumpers
>
> Understanding these detection signals helps red teamers chain techniques to minimize exposure.
