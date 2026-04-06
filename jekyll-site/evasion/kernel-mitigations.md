---
layout: training-page
title: "Windows Kernel Mitigations — Red Team Academy"
module: "Evasion"
tags:
  - patchguard
  - kaslr
  - smep
  - smap
  - kcfg
  - vbs
  - hyperguard
  - kernel-mitigations
page_key: "evasion-kernel-mitigations"
render_with_liquid: false
---

# Windows Kernel Mitigations

Understanding kernel mitigations is essential both for writing stable drivers and for evaluating what techniques are viable on a target. This page covers PatchGuard, VBS/HyperGuard, KASLR, SMEP/SMAP, and Kernel CFG — what each protects, how to detect its presence, and how to write code that doesn't fight these protections.

---

## PatchGuard (Kernel Patch Protection)

### What It Does

PatchGuard (KPP) runs periodic integrity checks on sensitive kernel structures. If it detects tampering, the system bugchecks with `0x109 CRITICAL_STRUCTURE_CORRUPTION`. It's a **tripwire**, not a lock — it halts the machine rather than blocking the operation.

**What it watches (high-level — Microsoft intentionally avoids full disclosure):**
- SSDT (System Service Descriptor Table)
- IDT/GDT
- MSRs (Model Specific Registers)
- Kernel code pages (.text sections of ntoskrnl.exe, HAL)
- Critical kernel lists (module list, process list)
- Object type tables

### WinDbg: Detecting PatchGuard Trips

```
.bugcheck
!analyze -v
```

`0x109` with parameter 3 = `0x3` means code integrity; parameter 3 = `0x6` means module list. The `!analyze` output names the specific violation type.

### Engineering Rules

- **Never** patch SSDT, IDT, or ntoskrnl.exe code bytes
- **Never** rewrite kernel lists (PsActiveProcessHead, PsLoadedModuleList) directly
- Use supported kernel callbacks instead: `PsSetCreateProcessNotifyRoutine`, minifilters, WFP, registry callbacks, object callbacks
- Expect a bugcheck (not silent failure) if you cross any PatchGuard boundary

---

## VBS / HyperGuard (Virtualization-Based Security)

### Architecture

When VBS is enabled, Hyper-V introduces a second security layer (VTL1) hosting a **Secure Kernel**. HyperGuard runs in VTL1 and applies integrity checks that are **deterministic** (no timing windows like PatchGuard) — violations immediately produce `0x18C HYPERGUARD_VIOLATION`.

```
VTL1 (Secure World)
  Secure Kernel + HyperGuard
  ↕ SLAT (Second Level Address Translation)
VTL0 (Normal World)
  Windows Kernel + drivers
  User-mode processes
```

**What VBS adds:**
- HyperGuard: real-time, deterministic integrity enforcement
- KCFG bitmap protected by SLAT (VTL0 cannot write it even with arbitrary kernel write)
- NPIEP: Non-Privileged Instruction Execution Prevention — `SGDT/SIDT/SLDT` return per-CPU fake values, blocking one KASLR leak class
- Credential Guard: LSA secrets isolated in VTL1

### Checking VBS Status

```
# WinDbg (kernel):
kd> !sysinfo hyperv          ; is Hyper-V / VBS present?
kd> vertarget                ; OS build version

# PowerShell (user-mode):
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard |
    Select-Object VirtualizationBasedSecurityStatus, SecurityServicesRunning
# VirtualizationBasedSecurityStatus = 2 → running
```

---

## Kernel ASLR (KASLR)

### What It Randomizes

On Windows x64, KASLR randomizes load bases at each boot:
- `ntoskrnl.exe` — 256 possible load addresses
- HAL (`hal.dll`)
- All loaded drivers
- Pool regions, PFN database, page table bases

### Bypasses (for Lab Understanding)

KASLR requires an **info leak** — a way to read a kernel address from user-mode. Common historical leak sources:
- `NtQuerySystemInformation(SystemModuleInformation)` — leaked ntoskrnl base (patched in newer builds)
- `EnumDeviceDrivers` — still works in current Windows (requires admin)
- GDT/IDT leak via `sgdt`/`sidt` (blocked by NPIEP when VBS is active)
- Pool spray timing oracles

### WinDbg Verification

```
kd> lm kv nt                     ; verify ntoskrnl base changes across boots
kd> !vm 1                        ; pool extents — KASLR shifts these too
kd> lm k                         ; all kernel modules with randomized bases
```

### KASLR-Clean Driver Code

```cpp
// Never hardcode kernel addresses. Resolve dynamically:
UNICODE_STRING name = RTL_CONSTANT_STRING(L"MmCopyVirtualMemory");
PVOID pMmCopy = MmGetSystemRoutineAddress(&name);
if (!pMmCopy) {
    // graceful fallback
}

// For your own exported routines, use RtlLookupFunctionEntry or
// read PsLoadedModuleList (read-only) to get a module base at runtime.
```

---

## SMEP / SMAP (CPU Enforcement)

### What They Do

| Feature | Protection | CR4 Bit |
|---------|-----------|---------|
| SMEP (Supervisor Mode Execution Prevention) | Kernel cannot **execute** user-mode pages | Bit 20 |
| SMAP (Supervisor Mode Access Prevention) | Kernel cannot **read/write** user-mode pages (unless explicitly allowed) | Bit 21 |

**SMEP** defeats return-to-userland (`ret2usr`) attacks and ROP chains that pivot into user memory. **SMAP** prevents accidental kernel dereferences of user pointers.

### Checking SMEP/SMAP in a Driver

```cpp
// smep_smap_check.cpp — diagnostic only; never modify CR4 from a driver
#include <ntddk.h>
#include <intrin.h>

VOID CheckMitigations() {
#if defined(_M_AMD64)
    unsigned __int64 cr4 = __readcr4();
    BOOLEAN smep = (cr4 & (1ull << 20)) != 0;
    BOOLEAN smap = (cr4 & (1ull << 21)) != 0;
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[mitig] CR4=0x%llx  SMEP=%d  SMAP=%d\n", cr4, smep, smap);
#endif
}
```

**Never clear these bits** — it is unsupported and PatchGuard/HyperGuard will catch it.

### SMAP-Safe Driver Code

When copying user buffers in a driver, always probe and capture:

```cpp
// Probe and capture user input before use at PASSIVE_LEVEL:
NTSTATUS SafeCopyFromUser(PVOID kernelBuf, PVOID userBuf, SIZE_T len) {
    __try {
        ProbeForRead(userBuf, len, sizeof(UCHAR));
        RtlCopyMemory(kernelBuf, userBuf, len);
        return STATUS_SUCCESS;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }
}

// For METHOD_NEITHER IOCTLs, always probe before dereferencing:
// Type3InputBuffer is unprobed; ProbeForRead before touching it.
```

---

## Kernel CFG (KCFG)

### What It Does

Kernel-mode Control Flow Guard validates **indirect call/jump targets** in kernel code compiled with `/guard:cf`. Each valid target has a bit set in a protected bitmap.

- Without VBS: KCFG bitmap lives in VTL0 kernel memory — an arbitrary kernel write can flip bits and disable it
- **With VBS/SLAT**: the KCFG bitmap page is mapped read-only in VTL0 but writable only from VTL1. An arbitrary kernel write can't corrupt it

### Driver Build Tips

```
# Compile with CFG:
cl /guard:cf mydriver.cpp

# CMakeLists:
target_compile_options(mydriver PRIVATE /guard:cf)
target_link_options(mydriver PRIVATE /guard:cf)
```

- Avoid dynamic trampolines that won't appear in the guard map
- Keep IAT "address-taken" entries tidy — KCFG uses function guard tables from PE metadata
- Expect Driver Verifier hooks to be restricted when KCFG is active (Verifier modifies indirect call targets)

### WinDbg: CFG Checks

```
kd> !verifier                            ; shows Verifier + KCFG interaction
kd> dd nt!guard_icall_bitmap L1          ; presence check (requires symbols)
```

---

## Mitigation Interaction Matrix

| Scenario | KASLR | SMEP | SMAP | KCFG + VBS |
|----------|-------|------|------|------------|
| Info leak defeats | partially | — | — | — |
| Ret2usr / ROP to user memory | — | blocks | blocks | — |
| Arbitrary kernel write + code injection | — | blocks exec | — | — |
| Indirect call hijack / vtable overwrite | — | — | — | blocks (with VBS) |
| PTE flip to make KCFG bitmap writable | — | — | — | blocked by SLAT |
| SSDT/IDT patch | — | — | — | PatchGuard kills |

---

## Kernel "Feature Recon" — WinDbg Checklist

```
kd> !sysinfo hyperv          ; VBS present and status
kd> vertarget                ; build number (feature expectations per version)
kd> !pte nt!KiSystemCall64   ; confirm kernel text page protections
kd> !vm 1                    ; pool/nonpaged extents — see KASLR effect
kd> lm k                     ; all kernel modules with randomized bases
kd> !verifier                ; active Verifier settings
kd> .bugcheck                ; last bugcheck code (if crash dump)
kd> !analyze -v              ; full automated analysis
```

---

## Hardening Checklist

- Enable **HVCI** (Hypervisor-Protected Code Integrity) — makes KCFG bitmap truly read-only
- Enable **Secure Boot** and require signed drivers (`bcdedit /set loadoptions DDISABLE_INTEGRITY_CHECKS` = DO NOT use in production)
- Disable test signing on production: `bcdedit /set testsigning off`
- Remove unnecessary signed drivers that expose broad IOCTL surfaces (BYOVD attack surface reduction)
- Enable **Driver Verifier** in CI/test environments (Special Pool, I/O Verification, IRQL checking)
- Restrict device object ACLs: use `IoCreateDeviceSecure` with explicit DACL
- Monitor for unexpected driver loads via Sysmon Event ID 6 (driver loaded)

---

## Resources

- Windows Internals, 7th ed. Part 1 — PatchGuard, HyperGuard, KASLR regions, KCFG/VBS details
- Windows Kernel Programming (Yosifovich) — address-space maps, VBS roles, safe driver patterns
- Microsoft KCFG documentation — `docs.microsoft.com/windows/security/threat-protection/device-guard/introduction-to-device-guard`
- VBS and HVCI overview — `docs.microsoft.com/windows/security/threat-protection/device-guard/hvci-security`
- "KPP: PatchGuard implementation details" — Alex Ionescu's public research on PatchGuard internals
